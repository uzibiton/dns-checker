"""Command line interface for the DNS Reputation Analysis Tool."""

import asyncio
import logging
import signal
import sys
import time
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.logging import RichHandler

from .cache import AsyncTTLCache
from .metrics import MetricsCollector
from .pcap_reader import PcapReader
from .rate_limiter import CombinedRateLimiter
from .reputation import ReputationClient
from .utils import normalize_domain
from .writer import ResultsManager

# Initialize Typer app and Rich console
app = typer.Typer(
    name="dnsreplay",
    help="DNS Reputation Analysis Tool for PCAP traffic analysis",
    add_completion=False
)
console = Console()

# Global state for graceful shutdown
shutdown_event = asyncio.Event()
analysis_task: Optional[asyncio.Task] = None


def signal_handler(signum, frame):
    """Handle shutdown signals."""
    console.print("\n[yellow]Received shutdown signal, stopping analysis...[/yellow]")
    shutdown_event.set()


def setup_logging(log_level: str) -> None:
    """Configure logging with Rich handler."""
    logging.basicConfig(
        level=getattr(logging, log_level.upper()),
        format="%(name)s: %(message)s",
        datefmt="[%X]",
        handlers=[RichHandler(rich_tracebacks=True)]
    )
    
    # Reduce noise from httpx
    logging.getLogger("httpx").setLevel(logging.WARNING)


async def run_analysis(
    pcap_path: Path,
    timeout: Optional[float],
    rps: float,
    concurrency: int,
    cache_ttl: float,
    results_manager: ResultsManager,
    metrics_collector: MetricsCollector
) -> str:
    """
    Run the main DNS reputation analysis.
    
    Returns:
        Reason for completion ("timeout", "keyboard interrupt", or "completed")
    """
    start_time = time.time()
    
    # Initialize components
    cache = AsyncTTLCache(default_ttl=cache_ttl)
    rate_limiter = CombinedRateLimiter(rate=rps, max_concurrent=concurrency)
    reputation_client = ReputationClient()
    
    # Create async queue for domains (larger queue to reduce backpressure)
    domain_queue: asyncio.Queue = asyncio.Queue(maxsize=5000)
    
    # Start background tasks
    await cache.start_cleanup_task()
    await metrics_collector.start_reporting()
    
    # Start PCAP reader with current event loop
    pcap_reader = PcapReader(pcap_path, domain_queue, asyncio.get_running_loop())
    pcap_reader.start()
    
    logger = logging.getLogger(__name__)
    logger.info(f"Starting analysis of {pcap_path}")
    logger.info(f"Rate limit: {rps} RPS, Concurrency: {concurrency}, Cache TTL: {cache_ttl}s")
    
    # Create worker tasks
    workers = []
    for i in range(concurrency):
        worker = asyncio.create_task(
            _reputation_worker(
                f"worker-{i}",
                domain_queue,
                cache,
                rate_limiter,
                reputation_client,
                results_manager,
                metrics_collector
            )
        )
        workers.append(worker)
    
    try:
        # Wait for completion or timeout
        if timeout:
            await asyncio.wait_for(
                shutdown_event.wait(),
                timeout=timeout
            )
            reason = "timeout"
        else:
            await shutdown_event.wait()
            reason = "keyboard interrupt"
            
    except asyncio.TimeoutError:
        reason = "timeout"
        
    finally:
        # Cleanup
        logger.info("Shutting down analysis...")
        
        # Stop PCAP reader
        pcap_reader.stop()
        
        # Wait for workers to finish processing
        await asyncio.sleep(2.0)  # Allow in-flight requests to complete
        
        # Cancel workers
        for worker in workers:
            worker.cancel()
            
        await asyncio.gather(*workers, return_exceptions=True)
        
        # Stop background tasks
        await metrics_collector.stop_reporting()
        await cache.stop_cleanup_task()
        await reputation_client.close()
        
        runtime = time.time() - start_time
        logger.info(f"Analysis completed in {runtime:.2f} seconds")
        
    return reason


async def _reputation_worker(
    worker_name: str,
    domain_queue: asyncio.Queue,
    cache: AsyncTTLCache,
    rate_limiter: CombinedRateLimiter,
    reputation_client: ReputationClient,
    results_manager: ResultsManager,
    metrics_collector: MetricsCollector
) -> None:
    """Worker task for processing domain reputation lookups."""
    logger = logging.getLogger(f"worker.{worker_name}")
    
    while not shutdown_event.is_set():
        try:
            # Get domain from queue with timeout
            try:
                domain_query = await asyncio.wait_for(
                    domain_queue.get(), 
                    timeout=1.0
                )
            except asyncio.TimeoutError:
                continue
                
            # None signals end of data
            if domain_query is None:
                # Re-queue for other workers
                await domain_queue.put(None)
                break
                
            domain = domain_query.domain
            query_source = domain_query.query_source
            
            # Check cache first (with per-key lock to prevent thundering herd)
            cache_lock = await cache.get_lock(domain)
            
            async with cache_lock:
                cached_result = await cache.get(domain)
                
                if cached_result is not None:
                    # Cache hit
                    cached_result.cached = True
                    cached_result.query_source = query_source
                    
                    await results_manager.write_result(cached_result, query_source)
                    await results_manager.write_sample(
                        domain, 1, 0, None, True, cached=True
                    )
                    
                    metrics_collector.record_request(domain, 0, True)
                    continue
                    
                # Cache miss - make API call
                async with rate_limiter:
                    result = await reputation_client.lookup_reputation(domain)
                    
                    # Record metrics
                    metrics_collector.record_request(
                        domain, 
                        result.response_time_ms,
                        result.status == "success"
                    )
                    
                    # Write sample for debugging
                    await results_manager.write_sample(
                        domain,
                        result.attempts,
                        result.response_time_ms,
                        result.http_status,
                        result.status == "success",
                        result.error_message,
                        cached=False
                    )
                    
                    # Cache successful results
                    if result.status == "success":
                        await cache.set(domain, result)
                        
                    # Write main result
                    await results_manager.write_result(result, query_source)
                    
            domain_queue.task_done()
            
        except Exception as e:
            logger.error(f"Error in worker {worker_name}: {e}")
            

@app.command()
def replay(
    pcap: Path = typer.Argument(..., help="Path to PCAP file"),
    timeout: Optional[float] = typer.Option(300.0, "--timeout", help="Overall run timeout in seconds"),
    rps: float = typer.Option(100.0, "--rps", help="Requests per second rate limit"),
    concurrency: int = typer.Option(20, "--concurrency", help="Maximum concurrent workers"),
    cache_ttl: float = typer.Option(3600.0, "--cache-ttl", help="Cache TTL in seconds"),
    out_csv: Optional[Path] = typer.Option(None, "--out-csv", help="Output CSV file path"),
    out_jsonl: Optional[Path] = typer.Option(None, "--out-jsonl", help="Output JSON Lines file path"),
    samples_jsonl: Optional[Path] = typer.Option(None, "--samples-jsonl", help="Detailed samples JSON Lines file"),
    log_level: str = typer.Option("INFO", "--log-level", help="Log level (DEBUG, INFO, WARNING, ERROR)"),
    nameserver: Optional[str] = typer.Option(None, "--nameserver", help="Target nameserver IP (unused in current implementation)")
) -> None:
    """
    Replay DNS traffic from PCAP and perform reputation analysis.
    
    Extracts domains from DNS queries in the PCAP file and performs concurrent
    reputation lookups with rate limiting, caching, and comprehensive reporting.
    """
    # Validate inputs
    if not pcap.exists():
        console.print(f"[red]Error: PCAP file {pcap} does not exist[/red]")
        raise typer.Exit(1)
        
    if not out_csv and not out_jsonl:
        console.print("[yellow]Warning: No output files specified, results will not be saved[/yellow]")
        
    # Setup logging
    setup_logging(log_level)
    logger = logging.getLogger(__name__)
    
    # Setup signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    console.print(f"[green]Starting DNS Reputation Analysis Tool[/green]")
    console.print(f"PCAP file: {pcap}")
    console.print(f"Rate limit: {rps} RPS")
    console.print(f"Concurrency: {concurrency} workers")
    console.print(f"Cache TTL: {cache_ttl} seconds")
    if timeout:
        console.print(f"Timeout: {timeout} seconds")
    console.print()
    
    async def main():
        start_time = time.time()
        
        # Initialize results manager
        async with ResultsManager(out_csv, out_jsonl, samples_jsonl) as results_manager:
            # Initialize metrics collector
            metrics_collector = MetricsCollector(report_interval=10.0)
            
            try:
                reason = await run_analysis(
                    pcap, timeout, rps, concurrency, cache_ttl,
                    results_manager, metrics_collector
                )
                
                # Print final summary
                runtime = time.time() - start_time
                summary = metrics_collector.get_final_summary(runtime)
                
                console.print()
                console.print("[green]Test is over![/green] Reason:", reason)
                console.print(f"Total runtime: {summary['total_runtime_seconds']} seconds")
                console.print(f"Requests total: {summary['requests_total']}")
                console.print(f"Domains processed: {summary['domains_processed']}")
                console.print(f"Average response time: {summary['average_response_time_ms']}ms")
                console.print(f"Max response time: {summary['max_response_time_ms']}ms")
                
                if out_csv:
                    console.print(f"Results saved to: {out_csv}")
                if out_jsonl:
                    console.print(f"Results saved to: {out_jsonl}")
                if samples_jsonl:
                    console.print(f"Samples saved to: {samples_jsonl}")
                    
            except Exception as e:
                logger.error(f"Analysis failed: {e}")
                console.print(f"[red]Analysis failed: {e}[/red]")
                raise typer.Exit(1)
    
    # Run the async main function
    asyncio.run(main())


if __name__ == "__main__":
    app()
