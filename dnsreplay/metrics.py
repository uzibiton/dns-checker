"""Metrics collection and reporting for DNS reputation analysis."""

import asyncio
import logging
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Deque, Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class RequestMetric:
    """Represents a single request metric."""
    timestamp: float
    response_time_ms: int
    success: bool
    domain: str


@dataclass
class MetricsSnapshot:
    """Snapshot of current metrics."""
    timestamp: float = field(default_factory=time.time)
    total_requests: int = 0
    successful_requests: int = 0
    failed_requests: int = 0
    unique_domains: int = 0
    avg_response_time_ms: float = 0.0
    min_response_time_ms: int = 0
    max_response_time_ms: int = 0
    requests_per_second: float = 0.0
    cache_hit_rate: float = 0.0
    
    def to_dict(self) -> Dict:
        """Convert to dictionary."""
        return {
            "timestamp": self.timestamp,
            "total_requests": self.total_requests,
            "successful_requests": self.successful_requests,
            "failed_requests": self.failed_requests,
            "unique_domains": self.unique_domains,
            "avg_response_time_ms": round(self.avg_response_time_ms, 2),
            "min_response_time_ms": self.min_response_time_ms,
            "max_response_time_ms": self.max_response_time_ms,
            "requests_per_second": round(self.requests_per_second, 2),
            "cache_hit_rate_percent": round(self.cache_hit_rate, 2)
        }


class MetricsCollector:
    """
    Collects and aggregates metrics for reputation lookups.
    
    Features:
    - Request rate calculation
    - Response time statistics 
    - Success/failure tracking
    - Periodic reporting
    - Moving averages
    """
    
    def __init__(self, window_size: int = 1000, report_interval: float = 10.0):
        self.window_size = window_size
        self.report_interval = report_interval
        
        # Metrics storage
        self._metrics: Deque[RequestMetric] = deque(maxlen=window_size)
        self._domains_seen: set = set()
        self._start_time = time.time()
        
        # Reporting task
        self._report_task: Optional[asyncio.Task] = None
        self._running = False
        
        # Snapshot history for trends
        self._snapshots: Deque[MetricsSnapshot] = deque(maxlen=100)
        
    async def start_reporting(self) -> None:
        """Start the periodic metrics reporting task."""
        if self._report_task is None or self._report_task.done():
            self._running = True
            self._report_task = asyncio.create_task(self._report_loop())
            logger.info(f"Started metrics reporting (interval: {self.report_interval}s)")
            
    async def stop_reporting(self) -> None:
        """Stop the periodic metrics reporting task."""
        self._running = False
        if self._report_task and not self._report_task.done():
            self._report_task.cancel()
            try:
                await self._report_task
            except asyncio.CancelledError:
                pass
            logger.info("Stopped metrics reporting")
            
    def record_request(
        self, 
        domain: str, 
        response_time_ms: int, 
        success: bool
    ) -> None:
        """
        Record a request metric.
        
        Args:
            domain: Domain that was queried
            response_time_ms: Response time in milliseconds
            success: Whether the request was successful
        """
        metric = RequestMetric(
            timestamp=time.time(),
            response_time_ms=response_time_ms,
            success=success,
            domain=domain
        )
        
        self._metrics.append(metric)
        self._domains_seen.add(domain)
        
    def get_current_snapshot(self, cache_stats: Optional[Dict] = None) -> MetricsSnapshot:
        """
        Get current metrics snapshot.
        
        Args:
            cache_stats: Optional cache statistics
            
        Returns:
            Current metrics snapshot
        """
        if not self._metrics:
            return MetricsSnapshot()
            
        now = time.time()
        
        # Calculate basic counts
        total_requests = len(self._metrics)
        successful_requests = sum(1 for m in self._metrics if m.success)
        failed_requests = total_requests - successful_requests
        unique_domains = len(self._domains_seen)
        
        # Calculate response time statistics
        response_times = [m.response_time_ms for m in self._metrics]
        avg_response_time = sum(response_times) / len(response_times)
        min_response_time = min(response_times)
        max_response_time = max(response_times)
        
        # Calculate requests per second (over last minute)
        one_minute_ago = now - 60
        recent_requests = [m for m in self._metrics if m.timestamp >= one_minute_ago]
        requests_per_second = len(recent_requests) / min(60, now - self._start_time)
        
        # Get cache hit rate
        cache_hit_rate = 0.0
        if cache_stats:
            total_cache_requests = cache_stats.get("total_requests", 0)
            if total_cache_requests > 0:
                cache_hit_rate = cache_stats.get("hit_rate_percent", 0.0)
        
        snapshot = MetricsSnapshot(
            timestamp=now,
            total_requests=total_requests,
            successful_requests=successful_requests,
            failed_requests=failed_requests,
            unique_domains=unique_domains,
            avg_response_time_ms=avg_response_time,
            min_response_time_ms=min_response_time,
            max_response_time_ms=max_response_time,
            requests_per_second=requests_per_second,
            cache_hit_rate=cache_hit_rate
        )
        
        self._snapshots.append(snapshot)
        return snapshot
        
    def get_final_summary(self, runtime_seconds: float, cache_stats: Optional[Dict] = None) -> Dict:
        """
        Get final summary statistics for shutdown.
        
        Args:
            runtime_seconds: Total runtime in seconds
            cache_stats: Optional cache statistics
            
        Returns:
            Final summary dictionary
        """
        if not self._metrics:
            return {
                "total_runtime_seconds": runtime_seconds,
                "requests_total": 0,
                "domains_processed": 0,
                "average_response_time_ms": 0,
                "max_response_time_ms": 0
            }
            
        response_times = [m.response_time_ms for m in self._metrics]
        
        return {
            "total_runtime_seconds": round(runtime_seconds, 2),
            "requests_total": len(self._metrics),
            "requests_successful": sum(1 for m in self._metrics if m.success),
            "requests_failed": sum(1 for m in self._metrics if not m.success),
            "domains_processed": len(self._domains_seen),
            "average_response_time_ms": round(sum(response_times) / len(response_times), 2),
            "min_response_time_ms": min(response_times),
            "max_response_time_ms": max(response_times),
            "requests_per_second": round(len(self._metrics) / runtime_seconds, 2) if runtime_seconds > 0 else 0,
            "cache_hit_rate_percent": cache_stats.get("hit_rate_percent", 0.0) if cache_stats else 0.0
        }
        
    async def _report_loop(self) -> None:
        """Periodic reporting loop."""
        while self._running:
            try:
                await asyncio.sleep(self.report_interval)
                if self._running:
                    await self._print_current_metrics()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in metrics reporting: {e}")
                
    async def _print_current_metrics(self) -> None:
        """Print current metrics to log."""
        snapshot = self.get_current_snapshot()
        
        logger.info(
            f"METRICS | "
            f"Requests: {snapshot.total_requests} "
            f"({snapshot.successful_requests} success, {snapshot.failed_requests} failed) | "
            f"Domains: {snapshot.unique_domains} | "
            f"QPS: {snapshot.requests_per_second:.1f} | "
            f"Avg latency: {snapshot.avg_response_time_ms:.0f}ms | "
            f"Cache hit rate: {snapshot.cache_hit_rate:.1f}%"
        )
        
    def get_trend_data(self) -> List[Dict]:
        """Get historical trend data."""
        return [snapshot.to_dict() for snapshot in self._snapshots]
