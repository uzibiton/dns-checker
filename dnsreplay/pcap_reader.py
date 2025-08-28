"""PCAP reader module for extracting DNS domains from packet captures."""

import asyncio
import logging
import threading
from pathlib import Path
from typing import AsyncGenerator, Dict, Generator, NamedTuple, Optional

from scapy.all import DNS, PcapNgReader, rdpcap
from scapy.packet import Packet

from .utils import extract_query_source, normalize_domain

logger = logging.getLogger(__name__)


class DomainQuery(NamedTuple):
    """Represents a DNS domain query extracted from PCAP."""
    domain: str
    query_source: str
    timestamp: float
    packet_info: Dict[str, str]


class PcapReader:
    """
    Reads DNS packets from PCAP files and extracts domain queries.
    Runs in a separate thread and feeds results to an async queue.
    """
    
    def __init__(self, pcap_path: Path, queue: asyncio.Queue[Optional[DomainQuery]], event_loop: asyncio.AbstractEventLoop):
        self.pcap_path = pcap_path
        self.queue = queue
        self.event_loop = event_loop
        self.running = False
        self._thread: Optional[threading.Thread] = None
        self._completion_signaled = False
        
    def start(self) -> None:
        """Start the PCAP reader thread."""
        if self._thread and self._thread.is_alive():
            raise RuntimeError("PCAP reader is already running")
            
        self.running = True
        self._thread = threading.Thread(target=self._read_packets, daemon=True)
        self._thread.start()
        logger.info(f"Started PCAP reader for {self.pcap_path}")
        
    def stop(self) -> None:
        """Stop the PCAP reader thread."""
        self.running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=5.0)
            
        # Signal completion by sending None
        # Signal completion by putting None in the queue (if not already stopped)
        if self.running and not self._completion_signaled:
            try:
                future = asyncio.run_coroutine_threadsafe(
                    self.queue.put(None), 
                    self.event_loop
                )
                future.result(timeout=1.0)
                self._completion_signaled = True
            except Exception as e:
                logger.debug(f"Failed to signal completion during stop: {e}")
            
        logger.info("PCAP reader stopped")
        
    def _read_packets(self) -> None:
        """Read packets from PCAP file in background thread."""
        try:
            packet_count = 0
            dns_count = 0
            batch_size = 10  # Process in small batches for better performance
            pending_domains = []
            
            for packet in self._iterate_packets():
                if not self.running:
                    break
                    
                packet_count += 1
                
                if DNS in packet:
                    dns_count += 1
                    domain_queries = self._extract_dns_domains(packet, packet_count)
                    pending_domains.extend(domain_queries)
                    
                    # Process domains in batches to reduce threading overhead
                    if len(pending_domains) >= batch_size:
                        self._queue_domain_batch(pending_domains)
                        pending_domains = []
                            
                if packet_count % 1000 == 0:
                    logger.info(f"Reading progress: {packet_count} packets processed, {dns_count} DNS queries found")
                    
            # Process remaining domains
            if pending_domains:
                self._queue_domain_batch(pending_domains)
                    
            logger.info(f"Finished reading PCAP: {packet_count} packets, {dns_count} DNS")
            
        except Exception as e:
            logger.error(f"Error reading PCAP: {e}")
        finally:
            # Signal completion
            if not self._completion_signaled:
                try:
                    future = asyncio.run_coroutine_threadsafe(
                        self.queue.put(None),
                        self.event_loop
                    )
                    future.result(timeout=2.0)  # Longer timeout for completion signal
                    self._completion_signaled = True
                except Exception:
                    pass
                    
    def _queue_domain_batch(self, domain_queries: list) -> None:
        """Queue a batch of domain queries efficiently."""
        for domain_query in domain_queries:
            try:
                # Use shorter timeout and don't block on each item
                future = asyncio.run_coroutine_threadsafe(
                    self.queue.put(domain_query),
                    self.event_loop
                )
                # Don't wait for completion to avoid blocking
                # The async queue will handle backpressure
            except Exception as e:
                logger.debug(f"Failed to queue domain query: {e}")
                
    def _iterate_packets(self) -> Generator[Packet, None, None]:
        """Iterate over packets in the PCAP file."""
        try:
            if self.pcap_path.suffix.lower() == ".pcapng":
                packets = PcapNgReader(str(self.pcap_path))
            else:
                packets = rdpcap(str(self.pcap_path))
                
            for packet in packets:
                yield packet
                
        except Exception as e:
            logger.error(f"Failed to read PCAP file {self.pcap_path}: {e}")
            
    def _extract_dns_domains(self, packet: Packet, frame_no: int) -> list[DomainQuery]:
        """Extract DNS domains from a packet."""
        if not packet.haslayer(DNS):
            return []
            
        dns_layer = packet[DNS]
        
        # Only process queries (not responses)
        if dns_layer.qr != 0:  # 0 = query, 1 = response
            return []
            
        domains = []
        
        # Extract packet metadata
        packet_info = self._extract_packet_info(packet, frame_no)
        query_source = extract_query_source(packet_info)
        
        # Handle multiple questions in one DNS packet
        if hasattr(dns_layer, 'qd') and dns_layer.qdcount > 0:
            questions = dns_layer.qd if isinstance(dns_layer.qd, list) else [dns_layer.qd]
            
            for question in questions:
                if hasattr(question, 'qname'):
                    try:
                        # Extract and normalize domain name
                        raw_domain = question.qname.decode() if isinstance(question.qname, bytes) else str(question.qname)
                        normalized_domain = normalize_domain(raw_domain)
                        
                        if normalized_domain:
                            domain_query = DomainQuery(
                                domain=normalized_domain,
                                query_source=query_source,
                                timestamp=float(packet.time) if hasattr(packet, 'time') else 0.0,
                                packet_info=packet_info
                            )
                            domains.append(domain_query)
                            
                    except Exception as e:
                        logger.warning(f"Failed to extract domain from packet {frame_no}: {e}")
                        
        return domains
        
    def _extract_packet_info(self, packet: Packet, frame_no: int) -> Dict[str, str]:
        """Extract metadata from packet for query source tracking."""
        info = {
            "frame_no": str(frame_no),
            "src_ip": "unknown",
            "src_port": "unknown", 
            "dst_ip": "unknown",
            "dst_port": "unknown"
        }
        
        try:
            # Extract IP layer info
            if packet.haslayer("IP"):
                ip_layer = packet["IP"]
                info["src_ip"] = str(ip_layer.src)
                info["dst_ip"] = str(ip_layer.dst)
            elif packet.haslayer("IPv6"):
                ipv6_layer = packet["IPv6"]
                info["src_ip"] = str(ipv6_layer.src)
                info["dst_ip"] = str(ipv6_layer.dst)
                
            # Extract transport layer ports
            if packet.haslayer("UDP"):
                udp_layer = packet["UDP"]
                info["src_port"] = str(udp_layer.sport)
                info["dst_port"] = str(udp_layer.dport)
            elif packet.haslayer("TCP"):
                tcp_layer = packet["TCP"]
                info["src_port"] = str(tcp_layer.sport)
                info["dst_port"] = str(tcp_layer.dport)
                
        except Exception as e:
            logger.debug(f"Failed to extract packet info from frame {frame_no}: {e}")
            
        return info
