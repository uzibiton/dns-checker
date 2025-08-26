import os
import time
import threading
import queue
from turtle import mode
import requests
from scapy.all import PcapNgReader, rdpcap, DNS, sniff
from concurrent.futures import ThreadPoolExecutor


def get_domain_info(domain, query_source=None):
    """
    Returns a structured dictionary with domain reputation information:
    - domain: normalized (lowercase, no trailing dot)
    - reputation_score: integer (0–100)
    - classification: "Trusted" (61–100) or "Untrusted" (0–60)
    - categories: array/list (e.g., ["general"])
    - query_source: from PCAP (e.g., pcap_file:frame_no:src_ip:src_port->dst_ip:dst_port)
    - response_time_ms: integer
    """    
    import time
    start_time = time.time()
    
    # Normalize domain (lowercase, no trailing dot)
    normalized_domain = domain.lower().rstrip('.')
    
    base_url = 'https://microcks.gin.dev.securingsam.io/rest/Reputation+API/1.0.0/domain/ranking'
    response = requests.get(
        url=f"{base_url}/{normalized_domain}",
        headers={
            'Authorization': 'Token I_am_under_stress_when_I_test',
            'Accept': 'application/json'
        }
    )
    
    end_time = time.time()
    response_time_ms = int((end_time - start_time) * 1000)
    
    if response.ok:
        api_data = response.json()
        reputation_score = api_data.get('reputation', 0)
        
        # Determine classification based on reputation score
        classification = "Trusted" if reputation_score >= 61 else "Untrusted"
        
        # Structure the return data
        domain_info = {
            'domain': normalized_domain,
            'reputation_score': reputation_score,
            'classification': classification,
            'categories': api_data.get('categories', ['general']),
            'query_source': query_source,
            'response_time_ms': response_time_ms
        }
        
        return domain_info
    else:
        print(f'Failed to fetch data for domain: {normalized_domain}')
        return None


def get_domain_ranking(domain):
    info = get_domain_info(domain)
    print(info)
    return info.get('reputation_score', 'No reputation found') if info else 'No reputation found'


def read_packets_from_file(file_path):
    """ Read packets from a pcap file """
    packets = PcapNgReader(file_path)  if file_path.lower().endswith('.pcapng') else rdpcap(file_path)
    for pkt in packets:
        yield pkt


def read_packets_from_interface(interface=None, filter_expr="port 53", count=0):
    """ Read packets from a network interface """
    try:
        if count == 0:
            # For infinite capture, we need to use a different approach
            # Capture in small batches and yield each packet
            batch_size = 10
            while True:
                packets = sniff(iface=interface, filter=filter_expr, count=batch_size, store=1, timeout=5)
                if not packets:
                    continue  # No packets captured in this batch, try again
                for pkt in packets:
                    yield pkt
        else:
            packets = sniff(iface=interface, filter=filter_expr, count=count, store=1)
            for pkt in packets:
                yield pkt
    except Exception as e:
        print(f"Sniff error: {e}")
        return


def get_domain_from_dns_pkt(pkt):
    # Extract the domain from the DNS query section using qname
    if DNS in pkt:
        dns_layer = pkt[DNS]
        if hasattr(dns_layer, 'qd') and dns_layer.qdcount > 0:
            domains = []
            # Scapy's DNS.qd is a DNSQR object or a list of DNSQR objects if qdcount > 1
            qd = dns_layer.qd
            if dns_layer.qdcount > 1 and hasattr(qd, '__iter__'):
                for question in qd:
                    if hasattr(question, 'qname'):
                        name = question.qname.decode() if isinstance(question.qname, bytes) else str(question.qname)
                        domains.append(name.rstrip('.'))
            else:
                if hasattr(qd, 'qname'):
                    name = qd.qname.decode() if isinstance(qd.qname, bytes) else str(qd.qname)
                    domains.append(name.rstrip('.'))
            return ', '.join(domains) if domains else None
    return None


def get_query_source_from_pkt(pkt, source_type="live", frame_no=None):
    """Extract query source information from packet"""
    if hasattr(pkt, 'src') and hasattr(pkt, 'dst'):
        src_ip = pkt.src if hasattr(pkt, 'src') else 'unknown'
        dst_ip = pkt.dst if hasattr(pkt, 'dst') else 'unknown'
        src_port = pkt.sport if hasattr(pkt, 'sport') else 'unknown'
        dst_port = pkt.dport if hasattr(pkt, 'dport') else 'unknown'
        
        if source_type == "pcap" and frame_no:
            return f"pcap_file:frame_{frame_no}:{src_ip}:{src_port}->{dst_ip}:{dst_port}"
        else:
            return f"live_capture:{src_ip}:{src_port}->{dst_ip}:{dst_port}"
    return "unknown_source"


class DNSReputationAnalyzer:
    def __init__(self, max_workers=5, cache_size=1000):
        self.packet_queue = queue.Queue(maxsize=100)  # Buffer for packets
        self.domain_cache = {}  # Cache for domain reputation
        self.cache_lock = threading.Lock()  # Thread-safe cache access
        self.max_workers = max_workers
        self.statistics = {
            'total_packets': 0,
            'dns_packets': 0,
            'api_calls': 0,
            'cache_hits': 0,
            'errors': 0
        }
        self.stats_lock = threading.Lock()
        self.running = False
        
    def update_stats(self, stat_name, increment=1):
        """Thread-safe statistics update"""
        with self.stats_lock:
            self.statistics[stat_name] += increment
    
    def get_cached_domain_info(self, domain):
        """Thread-safe cache lookup"""
        with self.cache_lock:
            return self.domain_cache.get(domain)
    
    def cache_domain_info(self, domain, info):
        """Thread-safe cache storage"""
        with self.cache_lock:
            self.domain_cache[domain] = info
    
    def packet_reader_thread(self, source, source_type="file"):
        """Producer thread: reads packets and puts them in queue"""
        try:
            if source_type == "file":
                packet_generator = read_packets_from_file(source)
            else:  # interface
                packet_generator = read_packets_from_interface(source, count=0)
            
            frame_no = 0
            for pkt in packet_generator:
                if not self.running:
                    break
                    
                frame_no += 1
                self.update_stats('total_packets')
                
                if DNS in pkt:
                    self.update_stats('dns_packets')
                    domain = get_domain_from_dns_pkt(pkt)
                    if domain:
                        query_source = get_query_source_from_pkt(pkt, source_type, frame_no)
                        # Put packet info in queue for processing
                        packet_info = {
                            'domain': domain,
                            'query_source': query_source,
                            'frame_no': frame_no
                        }
                        try:
                            if self.running:  # Check if still running before putting
                                self.packet_queue.put(packet_info, timeout=1)
                        except queue.Full:
                            print("Warning: Packet queue full, dropping packet")
                            self.update_stats('errors')
                            
        except Exception as e:
            print(f"Packet reader error: {e}")
            self.update_stats('errors')
        finally:
            # Signal end of packets to all workers
            for _ in range(self.max_workers):
                try:
                    self.packet_queue.put(None, timeout=1)
                except queue.Full:
                    pass
            print("Packet reader finished")
    
    def domain_processor_worker(self):
        """Consumer worker: processes domains from queue"""
        while self.running:
            try:
                # Get packet from queue with timeout
                packet_info = self.packet_queue.get(timeout=1)
                
                # None signals end of packets
                if packet_info is None:
                    self.packet_queue.task_done()  # Mark the None as done
                    break
                
                domain = packet_info['domain']
                
                # Check cache first
                domain_info = self.get_cached_domain_info(domain)
                
                if domain_info:
                    self.update_stats('cache_hits')
                    # Use cached data but update query_source
                    domain_info = domain_info.copy()
                    domain_info['query_source'] = packet_info['query_source']
                else:
                    # Make API call
                    self.update_stats('api_calls')
                    domain_info = get_domain_info(domain, packet_info['query_source'])
                    
                    if domain_info:
                        # Cache the result
                        self.cache_domain_info(domain, domain_info)
                    else:
                        self.update_stats('errors')
                        # Still mark task as done even if API call failed
                        self.packet_queue.task_done()
                        continue
                
                # Process/display result
                self.display_domain_info(domain_info)
                
                # Mark task as done
                self.packet_queue.task_done()
                
            except queue.Empty:
                continue  # Timeout, check if still running
            except Exception as e:
                print(f"Domain processor error: {e}")
                self.update_stats('errors')
                # Make sure to mark task as done even on error
                try:
                    self.packet_queue.task_done()
                except ValueError:
                    pass  # task_done called more times than items in queue
    
    def display_domain_info(self, domain_info):
        """Display domain information (thread-safe)"""
        print(f"Domain: {domain_info['domain']}")
        print(f"  Reputation: {domain_info['reputation_score']} ({domain_info['classification']})")
        print(f"  Categories: {domain_info['categories']}")
        print(f"  Response time: {domain_info['response_time_ms']}ms")
        print(f"  Source: {domain_info['query_source']}")
        print("-" * 50)
    
    def print_statistics(self):
        """Print current statistics"""
        with self.stats_lock:
            stats = self.statistics.copy()
        
        print(f"\n=== Statistics ===")
        print(f"Total packets: {stats['total_packets']}")
        print(f"DNS packets: {stats['dns_packets']}")
        print(f"API calls made: {stats['api_calls']}")
        print(f"Cache hits: {stats['cache_hits']}")
        print(f"Errors: {stats['errors']}")
        cache_hit_rate = (stats['cache_hits'] / max(stats['dns_packets'], 1)) * 100
        print(f"Cache hit rate: {cache_hit_rate:.1f}%")
    
    def analyze_file(self, file_path):
        """Analyze DNS packets from a PCAP file"""
        self.running = True
        print(f"Starting analysis with {self.max_workers} worker threads...")
        
        # Start packet reader thread
        reader_thread = threading.Thread(
            target=self.packet_reader_thread, 
            args=(file_path, "file"),
            name="PacketReader"
        )
        
        # Start domain processor threads
        with ThreadPoolExecutor(max_workers=self.max_workers, thread_name_prefix="DomainProcessor") as executor:
            # Submit worker tasks
            futures = [executor.submit(self.domain_processor_worker) for _ in range(self.max_workers)]
            
            # Start packet reader
            reader_thread.start()
            
            try:
                # Wait for packet reader to finish
                print("Waiting for packet reader to finish...")
                reader_thread.join()
                print("Packet reader finished, waiting for workers to complete...")
                
                # Wait for queue to be processed with timeout
                start_time = time.time()
                while not self.packet_queue.empty() and (time.time() - start_time) < 30:
                    time.sleep(0.1)
                
                # Stop workers
                self.running = False
                
            except KeyboardInterrupt:
                print("\nStopping analysis...")
                self.running = False
                
            finally:
                # Ensure all threads stop
                self.running = False
                
                # Wait for all futures to complete with timeout
                for i, future in enumerate(futures):
                    try:
                        future.result(timeout=5)
                        print(f"Worker {i+1} finished")
                    except Exception as e:
                        print(f"Worker {i+1} error: {e}")
        
        self.print_statistics()
    
    def analyze_interface(self, interface_name):
        """Analyze DNS packets from a network interface"""
        self.running = True
        
        # Start packet reader thread
        reader_thread = threading.Thread(
            target=self.packet_reader_thread, 
            args=(interface_name, "interface"),
            name="PacketReader"
        )
        
        # Start domain processor threads
        with ThreadPoolExecutor(max_workers=self.max_workers, thread_name_prefix="DomainProcessor") as executor:
            # Submit worker tasks
            futures = [executor.submit(self.domain_processor_worker) for _ in range(self.max_workers)]
            
            # Start packet reader
            reader_thread.start()
            
            try:
                # For interface capture, run until interrupted
                while self.running:
                    time.sleep(1)
                    # Optionally print periodic statistics
                    
            except KeyboardInterrupt:
                print("\nStopping capture...")
                
            finally:
                # Stop all threads
                self.running = False
                reader_thread.join(timeout=5)
                
                # Stop workers
                for future in futures:
                    try:
                        future.result(timeout=2)
                    except:
                        pass
        
        self.print_statistics()


def test_read_from_interface():
    intr = "Wi-Fi"
    print(f"Starting packet capture on interface: {intr}")
    dns_count = 0
    total_count = 0
    try:
        for pkt in read_packets_from_interface(interface=intr, count=0):  # Capture all packets
            total_count += 1            
            if DNS in pkt:
                dns_count += 1
                domain = get_domain_from_dns_pkt(pkt)
                if domain:
                    query_source = get_query_source_from_pkt(pkt, "live")
                    domain_info = get_domain_info(domain, query_source)
                    if domain_info:
                        print(f"Domain: {domain_info['domain']}")
                        print(f"  Reputation: {domain_info['reputation_score']} ({domain_info['classification']})")
                        print(f"  Categories: {domain_info['categories']}")
                        print(f"  Response time: {domain_info['response_time_ms']}ms")
                        print(f"  Source: {domain_info['query_source']}")
                        print("-" * 50)
    except KeyboardInterrupt:
        print("\nCapture stopped by user")
    except Exception as e:
        print(f"Error during capture: {e}")
    finally:
        print(f"Total packets processed: {total_count}")
        print(f"DNS packets found: {dns_count}")


def test_read_from_file():
    # file_name = "test3.pcap"
    file_name = "test1.pcapng"
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    files_dir = os.path.join(base_dir, "files")
    file_path = os.path.join(files_dir, file_name)
    dns_count = 0
    total_count = 0    
    try:
        for pkt in read_packets_from_file(file_path):
            total_count += 1
            if DNS in pkt:
                dns_count += 1
                domain = get_domain_from_dns_pkt(pkt)
                if domain:
                    query_source = get_query_source_from_pkt(pkt, "pcap", total_count)
                    domain_info = get_domain_info(domain, query_source)
                    if domain_info:
                        print(f"Domain: {domain_info['domain']}")
                        print(f"  Reputation: {domain_info['reputation_score']} ({domain_info['classification']})")
                        print(f"  Categories: {domain_info['categories']}")
                        print(f"  Response time: {domain_info['response_time_ms']}ms")
                        print(f"  Source: {domain_info['query_source']}")
                        print("-" * 50)
    except KeyboardInterrupt:
        print("\nCapture stopped by user")
    except Exception as e:
        print(f"Error during capture: {e}")
    finally:
        print(f"Total packets processed: {total_count}")
        print(f"DNS packets found: {dns_count}")


def test_get_domain_ranking():
    # Test with a known domain
    domain = "example.com"
    reputation = get_domain_ranking(domain)
    print(f"Domain: {domain}, reputation: {reputation}")


def test_threaded_file_analysis():
    """Test threaded analysis of PCAP file"""
    analyzer = DNSReputationAnalyzer(max_workers=3)
    
    file_name = "test1.pcapng"
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    files_dir = os.path.join(base_dir, "files")
    file_path = os.path.join(files_dir, file_name)
    
    print(f"Starting threaded analysis of: {file_path}")
    analyzer.analyze_file(file_path)


def test_threaded_interface_analysis():
    """Test threaded analysis of network interface"""
    analyzer = DNSReputationAnalyzer(max_workers=3)
    
    interface_name = "Wi-Fi"
    print(f"Starting threaded capture on interface: {interface_name}")
    analyzer.analyze_interface(interface_name)


def main(mode):
    if (mode == "file"):
        # file_name = "test3.pcap"
        file_name = "test1.pcapng"
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        files_dir = os.path.join(base_dir, "files")
        file_path = os.path.join(files_dir, file_name)
        print(f"Reading packets from file: {file_path}")
        packets = read_packets_from_file(file_path)
        source_type = "pcap"
    elif (mode == "interface"):
        intr = "Wi-Fi"
        print(f"Reading packets from interface: {intr}")
        packets = read_packets_from_interface(interface=intr, count=0)
        source_type = "live"
    else:
        raise ValueError("Invalid mode. Use 'file' or 'interface'.")

    dns_count = 0
    total_count = 0    
    try:
        for pkt in packets:
            total_count += 1
            if DNS in pkt:
                dns_count += 1
                domain = get_domain_from_dns_pkt(pkt)
                if domain:
                    query_source = get_query_source_from_pkt(pkt, source_type, total_count)
                    domain_info = get_domain_info(domain, query_source)
                    if domain_info:
                        print(f"Domain: {domain_info['domain']}")
                        print(f"  Reputation: {domain_info['reputation_score']} ({domain_info['classification']})")
                        print(f"  Categories: {domain_info['categories']}")
                        print(f"  Response time: {domain_info['response_time_ms']}ms")
                        print(f"  Source: {domain_info['query_source']}")
                        print("-" * 50)
    except KeyboardInterrupt:
        print("\nCapture stopped by user")
    except Exception as e:
        print(f"Error during capture: {e}")
    finally:
        print(f"Total packets processed: {total_count}")
        print(f"DNS packets found: {dns_count}")


if __name__ == "__main__":
    print("Starting DNS Checker Tool...")
    
    # Run threaded file analysis by default for testing
    print("Running multi-threaded file analysis...")
    # test_threaded_file_analysis()
    
    # Uncomment below for interactive mode
    print("Available modes:")
    print("1. Single-threaded file analysis")
    print("2. Single-threaded interface capture") 
    print("3. Multi-threaded file analysis")
    print("4. Multi-threaded interface capture")
    
    choice = input("Select mode (1-4): ").strip()
    
    if choice == "1":
        main(mode="file")
    elif choice == "2":
        main(mode="interface")
    elif choice == "3":
        test_threaded_file_analysis()
    elif choice == "4":
        test_threaded_interface_analysis()
    else:
        print("Invalid choice, using default threaded file analysis")
        test_threaded_file_analysis()