# DNS Reputation Analysis Tool

A production-ready tool for analyzing DNS traffic from PCAP files and performing concurrent reputation lookups with comprehensive monitoring and reporting.

> **Note**: This version focuses on PCAP file analysis. Live network interface capture from the original version has been removed in favor of a more production-focused approach. For live capture, use tools like `tcpdump` or `wireshark` to create PCAP files first.

## Features

- 🚀 **High Performance**: Concurrent API calls with configurable rate limiting
- 📊 **Smart Caching**: TTL-based caching with per-key locks to prevent thundering herd
- 📈 **Real-time Metrics**: Live monitoring with periodic progress reports
- 💾 **Multiple Output Formats**: CSV and JSON Lines export with detailed samples
- 🛡️ **Robust Error Handling**: Retry logic with exponential backoff
- ⚡ **Async Architecture**: Producer-consumer pipeline for optimal throughput
- 🎯 **Domain Normalization**: Proper handling of IDN, case, and trailing dots

## Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/uzibiton/dns-checker.git
cd dns-checker

# Install dependencies (Python 3.12+ required)
pip install -e .

# Or install development dependencies
pip install -e ".[dev]"
```

### Basic Usage

```bash
# Analyze a PCAP file with default settings (5 minute timeout)
python -m dnsreplay sample.pcap --out-csv results.csv

# Quick analysis with shorter timeout
python -m dnsreplay sample.pcap --out-csv results.csv --timeout 60

# Full configuration example
python -m dnsreplay capture.pcap \
    --timeout 300 \
    --rps 100 \
    --concurrency 20 \
    --cache-ttl 3600 \
    --out-csv results.csv \
    --out-jsonl results.jsonl \
    --samples-jsonl debug.jsonl \
    --log-level INFO
```

## Configuration Options

| Option | Default | Description |
|--------|---------|-------------|
| `--timeout` | 300 | **Overall run timeout in seconds (prevents infinite wait)** |
| `--rps` | 100 | Requests per second rate limit |
| `--concurrency` | 20 | Maximum concurrent workers |
| `--cache-ttl` | 3600 | Cache TTL in seconds |
| `--out-csv` | None | Output CSV file path |
| `--out-jsonl` | None | Output JSON Lines file path |
| `--samples-jsonl` | None | Detailed samples file (debug) |
| `--log-level` | INFO | Log level (DEBUG/INFO/WARNING/ERROR) |

## Architecture

```
┌─────────────┐    ┌──────────────┐    ┌─────────────────┐
│ PCAP Reader │───▶│ Async Queue  │───▶│ Reputation      │
│ (Thread)    │    │              │    │ Workers (Async) │
└─────────────┘    └──────────────┘    └─────────────────┘
                                                 │
                    ┌─────────────┐             │
                    │ Rate        │◀────────────┘
                    │ Limiter     │
                    └─────────────┘
                             │
┌─────────────┐    ┌─────────▼──┐    ┌──────────────┐
│ TTL Cache   │◀───│ API Client │───▶│ Results      │
│             │    │            │    │ Writers      │
└─────────────┘    └────────────┘    └──────────────┘
```

### Components

- **PCAP Reader**: Thread-based parser using Scapy, extracts DNS domains
- **Async Queue**: Buffers domains between reader and workers  
- **Reputation Workers**: Async tasks performing concurrent API lookups
- **Rate Limiter**: Token bucket + semaphore for precise rate control
- **TTL Cache**: Per-key locks prevent duplicate requests for same domain
- **API Client**: HTTP client with retries, timeouts, and error handling
- **Results Writers**: Async CSV/JSON writers with deduplication

## Output Formats

### Main Results (CSV/JSON Lines)

One row per unique domain with complete analysis:

```csv
domain,reputation_score,classification,categories,query_source,response_time_ms,timestamp_utc,cached,attempts,http_status,status,error_message
example.com,85,Trusted,"[""general""]",pcap:frame_100:192.168.1.1:12345->8.8.8.8:53,245,1640995200.123,false,1,200,success,
```

### Samples File (Debug)

Detailed log of every API call including retries:

```json
{"timestamp": 1640995200.123, "domain": "example.com", "attempt": 1, "response_time_ms": 245, "http_status": 200, "success": true, "cached": false}
{"timestamp": 1640995201.456, "domain": "bad-domain.com", "attempt": 1, "response_time_ms": 5000, "http_status": null, "success": false, "error": "timeout", "cached": false}
```

## API Details

The tool queries the reputation API:

- **Endpoint**: `https://microcks.gin.dev.securingsam.io/rest/Reputation+API/1.0.0/domain/ranking/{domain}`
- **Authentication**: `Authorization: Token I_am_under_stress_when_I_test`
- **Response Format**: `{"address": "domain.com", "reputation": 85, "categories": ["general"]}`
- **Classification**: 0-60 = Untrusted, 61-100 = Trusted

## Monitoring

The tool provides real-time monitoring with periodic reports:

```
INFO dnsreplay.metrics: METRICS | Requests: 1250 (1180 success, 70 failed) | Domains: 892 | QPS: 12.3 | Avg latency: 156ms | Cache hit rate: 67.2%
```

### Final Summary

```
Test is over! Reason: timeout
Total runtime: 300.45 seconds
Requests total: 2847
Domains processed: 1923
Average response time: 167ms
Max response time: 4523ms
```

## Performance Tuning

### Rate Limiting

- **`--rps`**: Controls API call frequency (respect API limits)
- **`--concurrency`**: Number of parallel workers (balance with system resources)

### Caching

- **`--cache-ttl`**: Longer TTL = better performance, less fresh data
- Cache hit rate > 60% indicates good performance

### Memory Usage

- PCAP reader processes incrementally (low memory footprint)
- Queue size limited to 1000 items (backpressure control)
- Cache auto-cleanup removes expired entries

## Error Handling

- **Retries**: Automatic retry for timeouts and 5xx errors (not 4xx)
- **Exponential Backoff**: Jitter prevents thundering herd on retries
- **Graceful Degradation**: Continue processing despite individual failures
- **Timeout Handling**: Per-request timeouts with overall run limits

## Development

### Running Tests

```bash
# Install development dependencies
pip install -e ".[dev]"

# Run tests
pytest

# With coverage
pytest --cov=dnsreplay --cov-report=html
```

### Code Quality

```bash
# Format code
black dnsreplay tests

# Sort imports  
isort dnsreplay tests

# Type checking
mypy dnsreplay
```

## Example Scenarios

### High-Speed Analysis

```bash
# Even faster analysis with maximum concurrency
python -m dnsreplay large-capture.pcap \
    --rps 200 \
    --concurrency 50 \
    --cache-ttl 7200 \
    --out-csv results.csv
```

### Debug Mode

```bash
# Detailed logging and samples with slower settings
python -m dnsreplay debug-capture.pcap \
    --rps 25 \
    --concurrency 10 \
    --samples-jsonl debug-samples.jsonl \
    --log-level DEBUG
```

### Long-Running Analysis

```bash
# Extended timeout with default high-performance settings
python -m dnsreplay huge-capture.pcap \
    --timeout 3600 \
    --out-jsonl results.jsonl
```

## Troubleshooting

### Common Issues

1. **Command times out too quickly**: Increase `--timeout` value for larger PCAP files (default: 300 seconds)
2. **High Error Rate**: Check network connectivity and API limits
3. **Low Cache Hit Rate**: Increase `--cache-ttl` or check for domain diversity
4. **Slow Performance**: Monitor with `--log-level INFO` and consider adjusting `--rps` and `--concurrency`
5. **Memory Issues**: Large PCAP files are processed incrementally (should not cause memory issues)

### Logs

Enable debug logging to see detailed operation:

```bash
python -m dnsreplay sample.pcap --log-level DEBUG
```

## Design Decisions

### File-Only Analysis

This production version focuses exclusively on PCAP file analysis and removes the live network interface capture capability from the original version. This design decision was made for:

- **Security**: No elevated privileges required for deployment
- **Reliability**: Predictable input handling without network interface dependencies  
- **Production Focus**: Better suited for forensic analysis and batch processing
- **Portability**: Runs consistently across different environments

For live capture scenarios, use standard tools to create PCAP files first:

```bash
# Linux/Mac
sudo tcpdump -i eth0 port 53 -w capture.pcap

# Windows (with npcap)
dumpcap -i "Ethernet" -f "port 53" -w capture.pcap

# Then analyze
python -m dnsreplay capture.pcap --out-csv results.csv
```

## License

MIT License - see LICENSE file for details.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure all tests pass
5. Submit a pull request

## Support

For issues and questions:
- GitHub Issues: https://github.com/uzibiton/dns-checker/issues
- Documentation: See inline code documentation

### Running the Application

Use the command-line interface for analysis:

```bash
# Basic analysis with new defaults (100 RPS, 20 workers, 5min timeout)
python -m dnsreplay sample.pcap --out-csv results.csv

# Advanced configuration
python -m dnsreplay sample.pcap \
    --rps 100 \
    --concurrency 20 \
    --cache-ttl 3600 \
    --out-csv results.csv \
    --out-jsonl results.jsonl \
    --log-level INFO
```

See the [Configuration Options](#configuration-options) section for detailed parameter descriptions.

## Project Structure

```
dns-checker/
├── dnsreplay/               # Main package
│   ├── __init__.py          # Package initialization
│   ├── __main__.py          # CLI entry point
│   ├── cli.py               # Command line interface
│   ├── pcap_reader.py       # PCAP file parser
│   ├── reputation.py        # API client and reputation logic
│   ├── cache.py             # TTL cache implementation
│   ├── rate_limiter.py      # Rate limiting and concurrency control
│   ├── metrics.py           # Performance monitoring
│   ├── writer.py            # CSV/JSON output writers
│   └── utils.py             # Domain normalization utilities
├── tests/                   # Test suite
│   ├── test_cache.py        # Cache tests
│   └── test_utils.py        # Utility tests
├── files/                   # PCAP files for analysis
│   ├── Sample1.pcapng       # Sample PCAP files
│   ├── Sample2.pcapng
│   └── Sample3.pcap         # Additional test files
├── pyproject.toml           # Python project configuration
├── Dockerfile               # Docker configuration
├── docker-compose.yml       # Docker Compose setup
├── .gitignore              # Git ignore rules
├── venv312/                # Virtual environment (excluded from git)
└── README.md               # Documentation
```

## API Configuration

The tool uses the reputation API endpoint:
- **Base URL**: `https://microcks.gin.dev.securingsam.io/rest/Reputation+API/1.0.0/domain/ranking/`
- **Authentication**: `Authorization: Token I_am_under_stress_when_I_test`
- **Response Format**: `{"address": "domain.com", "reputation": 85, "categories": ["general"]}`

To modify the API configuration, update the `ReputationClient` class in `dnsreplay/reputation.py`.

## Sample PCAP Files

Sample PCAP files are included in the `files/` directory for testing various network protocols and DNS scenarios. The tool supports both `.pcap` and `.pcapng` formats.

## Requirements

- Python 3.12+
- Dependencies automatically installed via `pip install -e .`
- See `pyproject.toml` for complete dependency list

## Docker Notes

The DNS Reputation Analysis Tool can be run in Docker containers for consistent deployment across environments.

### Quick Start with Docker

```bash
# Build the image
docker-compose build

# Quick demo (30 seconds, Sample3.pcap)
docker-compose run --rm dnsreplay-quick

# Default analysis (60 seconds, Sample3.pcap) 
docker-compose run --rm dnsreplay

# Interactive shell for custom commands  
docker-compose run --rm dnsreplay-interactive

# Debug mode with detailed logging (180 seconds, Sample3.pcap)
docker-compose run --rm dnsreplay-debug

# Custom analysis command
docker-compose run --rm dnsreplay python -m dnsreplay files/Sample2.pcapng --out-csv output/custom.csv --timeout 120
```

### Docker Services

1. **dnsreplay-quick**: 30-second demo with Sample3.pcap (fastest)
2. **dnsreplay**: 60-second analysis with Sample3.pcap (default)
3. **dnsreplay-interactive**: Interactive bash shell for custom commands
4. **dnsreplay-debug**: 180-second debug analysis with detailed logging

### Volume Mounts

- `./files:/app/files:ro` - PCAP files (read-only)
- `./dnsreplay:/app/dnsreplay` - Source code (for development)
- `./output:/app/output` - Results output directory

### Example Commands

```bash
# Quick test
docker-compose run --rm dnsreplay python -m dnsreplay files/Sample3.pcap --out-csv output/test.csv --timeout 60

# High performance analysis
docker-compose run --rm dnsreplay python -m dnsreplay files/large.pcap --out-jsonl output/results.jsonl --rps 200 --concurrency 30

# Debug specific issues
docker-compose run --rm dnsreplay python -m dnsreplay files/debug.pcap --samples-jsonl output/debug.jsonl --log-level DEBUG
```

### Building Custom Images

```bash
# Build with custom tag
docker build -t my-dnsreplay:latest .

# Run custom image
docker run --rm -v $(pwd)/files:/app/files:ro -v $(pwd)/output:/app/output my-dnsreplay:latest python -m dnsreplay files/sample.pcap --out-csv output/results.csv
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

## License

This project is open source and available under the MIT License.