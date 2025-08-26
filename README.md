# DNS Checker

A Python-based tool for analyzing DNS traffic from pcap files or live network interfaces and checking domain reputations using an external API.

## Features

- 📦 **PCAP Analysis**: Read and analyze DNS packets from `.pcap` and `.pcapng` files
- 🔴 **Live Capture**: Capture DNS packets from network interfaces in real-time
- 🔍 **Domain Extraction**: Extract domain names from DNS queries
- 🛡️ **Reputation Check**: Query domain reputation using external API
- 🐳 **Docker Support**: Containerized deployment with packet capture capabilities

## Installation

### Local Setup

1. **Create virtual environment:**
```bash
py -3.12 -m venv venv312
source venv312/Scripts/activate
```

2. **Install dependencies:**
```bash
python -m pip install --upgrade pip
pip install -r requirements.txt
```

### Docker Setup

1. **Build and run with Docker Compose:**
```bash
# Build and run
docker-compose up --build

# Run in background
docker-compose up -d

# Stop
docker-compose down
```

2. **Or build and run manually:**
```bash
docker build -t dns-checker .
docker run --rm -it --privileged --network host dns-checker
```

## Usage

### Running the Application

```bash
python src/main.py
```

The application will prompt you to choose between:
- **Option 1**: Analyze packets from a file
- **Option 2**: Capture packets from network interface (requires admin privileges)

### File Analysis Mode

Analyzes DNS packets from pcap files in the `files/` directory. Example files are included for testing.

### Live Capture Mode

Captures DNS packets from your network interface in real-time. Requires administrator/root privileges for packet capture.

**Note**: On Windows, run as Administrator. On Linux/Mac, run with `sudo`.

## Project Structure

```
dns-checker/
├── src/
│   └── main.py              # Main application code
├── files/                   # PCAP files for analysis
│   ├── ETH_IPv4_UDP_dns.pcap
│   ├── DNS_Flood.pcap
│   └── ...
├── venv312/                 # Virtual environment (excluded from git)
├── requirements.txt         # Python dependencies
├── Dockerfile              # Docker configuration
├── docker-compose.yml      # Docker Compose configuration
├── .gitignore             # Git ignore rules
└── README.md              # This file
```

## API Configuration

The application uses a mock reputation API. To use a different API, modify the `get_domain_ranking()` function in `src/main.py`:

```python
def get_domain_ranking(domain):
    base_url = 'your-api-endpoint'
    # Update headers and request format as needed
```

## Sample PCAP Files

Sample PCAP files are included from [Xena Networks](https://xenanetworks.com/?knowledge-base=knowledge-base%2Fvalkyrie%2Fdownloads%2Fpcap-samples) for testing various network protocols and attack scenarios.

## Requirements

- Python 3.12+
- Scapy (for packet analysis)
- Requests (for API calls)
- Administrator/root privileges (for live capture)

## Docker Notes

- The container runs in privileged mode for packet capture
- Uses host networking to access network interfaces
- Volume mounts allow for live code editing during development

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

## License

This project is open source and available under the MIT License.