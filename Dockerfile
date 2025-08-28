# Use official Python image with packet capture capabilities
FROM python:3.12-slim

# Install required system packages for packet capture
RUN apt-get update && apt-get install -y \
    libpcap-dev \
    tcpdump \
    net-tools \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy package configuration first for better Docker layer caching
COPY pyproject.toml .

# Install the package in development mode
RUN pip install --upgrade pip && pip install -e .

# Copy source code and files
COPY dnsreplay/ ./dnsreplay/
COPY files/ ./files/

# Create output directory for results
RUN mkdir -p /app/output

# Set up environment for the dnsreplay package
ENV PYTHONPATH=/app
ENV PYTHONUNBUFFERED=1

# Default command runs the CLI tool
CMD ["python", "-m", "dnsreplay", "--help"]