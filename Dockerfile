# Use official Python image with packet capture capabilities
FROM python:3.12-slim

# Install required system packages for packet capture
RUN apt-get update && apt-get install -y \
    libpcap-dev \
    tcpdump \
    net-tools \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .

RUN pip install --upgrade pip && pip install -r requirements.txt

# Copy source code and files
COPY src/ ./src/
COPY files/ ./files/

# Set up capabilities for packet capture (requires privileged mode)
# This allows the container to capture network packets

CMD ["python", "src/main.py"]