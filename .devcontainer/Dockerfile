FROM mcr.microsoft.com/devcontainers/rust:latest

# Install libpcap and other dependencies
RUN apt-get update && \
    apt-get install -y \
    libpcap-dev \
    pkg-config \
    build-essential && \
    rm -rf /var/lib/apt/lists/*