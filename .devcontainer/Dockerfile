FROM mcr.microsoft.com/devcontainers/rust:latest

# Install libpcap and other dependencies
RUN apt-get update && \
    apt-get install -y \
    libpcap-dev \
    pkg-config \
    build-essential \
    lldb \
    tcpdump \
    net-tools \
    iproute2 \
    iputils-ping && \
    rm -rf /var/lib/apt/lists/*

# Install useful Rust tools
RUN cargo install cargo-watch cargo-edit cargo-audit