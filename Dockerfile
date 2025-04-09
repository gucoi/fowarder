FROM mcr.microsoft.com/devcontainers/rust:latest

# Install libpcap and other dependencies
RUN apt-get update && \
    apt-get install -y \
    libpcap-dev \
    pkg-config && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /usr/src/dragent
COPY . .
RUN cargo build --release

FROM debian:bullseye-slim
COPY --from=builder /usr/src/dragent/target/release/dragent_rs /usr/local/bin/
EXPOSE 4789/udp
CMD ["dragent_rs"]

LABEL Name=dragentrs Version=0.0.1