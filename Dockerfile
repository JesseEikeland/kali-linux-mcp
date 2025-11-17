FROM kalilinux/kali-rolling:latest

# Set environment variables
ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1

# Update and install core tools
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    python3-venv \
    sudo \
    # Network Scanning
    nmap \
    masscan \
    netdiscover \
    # Web Application Testing
    nikto \
    sqlmap \
    wpscan \
    dirb \
    dirbuster \
    gobuster \
    whatweb \
    wafw00f \
    # Exploitation Tools
    metasploit-framework \
    exploitdb \
    searchsploit \
    # Password Cracking
    john \
    hashcat \
    hydra \
    medusa \
    crunch \
    # Wireless Testing
    aircrack-ng \
    reaver \
    # SSL/TLS Testing
    sslscan \
    sslyze \
    testssl.sh \
    # DNS Tools
    dnsenum \
    dnsrecon \
    fierce \
    # SMTP Testing
    smtp-user-enum \
    # Web Proxies & Interceptors
    # Note: Burp Suite requires GUI, not included
    # Vulnerability Scanning
    lynis \
    # Information Gathering
    whois \
    theharvester \
    # Exploitation Frameworks
    commix \
    # Reverse Engineering (CLI only)
    binwalk \
    foremost \
    # Forensics
    exiftool \
    # Other utilities
    git \
    curl \
    wget \
    netcat-traditional \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user with specific UID/GID
RUN groupadd -g 1000 mcpuser && \
    useradd -m -u 1000 -g mcpuser -s /bin/bash mcpuser && \
    echo "mcpuser ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers

# Create working directory
RUN mkdir -p /app /output && \
    chown -R mcpuser:mcpuser /app /output

# Switch to non-root user
USER mcpuser
WORKDIR /app

# Copy requirements first for better caching
COPY --chown=mcpuser:mcpuser requirements.txt .

# Create virtual environment and install Python dependencies
RUN python3 -m venv /app/venv && \
    /app/venv/bin/pip install --no-cache-dir --upgrade pip && \
    /app/venv/bin/pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY --chown=mcpuser:mcpuser server.py .

# Update searchsploit database
RUN sudo searchsploit -u || true

# Set PATH to include venv
ENV PATH="/app/venv/bin:$PATH"

# Expose MCP server (if needed for network mode)
EXPOSE 8000

# Run the MCP server
CMD ["python3", "server.py"]