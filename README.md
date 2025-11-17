# Kali Linux Security Tools MCP Server

A comprehensive MCP server providing access to 30+ Kali Linux penetration testing tools through Claude Desktop.

## ⚠️ LEGAL WARNING

**IMPORTANT:** These tools are for EDUCATIONAL PURPOSES ONLY. Only use on:
- Systems you own
- Systems you have explicit written permission to test
- Controlled lab environments

Unauthorized access, scanning, or testing of computer systems may be ILLEGAL in your jurisdiction and could result in criminal prosecution.

## 🛠️ Available Tools (30+ Tools)

### Network Scanning
- `nmap_scan` - Port scanning and service detection
- `masscan_scan` - High-speed port scanning
- `netdiscover_scan` - Network host discovery

### Web Application Testing
- `nikto_scan` - Web server vulnerability scanning
- `sqlmap_scan` - SQL injection testing
- `wpscan_scan` - WordPress security testing
- `dirb_scan` - Directory brute forcing
- `gobuster_scan` - Fast directory/DNS brute forcing
- `whatweb_scan` - Web technology identification
- `wafw00f_scan` - WAF detection
- `commix_scan` - Command injection testing

### SSL/TLS Testing
- `sslscan_test` - SSL/TLS configuration testing
- `testssl_test` - Comprehensive SSL/TLS testing

### DNS Tools
- `dnsenum_scan` - DNS enumeration
- `dnsrecon_scan` - DNS reconnaissance
- `fierce_scan` - DNS and subdomain enumeration

### Password Cracking
- `john_crack` - Password hash cracking
- `hydra_crack` - Login brute forcing
- `crunch_generate` - Custom wordlist generation

### Exploitation
- `searchsploit_search` - Exploit database search
- `msfconsole_search` - Metasploit module search

### Information Gathering
- `whois_lookup` - Domain WHOIS information
- `theharvester_search` - Email and subdomain harvesting
- `smtp_user_enum` - SMTP user enumeration

### Wireless Testing
- `aircrack_info` - Wireless interface information

### System Auditing
- `lynis_audit` - System security auditing

### Forensics
- `exiftool_analyze` - File metadata extraction
- `binwalk_analyze` - Embedded file analysis

### Utilities
- `netcat_connect` - TCP/UDP connection testing

## 📋 Prerequisites

- Docker Desktop installed
- Claude Desktop installed
- At least 8GB RAM
- 20GB free disk space

## 🚀 Quick Start

### 1. Clone the Repository

```bash
cd ~/MCP/kali
git clone https://github.com/JesseEikeland/kali-linux-mcp.git .
```

### 2. Create Output Directory

```bash
mkdir output
```

### 3. Build the Docker Container

```bash
docker-compose build
```

This will take 10-15 minutes as it downloads Kali Linux and installs all security tools.

### 4. Test the Server

```bash
docker-compose up
```

You should see log messages indicating the server has started. Press `Ctrl+C` to stop.

### 5. Configure Claude Desktop

Edit your Claude Desktop configuration file:

**macOS:** `~/Library/Application Support/Claude/claude_desktop_config.json`

**Windows:** `%APPDATA%\Claude\claude_desktop_config.json`

Add this configuration:

```json
{
  "mcpServers": {
    "kali-security-tools": {
      "command": "docker",
      "args": [
        "compose",
        "-f",
        "/Users/jesse/MCP/kali/docker-compose.yml",
        "run",
        "--rm",
        "kali-mcp-server"
      ]
    }
  }
}
```

**Note:** The path `/Users/jesse/MCP/kali/docker-compose.yml` is already set for your system. If you cloned to a different location, update this path.

### 6. Restart Claude Desktop

Completely quit and restart Claude Desktop.

### 7. Verify Installation

In Claude Desktop, start a new conversation and look for the 🔌 icon indicating MCP tools are available. You should see 30+ security tools available.

### 8. Test a Tool

Try this prompt in Claude:

```
Use searchsploit_search to search for "wordpress" exploits
```

## 📁 File Storage

Place files to analyze in the `./output` directory. Tools like `exiftool_analyze` and `binwalk_analyze` will access files from this location.

## 🔒 Security Features

- Non-root execution
- Input sanitization
- Command timeout protection
- Dangerous character filtering
- IP and domain validation
- Logging for audit trails

## 📝 Usage Examples

### Port Scanning
```
Use nmap_scan to scan 192.168.1.1 with scan_type "basic"
```

### Web Vulnerability Scanning
```
Use nikto_scan to test http://testsite.local on port 80
```

### SQL Injection Testing
```
Use sqlmap_scan to test http://testsite.local/page.php?id=1
```

### Exploit Search
```
Use searchsploit_search to find exploits for "apache 2.4"
```

### WordPress Scanning
```
Use wpscan_scan to scan https://example.com with enumerate "vp"
```

## ⚡ Performance Notes

- Some scans may take several minutes
- Timeout limits prevent hanging
- Network mode: host (for raw packet access)
- Requires NET_ADMIN and NET_RAW capabilities

## 🐛 Troubleshooting

### Permission Errors
Ensure Docker has proper capabilities set in docker-compose.yml

### Timeout Issues
Increase timeout values in server.py for long-running scans

### Network Issues
Verify network_mode: host is set for tools requiring raw sockets

### Container Won't Start
```bash
# Check logs
docker-compose logs

# Rebuild container
docker-compose build --no-cache
```

## 🔄 Updating Tools

To update the security tools database:

```bash
docker-compose run --rm kali-mcp-server sudo searchsploit -u
```

## 📚 Additional Resources

- [Kali Linux Documentation](https://www.kali.org/docs/)
- [Nmap Reference Guide](https://nmap.org/book/man.html)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [Metasploit Unleashed](https://www.offsec.com/metasploit-unleashed/)

## ⚖️ Ethical Use

Always follow responsible disclosure practices. If you discover vulnerabilities:
1. Document findings carefully
2. Notify the system owner privately
3. Allow reasonable time for fixes
4. Do not disclose publicly without permission

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 📄 License

For educational and authorized testing purposes only.

## ⚠️ Disclaimer

The authors and contributors are not responsible for misuse of these tools. Users are solely responsible for ensuring they have proper authorization before testing any systems.

## 🌟 Star This Repo

If you find this useful, please star the repository!