import subprocess
import logging
import sys
import os
import re
from fastmcp import FastMCP

# Configure logging to stderr
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    stream=sys.stderr
)
logger = logging.getLogger(__name__)

# Initialize FastMCP server
mcp = FastMCP("Kali Security Tools")

# Security and validation helpers
def sanitize_input(input_str):
    """Remove dangerous characters from input"""
    if not input_str:
        return ""
    # Remove shell metacharacters
    dangerous_chars = [';', '&', '|', '`', '$', '(', ')', '<', '>', '\n', '\r']
    result = input_str
    for char in dangerous_chars:
        result = result.replace(char, '')
    return result.strip()

def validate_ip(ip):
    """Validate IP address format"""
    pattern = r'^(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?$'
    return bool(re.match(pattern, ip))

def validate_domain(domain):
    """Validate domain format"""
    pattern = r'^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    return bool(re.match(pattern, domain))

def run_command(cmd, timeout=300):
    """Execute command safely with timeout"""
    try:
        logger.info(f"Executing: {' '.join(cmd)}")
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False
        )
        return result.stdout + result.stderr
    except subprocess.TimeoutExpired:
        return f"Command timed out after {timeout} seconds"
    except Exception as e:
        logger.error(f"Command failed: {e}")
        return f"Error executing command: {str(e)}"

# NETWORK SCANNING TOOLS

@mcp.tool()
def nmap_scan(target: str, scan_type: str = "basic", ports: str = ""):
    """Scan network hosts and ports using nmap. Scan types: basic, fast, intense, vuln, service. WARNING: Only scan authorized targets."""
    target = sanitize_input(target)
    if not target or not (validate_ip(target) or validate_domain(target)):
        return "Error: Invalid target IP or domain"
    
    scan_options = {
        "basic": ["-sV"],
        "fast": ["-F"],
        "intense": ["-T4", "-A", "-v"],
        "vuln": ["--script=vuln"],
        "service": ["-sV", "-sC"]
    }
    
    options = scan_options.get(scan_type, ["-sV"])
    cmd = ["sudo", "nmap"] + options
    
    if ports:
        ports = sanitize_input(ports)
        cmd.extend(["-p", ports])
    
    cmd.append(target)
    return run_command(cmd, timeout=600)

@mcp.tool()
def masscan_scan(target: str, ports: str = "80,443", rate: str = "1000"):
    """Fast TCP port scanner using masscan. Scans large networks quickly. WARNING: Only scan authorized targets."""
    target = sanitize_input(target)
    if not target or not (validate_ip(target) or validate_domain(target)):
        return "Error: Invalid target"
    
    ports = sanitize_input(ports)
    rate = sanitize_input(rate)
    
    cmd = ["sudo", "masscan", target, "-p", ports, "--rate", rate]
    return run_command(cmd, timeout=600)

@mcp.tool()
def netdiscover_scan(interface: str = "eth0", range_cidr: str = ""):
    """Discover live hosts on network using ARP. WARNING: Only scan authorized networks."""
    interface = sanitize_input(interface)
    cmd = ["sudo", "netdiscover", "-i", interface, "-P"]
    
    if range_cidr:
        range_cidr = sanitize_input(range_cidr)
        if validate_ip(range_cidr):
            cmd.extend(["-r", range_cidr])
    
    return run_command(cmd, timeout=120)

# WEB APPLICATION TESTING

@mcp.tool()
def nikto_scan(target: str, port: str = "80", ssl: str = "no"):
    """Scan web server for vulnerabilities using Nikto. WARNING: Only scan authorized web servers."""
    target = sanitize_input(target)
    if not target:
        return "Error: Target required"
    
    port = sanitize_input(port)
    cmd = ["nikto", "-h", target, "-p", port]
    
    if ssl.lower() == "yes":
        cmd.append("-ssl")
    
    return run_command(cmd, timeout=600)

@mcp.tool()
def sqlmap_scan(target_url: str, data: str = "", cookie: str = ""):
    """Test for SQL injection vulnerabilities using sqlmap. WARNING: Only test authorized applications."""
    target_url = sanitize_input(target_url)
    if not target_url or not target_url.startswith("http"):
        return "Error: Valid HTTP/HTTPS URL required"
    
    cmd = ["sqlmap", "-u", target_url, "--batch", "--random-agent"]
    
    if data:
        data = sanitize_input(data)
        cmd.extend(["--data", data])
    
    if cookie:
        cookie = sanitize_input(cookie)
        cmd.extend(["--cookie", cookie])
    
    return run_command(cmd, timeout=600)

@mcp.tool()
def wpscan_scan(target_url: str, enumerate: str = ""):
    """Scan WordPress sites for vulnerabilities. Enumerate options: u (users), p (plugins), t (themes), vp (vulnerable plugins). WARNING: Only scan authorized sites."""
    target_url = sanitize_input(target_url)
    if not target_url or not target_url.startswith("http"):
        return "Error: Valid HTTP/HTTPS URL required"
    
    cmd = ["wpscan", "--url", target_url, "--no-banner"]
    
    if enumerate:
        enumerate = sanitize_input(enumerate)
        cmd.extend(["--enumerate", enumerate])
    
    return run_command(cmd, timeout=600)

@mcp.tool()
def dirb_scan(target_url: str, wordlist: str = "/usr/share/dirb/wordlists/common.txt"):
    """Brute force directories and files on web servers using DIRB. WARNING: Only scan authorized web servers."""
    target_url = sanitize_input(target_url)
    if not target_url or not target_url.startswith("http"):
        return "Error: Valid HTTP/HTTPS URL required"
    
    cmd = ["dirb", target_url, wordlist, "-S", "-w"]
    return run_command(cmd, timeout=600)

@mcp.tool()
def gobuster_scan(target_url: str, mode: str = "dir", wordlist: str = "/usr/share/wordlists/dirb/common.txt"):
    """Fast directory and DNS brute forcing using gobuster. Modes: dir, dns, vhost. WARNING: Only scan authorized targets."""
    target_url = sanitize_input(target_url)
    if not target_url:
        return "Error: Target required"
    
    mode = sanitize_input(mode)
    cmd = ["gobuster", mode, "-u", target_url, "-w", wordlist, "-q"]
    return run_command(cmd, timeout=600)

@mcp.tool()
def whatweb_scan(target_url: str, aggression: str = "1"):
    """Identify web technologies, CMS, frameworks using WhatWeb. Aggression levels: 1-4. WARNING: Only scan authorized sites."""
    target_url = sanitize_input(target_url)
    if not target_url:
        return "Error: Target URL required"
    
    aggression = sanitize_input(aggression)
    cmd = ["whatweb", target_url, "-a", aggression]
    return run_command(cmd)

@mcp.tool()
def wafw00f_scan(target_url: str):
    """Detect Web Application Firewalls (WAF) using wafw00f. WARNING: Only scan authorized sites."""
    target_url = sanitize_input(target_url)
    if not target_url or not target_url.startswith("http"):
        return "Error: Valid HTTP/HTTPS URL required"
    
    cmd = ["wafw00f", target_url]
    return run_command(cmd)

@mcp.tool()
def commix_scan(target_url: str, data: str = ""):
    """Test for command injection vulnerabilities using Commix. WARNING: Only test authorized applications."""
    target_url = sanitize_input(target_url)
    if not target_url or not target_url.startswith("http"):
        return "Error: Valid HTTP/HTTPS URL required"
    
    cmd = ["commix", "--url", target_url, "--batch"]
    
    if data:
        data = sanitize_input(data)
        cmd.extend(["--data", data])
    
    return run_command(cmd, timeout=600)

# SSL/TLS TESTING

@mcp.tool()
def sslscan_test(target: str, port: str = "443"):
    """Test SSL/TLS configuration using sslscan. WARNING: Only test authorized servers."""
    target = sanitize_input(target)
    if not target:
        return "Error: Target required"
    
    port = sanitize_input(port)
    cmd = ["sslscan", f"{target}:{port}"]
    return run_command(cmd)

@mcp.tool()
def testssl_test(target: str):
    """Comprehensive SSL/TLS testing using testssl.sh. WARNING: Only test authorized servers."""
    target = sanitize_input(target)
    if not target:
        return "Error: Target required"
    
    cmd = ["testssl.sh", "--fast", target]
    return run_command(cmd, timeout=300)

# DNS TOOLS

@mcp.tool()
def dnsenum_scan(domain: str):
    """Enumerate DNS information using dnsenum. WARNING: Only scan authorized domains."""
    domain = sanitize_input(domain)
    if not domain or not validate_domain(domain):
        return "Error: Valid domain required"
    
    cmd = ["dnsenum", domain]
    return run_command(cmd)

@mcp.tool()
def dnsrecon_scan(domain: str, scan_type: str = "std"):
    """DNS reconnaissance using dnsrecon. Types: std, axfr, bing, zonewalk. WARNING: Only scan authorized domains."""
    domain = sanitize_input(domain)
    if not domain or not validate_domain(domain):
        return "Error: Valid domain required"
    
    scan_type = sanitize_input(scan_type)
    cmd = ["dnsrecon", "-d", domain, "-t", scan_type]
    return run_command(cmd)

@mcp.tool()
def fierce_scan(domain: str):
    """DNS reconnaissance and subdomain enumeration using Fierce. WARNING: Only scan authorized domains."""
    domain = sanitize_input(domain)
    if not domain or not validate_domain(domain):
        return "Error: Valid domain required"
    
    cmd = ["fierce", "--domain", domain]
    return run_command(cmd)

# PASSWORD CRACKING

@mcp.tool()
def john_crack(hash_file: str, wordlist: str = "", format_type: str = ""):
    """Crack password hashes using John the Ripper. Provide hash file path. WARNING: Only crack authorized hashes."""
    hash_file = sanitize_input(hash_file)
    if not hash_file:
        return "Error: Hash file path required"
    
    cmd = ["john", hash_file]
    
    if wordlist:
        wordlist = sanitize_input(wordlist)
        cmd.extend([f"--wordlist={wordlist}"])
    
    if format_type:
        format_type = sanitize_input(format_type)
        cmd.extend([f"--format={format_type}"])
    
    return run_command(cmd, timeout=600)

@mcp.tool()
def hydra_crack(target: str, service: str, username: str = "", password_list: str = "/usr/share/wordlists/rockyou.txt"):
    """Brute force login credentials using Hydra. Services: ssh, ftp, http-get, http-post-form, etc. WARNING: Only test authorized systems."""
    target = sanitize_input(target)
    service = sanitize_input(service)
    
    if not target or not service:
        return "Error: Target and service required"
    
    cmd = ["hydra", "-V"]
    
    if username:
        username = sanitize_input(username)
        cmd.extend(["-l", username])
    
    cmd.extend(["-P", password_list, target, service])
    return run_command(cmd, timeout=600)

@mcp.tool()
def crunch_generate(min_len: str, max_len: str, charset: str = ""):
    """Generate custom wordlists using Crunch. Output limited to first 100 lines for safety."""
    min_len = sanitize_input(min_len)
    max_len = sanitize_input(max_len)
    
    if not min_len or not max_len:
        return "Error: Min and max length required"
    
    cmd = ["crunch", min_len, max_len]
    
    if charset:
        charset = sanitize_input(charset)
        cmd.append(charset)
    
    cmd.extend(["-c", "100"])
    return run_command(cmd, timeout=60)

# EXPLOITATION

@mcp.tool()
def searchsploit_search(keyword: str):
    """Search exploit database using searchsploit. Searches for known exploits and vulnerabilities."""
    keyword = sanitize_input(keyword)
    if not keyword:
        return "Error: Search keyword required"
    
    cmd = ["searchsploit", keyword]
    return run_command(cmd)

@mcp.tool()
def msfconsole_search(keyword: str):
    """Search Metasploit modules for exploits, payloads, auxiliaries. WARNING: Only use on authorized systems."""
    keyword = sanitize_input(keyword)
    if not keyword:
        return "Error: Search keyword required"
    
    cmd = ["msfconsole", "-q", "-x", f"search {keyword}; exit"]
    return run_command(cmd, timeout=60)

# INFORMATION GATHERING

@mcp.tool()
def whois_lookup(domain: str):
    """Perform WHOIS lookup for domain registration information."""
    domain = sanitize_input(domain)
    if not domain:
        return "Error: Domain required"
    
    cmd = ["whois", domain]
    return run_command(cmd)

@mcp.tool()
def theharvester_search(domain: str, source: str = "google", limit: str = "100"):
    """Gather emails, subdomains, IPs using theHarvester. Sources: google, bing, linkedin, etc. WARNING: Respect privacy and authorization."""
    domain = sanitize_input(domain)
    if not domain:
        return "Error: Domain required"
    
    source = sanitize_input(source)
    limit = sanitize_input(limit)
    
    cmd = ["theHarvester", "-d", domain, "-b", source, "-l", limit]
    return run_command(cmd, timeout=300)

# SMTP ENUMERATION

@mcp.tool()
def smtp_user_enum(target: str, mode: str = "VRFY", user_list: str = ""):
    """Enumerate SMTP users. Modes: VRFY, EXPN, RCPT. WARNING: Only test authorized mail servers."""
    target = sanitize_input(target)
    if not target:
        return "Error: Target required"
    
    mode = sanitize_input(mode)
    cmd = ["smtp-user-enum", "-M", mode, "-t", target]
    
    if user_list:
        user_list = sanitize_input(user_list)
        cmd.extend(["-U", user_list])
    
    return run_command(cmd)

# WIRELESS TESTING

@mcp.tool()
def aircrack_info(interface: str = "wlan0"):
    """Display wireless interface information using airmon-ng. WARNING: Only test authorized wireless networks."""
    interface = sanitize_input(interface)
    cmd = ["sudo", "airmon-ng", interface]
    return run_command(cmd)

# SYSTEM AUDITING

@mcp.tool()
def lynis_audit(scan_type: str = "system"):
    """Perform security audit using Lynis. Scan types: system, full. Audits local system security."""
    scan_type = sanitize_input(scan_type)
    cmd = ["sudo", "lynis", "audit", scan_type, "--quick"]
    return run_command(cmd, timeout=300)

# FORENSICS AND ANALYSIS

@mcp.tool()
def exiftool_analyze(file_path: str):
    """Extract metadata from files using ExifTool. Provide file path relative to /output directory."""
    file_path = sanitize_input(file_path)
    if not file_path:
        return "Error: File path required"
    
    full_path = f"/output/{file_path}"
    cmd = ["exiftool", full_path]
    return run_command(cmd)

@mcp.tool()
def binwalk_analyze(file_path: str):
    """Analyze and extract embedded files using Binwalk. Provide file path relative to /output directory."""
    file_path = sanitize_input(file_path)
    if not file_path:
        return "Error: File path required"
    
    full_path = f"/output/{file_path}"
    cmd = ["binwalk", full_path]
    return run_command(cmd)

# UTILITY TOOLS

@mcp.tool()
def netcat_connect(target: str, port: str, message: str = ""):
    """Connect to TCP/UDP ports using netcat. WARNING: Only connect to authorized systems."""
    target = sanitize_input(target)
    port = sanitize_input(port)
    
    if not target or not port:
        return "Error: Target and port required"
    
    if message:
        cmd = ["bash", "-c", f"echo '{sanitize_input(message)}' | nc {target} {port} -w 3"]
    else:
        cmd = ["nc", "-zv", target, port]
    
    return run_command(cmd, timeout=30)

if __name__ == "__main__":
    logger.info("Starting Kali Security Tools MCP Server")
    logger.info("WARNING: Only use these tools on authorized targets")
    logger.info("Unauthorized scanning/testing may be illegal")
    mcp.run()