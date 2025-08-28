# Nmap Scanner Plugin for Dify

A comprehensive network scanning and security auditing plugin for Dify that provides full access to Nmap's powerful
capabilities through an intuitive interface.

## 🚀 Features

### Core Scanning Capabilities

- **Port Scanning**: TCP, UDP, SYN stealth, ACK, Window, Maimon, NULL, FIN, Xmas, SCTP
- **Service Detection**: Version detection with adjustable intensity
- **OS Fingerprinting**: Operating system detection and identification
- **Network Discovery**: Host enumeration with multiple discovery methods
- **Vulnerability Assessment**: NSE script scanning for security vulnerabilities

### Advanced Features

- **Timing Control**: 6 timing templates from paranoid to insane
- **Evasion Techniques**: Packet fragmentation, decoy hosts, source port spoofing
- **Performance Tuning**: Parallelism control, rate limiting, timeout management
- **Script Engine**: Support for all NSE script categories and custom scripts
- **Multiple Output Formats**: Normal, XML, JSON, greppable

## 📦 Installation

### Prerequisites

1. **Nmap Installation**: The system must have Nmap installed
   ```bash
   # Ubuntu/Debian
   sudo apt-get install nmap
   
   # CentOS/RHEL/Fedora
   sudo yum install nmap
   
   # macOS
   brew install nmap
   
   # Windows
   Download from https://nmap.org/download.html
   ```

2. **Python Dependencies**: Automatically installed by Dify
    - python-nmap
    - pydantic
    - ipaddress

### Plugin Installation

1. Navigate to Dify Plugin Management
2. Click "Add Plugin"
3. Upload the plugin package or search for "Nmap Scanner"
4. Configure credentials if needed (sudo password for privileged scans)
5. Enable the plugin

## 🛠️ Configuration

### Provider Credentials (Optional)

- **Sudo Password**: Required only for SYN scans and OS detection
- **Max Parallelism**: Default concurrent operations limit

## 📚 Tools Included

### 1. Comprehensive Port Scanner

Full-featured port scanning with all Nmap options:

- All scan types (TCP, UDP, SYN, etc.)
- Service and version detection
- OS fingerprinting
- NSE script execution
- Custom timing and performance settings

### 2. Network Discovery

Efficient host enumeration:

- ARP scanning for local networks
- ICMP/TCP/UDP ping sweeps
- MAC address and vendor detection
- Basic OS identification

### 3. Vulnerability Scanner

Security-focused scanning:

- Vulnerability detection scripts
- Common CVE checks
- Service-specific vulnerabilities
- Security misconfiguration detection

### 4. Service Detector

Detailed service identification:

- Application version detection
- Protocol identification
- Banner grabbing
- Service-specific information gathering

### 5. OS Fingerprinting

Operating system detection:

- TCP/IP stack fingerprinting
- OS version identification
- Network distance estimation
- Device type classification

## 📝 Usage Examples

### Basic Port Scan

```yaml
Tool: port_scanner
Parameters:
  targets: "192.168.1.1"
  ports: "22,80,443"
  scan_type: "tcp_connect"
```

### Comprehensive Network Scan

```yaml
Tool: port_scanner
Parameters:
  targets: "192.168.1.0/24"
  ports: "1-1000"
  scan_type: "syn_stealth"
  service_detection: true
  os_detection: true
  default_scripts: true
  timing_template: "aggressive"
```

### Vulnerability Assessment

```yaml
Tool: port_scanner
Parameters:
  targets: "example.com"
  ports: "-"  # All ports
  script_categories: "vuln,exploit"
  safe_mode: true
  timing_template: "normal"
```

### Stealth Scan with Evasion

```yaml
Tool: port_scanner
Parameters:
  targets: "target.com"
  ports: "80,443"
  scan_type: "syn_stealth"
  timing_template: "sneaky"
  fragment_packets: true
  decoy_hosts: "192.168.1.5,192.168.1.8,ME"
  source_port: 53
```

## 🔧 Best Practices

### Performance Optimization

1. **Timing Templates**:
    - Use "polite" or "normal" for production networks
    - "Aggressive" or "insane" only for authorized testing

2. **Port Ranges**:
    - Start with common ports (top 1000)
    - Use full port scans (-) only when necessary

3. **Parallelism**:
    - Default 100 is suitable for most networks
    - Reduce for sensitive systems
    - Increase for lab environments

### Security Considerations

1. **Authorization**: Always ensure you have permission to scan target systems
2. **Rate Limiting**: Use appropriate timing to avoid overwhelming targets
3. **Safe Mode**: Keep enabled to avoid potentially dangerous scripts
4. **Logging**: All scans are logged for audit purposes

### Scan Type Selection

- **TCP Connect**: Default, works without privileges
- **SYN Stealth**: Faster, requires root, less detectable
- **UDP**: For UDP services, slower than TCP
- **ACK/Window**: For firewall rule mapping
- **NULL/FIN/Xmas**: For firewall evasion

## 🔒 Security & Privacy

- **No Data Collection**: All scanning is performed locally
- **No External Communication**: Except to specified targets
- **Credential Protection**: Sudo passwords are encrypted
- **Audit Logging**: All scan activities are logged
- **Rate Limiting**: Built-in protection against abuse

## ⚠️ Legal Notice

This plugin is a powerful network security tool. Users must:

- Only scan networks and systems they own or have explicit permission to test
- Comply with all applicable laws and regulations
- Understand that unauthorized scanning may be illegal
- Take responsibility for all scanning activities

## 🐛 Troubleshooting

### Common Issues

1. **"Nmap not installed"**
    - Solution: Install Nmap on the system

2. **"Permission denied for SYN scan"**
    - Solution: Provide sudo password in credentials
    - Alternative: Use TCP connect scan instead

3. **"Host seems down"**
    - Try different ping types
    - Use -Pn (no_ping) option

4. **"Scan too slow"**
    - Increase timing template
    - Reduce version intensity
    - Limit port range

### Performance Tips

- Use specific port lists instead of full scans
- Disable DNS resolution for faster scans
- Use appropriate timing templates
- Limit script usage to necessary categories

## 📊 Output Formats

### Text Output

Human-readable format with structured sections:

- Scan statistics
- Host information
- Port states and services
- Script results

### JSON Output

Structured data for programmatic processing:

```json
{
  "scan_info": {
    ...
  },
  "statistics": {
    ...
  },
  "hosts": [
    ...
  ]
}
```

### XML Output

Complete Nmap XML output for further analysis

## 🤝 Support

- GitHub: [your-repo/dify-nmap-scanner]
- Email: support@example.com
- Documentation: [link-to-docs]

## 📄 License

MIT License - See LICENSE file for details

## 🙏 Acknowledgments

- Built on the powerful Nmap network scanner
- Integrated with Dify's plugin ecosystem
- Uses python-nmap for Python integration

## ⚡ Quick Reference

### Timing Templates

- **T0 (Paranoid)**: 5 min between probes
- **T1 (Sneaky)**: 15 sec between probes
- **T2 (Polite)**: 0.4 sec between probes
- **T3 (Normal)**: Default timing
- **T4 (Aggressive)**: Faster, reliable networks
- **T5 (Insane)**: Maximum speed

### Common Ports

- **21**: FTP
- **22**: SSH
- **23**: Telnet
- **25**: SMTP
- **53**: DNS
- **80**: HTTP
- **110**: POP3
- **143**: IMAP
- **443**: HTTPS
- **445**: SMB
- **3306**: MySQL
- **3389**: RDP
- **5432**: PostgreSQL
- **8080**: HTTP Alternate

### NSE Script Categories

- **auth**: Authentication
- **broadcast**: Broadcast discovery
- **brute**: Password brute-forcing
- **default**: Default scripts
- **discovery**: Service discovery
- **dos**: Denial of service
- **exploit**: Active exploitation
- **fuzzer**: Fuzzing
- **intrusive**: Intrusive probes
- **malware**: Malware detection
- **safe**: Safe scripts
- **version**: Version detection
- **vuln**: Vulnerability detection

---

**Note**: This plugin provides powerful network scanning capabilities. Always use responsibly and ensure you have proper
authorization before scanning any network or system.