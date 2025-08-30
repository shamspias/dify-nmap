import logging
import asyncio
import platform
import time
from collections.abc import Generator
from typing import Any, Dict, List, Optional
from datetime import datetime

from dify_plugin import Tool
from dify_plugin.entities.tool import ToolInvokeMessage
from pydantic import BaseModel, Field, validator

logger = logging.getLogger(__name__)


class ComprehensiveScannerParameters(BaseModel):
    """Enhanced parameters with all Nmap features"""

    # Target specification
    targets: str = Field(..., description="Targets to scan")
    exclude_targets: Optional[str] = Field(None, description="Hosts to exclude")
    target_file: Optional[str] = Field(None, description="Read targets from file")

    # Scan profile (NEW)
    scan_profile: str = Field(
        "balanced",
        description="Predefined profiles: quick, balanced, thorough, paranoid, custom"
    )

    # Port specification
    ports: Optional[str] = Field(None, description="Ports to scan")
    exclude_ports: Optional[str] = Field(None, description="Ports to exclude")
    top_ports: Optional[int] = Field(None, description="Scan top N ports")
    port_ratio: Optional[float] = Field(None, description="Port ratio for random")

    # Scan techniques (ENHANCED)
    scan_techniques: List[str] = Field(
        default_factory=lambda: ["tcp_syn"],
        description="Multiple scan types can be combined"
    )

    # Performance (ENHANCED)
    performance_level: str = Field(
        "auto",
        description="auto, low, medium, high, extreme"
    )
    max_parallelism: Optional[int] = Field(None)
    min_parallelism: Optional[int] = Field(None)
    max_rtt_timeout: Optional[str] = Field(None)
    initial_rtt_timeout: Optional[str] = Field(None)
    min_hostgroup: Optional[int] = Field(None)
    max_hostgroup: Optional[int] = Field(None)

    # Service/Version (ENHANCED)
    service_detection: bool = Field(False)
    version_all: bool = Field(False)
    version_light: bool = Field(False)
    rpc_scan: bool = Field(False)

    # OS Detection (ENHANCED - Windows compatible)
    os_detection: bool = Field(False)
    os_scan_limit: bool = Field(True)
    os_scan_guess: bool = Field(True)
    max_os_tries: int = Field(5)

    # NSE Scripts (COMPLETE)
    script_categories: Optional[List[str]] = Field(None)
    specific_scripts: Optional[List[str]] = Field(None)
    script_args: Optional[Dict[str, str]] = Field(None)
    script_timeout: Optional[str] = Field("30s")
    script_updatedb: bool = Field(False)

    # IPv6 Support (NEW)
    ipv6_scan: bool = Field(False)

    # Firewall/IDS Evasion (ENHANCED)
    fragment_packets: bool = Field(False)
    mtu_discovery: bool = Field(False)
    mtu_size: Optional[int] = Field(None)
    decoy_hosts: Optional[List[str]] = Field(None)
    spoof_mac: Optional[str] = Field(None)
    spoof_source: Optional[str] = Field(None)
    source_port: Optional[int] = Field(None)
    data_length: Optional[int] = Field(None)
    randomize_hosts: bool = Field(False)

    # Advanced Options (NEW)
    traceroute: bool = Field(False)
    reason: bool = Field(True)
    packet_trace: bool = Field(False)
    disable_arp_ping: bool = Field(False)

    # Output Options (ENHANCED)
    output_formats: List[str] = Field(
        default_factory=lambda: ["normal", "json"],
        description="normal, xml, json, greppable, all"
    )
    verbose_level: int = Field(1, ge=0, le=5)
    debugging_level: int = Field(0, ge=0, le=9)

    # Safety and Limits
    safe_mode: bool = Field(True)
    aggressive_mode: bool = Field(False)
    host_timeout: Optional[str] = Field("30m")
    max_retries: int = Field(2)

    # Windows Specific (NEW)
    windows_scan: bool = Field(False)

    @validator('scan_techniques')
    def validate_scan_techniques(cls, v):
        valid_techniques = {
            'tcp_syn', 'tcp_connect', 'tcp_ack', 'tcp_window',
            'tcp_maimon', 'tcp_null', 'tcp_fin', 'tcp_xmas',
            'tcp_idle', 'udp', 'sctp_init', 'sctp_cookie',
            'ip_protocol', 'ftp_bounce'
        }
        for technique in v:
            if technique not in valid_techniques:
                raise ValueError(f"Invalid scan technique: {technique}")
        return v


class ComprehensiveScannerTool(Tool):
    """Enhanced comprehensive scanner with all Nmap features"""

    def __init__(self):
        super().__init__()
        self.is_windows = platform.system() == "Windows"
        self.scan_profiles = self._load_scan_profiles()
        self.script_db = self._load_script_database()

    def _load_scan_profiles(self) -> Dict:
        """Load predefined scan profiles"""
        return {
            "quick": {
                "ports": "21,22,23,25,80,443,445,3389,8080",
                "timing": "aggressive",
                "scripts": None
            },
            "balanced": {
                "ports": "--top-ports 1000",
                "timing": "normal",
                "scripts": "default,safe"
            },
            "thorough": {
                "ports": "-p-",
                "timing": "normal",
                "scripts": "default,safe,vuln"
            },
            "paranoid": {
                "ports": "--top-ports 100",
                "timing": "paranoid",
                "scripts": "safe",
                "evasion": True
            }
        }

    def _load_script_database(self) -> Dict:
        """Load NSE script catalog with categories"""
        return {
            "auth": ["http-auth", "ftp-anon", "mysql-empty-password"],
            "broadcast": ["broadcast-ping", "broadcast-dhcp-discover"],
            "brute": ["http-brute", "ssh-brute", "ftp-brute"],
            "default": ["http-title", "ssh-hostkey", "ssl-cert"],
            "discovery": ["dns-srv-enum", "snmp-sysdescr"],
            "dos": ["http-slowloris"],  # Use with caution
            "exploit": ["http-vuln-cve2017-5638"],  # Use with caution
            "external": ["whois-ip", "asn-query"],
            "fuzzer": ["dns-fuzz"],  # Use with caution
            "intrusive": ["snmp-brute", "http-open-proxy"],
            "malware": ["http-malware-host"],
            "safe": ["banner", "http-headers"],
            "version": ["ssh2-enum-algos", "ssl-enum-ciphers"],
            "vuln": ["smb-vuln-ms17-010", "ssl-heartbleed"]
        }

    def _check_privileges(self) -> tuple[bool, str]:
        """Check for required privileges (Windows compatible)"""
        import os

        if self.is_windows:
            try:
                import ctypes
                is_admin = ctypes.windll.shell32.IsUserAnAdmin()
                if is_admin:
                    return True, "Administrator"
                else:
                    return False, "User"
            except:
                return False, "Unknown"
        else:
            # Unix/Linux
            if os.geteuid() == 0:
                return True, "root"
            else:
                return False, f"uid={os.geteuid()}"

    def _build_optimized_arguments(self, params: ComprehensiveScannerParameters) -> str:
        """Build optimized Nmap arguments based on parameters"""
        args = []

        # Apply scan profile first
        if params.scan_profile != "custom":
            profile = self.scan_profiles.get(params.scan_profile, {})
            # Profile settings can be overridden by explicit parameters

        # Scan techniques (can combine multiple)
        technique_flags = {
            'tcp_syn': '-sS',
            'tcp_connect': '-sT',
            'tcp_ack': '-sA',
            'tcp_window': '-sW',
            'tcp_maimon': '-sM',
            'tcp_null': '-sN',
            'tcp_fin': '-sF',
            'tcp_xmas': '-sX',
            'tcp_idle': '-sI',
            'udp': '-sU',
            'sctp_init': '-sY',
            'sctp_cookie': '-sZ',
            'ip_protocol': '-sO',
            'ftp_bounce': '-b'
        }

        for technique in params.scan_techniques:
            if technique in technique_flags:
                args.append(technique_flags[technique])

        # Port specification (optimized)
        if params.top_ports:
            args.append(f'--top-ports {params.top_ports}')
        elif params.ports:
            if params.ports == '-':
                args.append('-p-')
            else:
                args.append(f'-p {params.ports}')

        if params.exclude_ports:
            args.append(f'--exclude-ports {params.exclude_ports}')

        # Performance optimization
        if params.performance_level == "auto":
            # Auto-detect best settings based on target count
            import ipaddress
            try:
                net = ipaddress.ip_network(params.targets, strict=False)
                host_count = net.num_addresses
                if host_count > 1000:
                    args.append('-T4 --min-hostgroup 256 --max-rtt-timeout 100ms')
                elif host_count > 100:
                    args.append('-T4 --min-hostgroup 64')
                else:
                    args.append('-T3')
            except:
                args.append('-T3')
        elif params.performance_level == "extreme":
            args.append('-T5 --max-parallelism 300 --min-hostgroup 256')
        elif params.performance_level == "high":
            args.append('-T4 --max-parallelism 100')
        elif params.performance_level == "medium":
            args.append('-T3')
        elif params.performance_level == "low":
            args.append('-T2')

        # Service detection (optimized)
        if params.service_detection:
            if params.version_light:
                args.append('-sV --version-light')
            elif params.version_all:
                args.append('-sV --version-all')
            else:
                args.append('-sV --version-intensity 7')

        # OS detection (Windows compatible)
        if params.os_detection:
            has_privs, _ = self._check_privileges()
            if has_privs or self.is_windows:
                args.append('-O')
                if params.os_scan_guess:
                    args.append('--osscan-guess')
                if params.os_scan_limit:
                    args.append('--osscan-limit')
                args.append(f'--max-os-tries {params.max_os_tries}')

        # NSE Scripts (optimized selection)
        scripts = []
        if params.script_categories:
            scripts.extend(params.script_categories)
        if params.specific_scripts:
            scripts.extend(params.specific_scripts)

        if scripts:
            # Remove dangerous scripts in safe mode
            if params.safe_mode:
                dangerous = ['dos', 'exploit', 'brute', 'fuzzer']
                scripts = [s for s in scripts if s not in dangerous]

            args.append(f'--script={",".join(scripts)}')

            if params.script_args:
                script_args_str = ','.join([f'{k}={v}' for k, v in params.script_args.items()])
                args.append(f'--script-args={script_args_str}')

            if params.script_timeout:
                args.append(f'--script-timeout {params.script_timeout}')

        # IPv6
        if params.ipv6_scan:
            args.append('-6')

        # Firewall evasion
        if params.fragment_packets:
            args.append('-f')
        if params.mtu_size:
            args.append(f'--mtu {params.mtu_size}')
        if params.decoy_hosts:
            args.append(f'-D {",".join(params.decoy_hosts)}')
        if params.spoof_mac:
            args.append(f'--spoof-mac {params.spoof_mac}')
        if params.source_port:
            args.append(f'--source-port {params.source_port}')
        if params.randomize_hosts:
            args.append('--randomize-hosts')

        # Advanced options
        if params.traceroute:
            args.append('--traceroute')
        if params.reason:
            args.append('--reason')
        if params.packet_trace:
            args.append('--packet-trace')

        # Timing and retries
        if params.max_retries:
            args.append(f'--max-retries {params.max_retries}')
        if params.host_timeout:
            args.append(f'--host-timeout {params.host_timeout}')

        # Exclude targets
        if params.exclude_targets:
            args.append(f'--exclude {params.exclude_targets}')

        # Verbosity
        if params.verbose_level > 0:
            args.append('-' + 'v' * min(params.verbose_level, 4))
        if params.debugging_level > 0:
            args.append('-' + 'd' * min(params.debugging_level, 9))

        return ' '.join(args)

    async def _run_scan_async(self, nm, targets: str, arguments: str) -> dict:
        """Run scan asynchronously for better performance"""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, nm.scan, targets, None, arguments)

    def _format_enhanced_output(self, scan_data: dict, params: ComprehensiveScannerParameters) -> str:
        """Create beautifully formatted output with rich UI"""
        output = []

        # Header with scan info
        output.append("╔" + "═" * 78 + "╗")
        output.append("║" + " " * 25 + "🔍 NMAP SCAN RESULTS" + " " * 26 + "║")
        output.append("╠" + "═" * 78 + "╣")

        # Scan metadata
        output.append(f"║ 📅 Scan Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}" + " " * 43 + "║")
        output.append(f"║ 🎯 Target: {params.targets[:50]}" + " " * (63 - len(params.targets[:50])) + "║")
        output.append(f"║ ⚡ Profile: {params.scan_profile.upper()}" + " " * (64 - len(params.scan_profile)) + "║")
        output.append("╠" + "═" * 78 + "╣")

        # Statistics
        stats = scan_data.get('statistics', {})
        output.append("║ 📊 STATISTICS" + " " * 64 + "║")
        output.append(f"║   • Hosts Up: {stats.get('hosts_up', 0)}/{stats.get('total_hosts', 0)}" + " " * 40 + "║")
        output.append(f"║   • Open Ports: {stats.get('open_ports', 0)}" + " " * 50 + "║")
        output.append(f"║   • Services Found: {stats.get('services_found', 0)}" + " " * 45 + "║")

        if params.os_detection:
            output.append(f"║   • OS Identified: {stats.get('os_identified', 0)}" + " " * 45 + "║")

        output.append("╠" + "═" * 78 + "╣")

        # Host details
        for host in scan_data.get('hosts', []):
            output.append(f"║ 🖥️  HOST: {host['address']}" + " " * (60 - len(host['address'])) + "║")

            if host.get('hostname'):
                output.append(f"║    Hostname: {host['hostname']}" + " " * (60 - len(host['hostname'])) + "║")

            if host.get('os'):
                os_info = host['os']
                output.append(f"║    OS: {os_info.get('name', 'Unknown')[:50]}" + " " * 35 + "║")

            # Open ports with service info
            if host.get('ports'):
                output.append("║    " + "─" * 74 + "║")
                output.append("║    PORT      STATE    SERVICE         VERSION" + " " * 31 + "║")

                for port in sorted(host['ports'], key=lambda x: x['port']):
                    if port['state'] == 'open':
                        port_str = f"{port['port']}/{port['protocol']}"
                        service = port.get('service', 'unknown')[:15]
                        version = f"{port.get('product', '')} {port.get('version', '')}"[:30]

                        line = f"║    {port_str:<10} {port['state']:<8} {service:<15} {version:<30}║"
                        output.append(line)

            # Vulnerabilities if found
            if host.get('vulnerabilities'):
                output.append("║    " + "─" * 74 + "║")
                output.append("║    ⚠️  VULNERABILITIES:" + " " * 53 + "║")
                for vuln in host['vulnerabilities'][:5]:  # Limit to 5
                    output.append(f"║      • {vuln['name'][:65]}" + " " * 10 + "║")

            output.append("║" + " " * 78 + "║")

        # Footer
        output.append("╚" + "═" * 78 + "╝")

        # Add performance metrics
        if 'performance' in scan_data:
            perf = scan_data['performance']
            output.append("\n📈 Performance Metrics:")
            output.append(f"  • Scan Duration: {perf.get('duration', 'N/A')}")
            output.append(f"  • Packets Sent: {perf.get('packets_sent', 'N/A')}")
            output.append(f"  • Packets Received: {perf.get('packets_received', 'N/A')}")

        return "\n".join(output)

    def _invoke(self, tool_parameters: dict[str, Any]) -> Generator[ToolInvokeMessage, None, None]:
        """Execute comprehensive scan with all features"""
        try:
            params = ComprehensiveScannerParameters(**tool_parameters)

            # Import python-nmap
            try:
                import nmap
            except ImportError:
                yield self.create_text_message("❌ Error: python-nmap not installed")
                return

            nm = nmap.PortScanner()

            # Check privileges
            has_privs, priv_level = self._check_privileges()

            # Initial status
            yield self.create_text_message(
                f"🚀 **Starting Enhanced Nmap Scan**\n"
                f"━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
                f"🎯 Targets: {params.targets}\n"
                f"👤 Privileges: {priv_level} {'✅' if has_privs else '⚠️'}\n"
                f"📊 Profile: {params.scan_profile.upper()}\n"
                f"🔧 Performance: {params.performance_level.upper()}\n"
            )

            # Build optimized arguments
            arguments = self._build_optimized_arguments(params)

            # Log command for transparency
            logger.info(f"Executing: nmap {arguments} {params.targets}")

            # Progress tracking
            start_time = time.time()

            # Execute scan (with async if available)
            try:
                if hasattr(asyncio, 'run'):
                    # Use async for better performance
                    scan_result = asyncio.run(
                        self._run_scan_async(nm, params.targets, arguments)
                    )
                else:
                    scan_result = nm.scan(params.targets, arguments=arguments)

            except Exception as e:
                yield self.create_text_message(f"❌ Scan error: {e}")
                return

            # Calculate scan duration
            duration = time.time() - start_time

            # Parse results
            scan_data = self._parse_enhanced_results(nm, scan_result, params, duration)

            # Send formatted output
            formatted_output = self._format_enhanced_output(scan_data, params)
            yield self.create_text_message(formatted_output)

            # Send JSON data
            yield self.create_json_message(scan_data)

            # Export in requested formats
            if 'xml' in params.output_formats:
                xml_output = nm.get_nmap_last_output()
                if xml_output:
                    yield self.create_blob_message(
                        xml_output.encode('utf-8'),
                        meta={'mime_type': 'text/xml', 'filename': 'scan_results.xml'}
                    )

            # Final summary with insights
            yield self.create_text_message(
                f"\n✅ **Scan Complete!**\n"
                f"━━━━━━━━━━━━━━━━━━━━\n"
                f"⏱️ Duration: {duration:.2f} seconds\n"
                f"📊 Hosts Up: {scan_data['statistics']['hosts_up']}\n"
                f"🔓 Open Ports: {scan_data['statistics']['open_ports']}\n"
                f"🛡️ Vulnerabilities: {scan_data['statistics'].get('vulnerabilities', 0)}\n"
            )

        except Exception as e:
            logger.error(f"Comprehensive scan error: {e}", exc_info=True)
            yield self.create_text_message(f"❌ Critical error: {e}")

    def _parse_enhanced_results(self, nm, scan_result: dict, params, duration: float) -> dict:
        """Parse scan results with enhanced data extraction"""
        data = {
            'scan_info': {
                'command': nm.command_line(),
                'version': nm.nmap_version(),
                'scan_type': params.scan_techniques,
                'profile': params.scan_profile
            },
            'statistics': {
                'total_hosts': 0,
                'hosts_up': 0,
                'open_ports': 0,
                'services_found': set(),
                'vulnerabilities': 0,
                'os_identified': 0
            },
            'performance': {
                'duration': f"{duration:.2f}s",
                'packets_sent': 0,
                'packets_received': 0
            },
            'hosts': []
        }

        # Process each host
        for host in nm.all_hosts():
            if nm[host].state() == 'up':
                data['statistics']['hosts_up'] += 1

            host_data = {
                'address': host,
                'hostname': nm[host].hostname(),
                'state': nm[host].state(),
                'ports': [],
                'os': {},
                'vulnerabilities': [],
                'traceroute': []
            }

            # Extract port information
            for proto in nm[host].all_protocols():
                for port in nm[host][proto].keys():
                    port_info = nm[host][proto][port]
                    if port_info['state'] == 'open':
                        data['statistics']['open_ports'] += 1
                        if port_info.get('name'):
                            data['statistics']['services_found'].add(port_info['name'])

                    host_data['ports'].append({
                        'port': port,
                        'protocol': proto,
                        'state': port_info['state'],
                        'service': port_info.get('name', ''),
                        'product': port_info.get('product', ''),
                        'version': port_info.get('version', ''),
                        'scripts': port_info.get('script', {})
                    })

            # Extract OS information
            if 'osmatch' in nm[host] and nm[host]['osmatch']:
                data['statistics']['os_identified'] += 1
                os_match = nm[host]['osmatch'][0]
                host_data['os'] = {
                    'name': os_match.get('name', 'Unknown'),
                    'accuracy': os_match.get('accuracy', 0)
                }

            # Extract vulnerabilities from scripts
            if 'hostscript' in nm[host]:
                for script in nm[host]['hostscript']:
                    if 'vuln' in script['id'].lower():
                        data['statistics']['vulnerabilities'] += 1
                        host_data['vulnerabilities'].append({
                            'name': script['id'],
                            'output': script.get('output', '')[:200]
                        })

            data['hosts'].append(host_data)
            data['statistics']['total_hosts'] += 1

        # Convert set to count
        data['statistics']['services_found'] = len(data['statistics']['services_found'])

        return data
