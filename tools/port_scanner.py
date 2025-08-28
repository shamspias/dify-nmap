import logging
from collections.abc import Generator
from typing import Any, Optional, List, Dict
import json
import re
import ipaddress
import socket
from datetime import datetime

from dify_plugin import Tool
from dify_plugin.entities.tool import ToolInvokeMessage
from pydantic import BaseModel, Field, validator

logger = logging.getLogger(__name__)


class ToolParameters(BaseModel):
    """
    Comprehensive Nmap scanning parameters following best practices
    """
    # Target specification
    targets: str = Field(
        ...,
        description="Target hosts (IP, hostname, CIDR, ranges like 192.168.1.1-10)"
    )

    # Port specification
    ports: Optional[str] = Field(
        None,
        description="Port specification (e.g., '22,80,443', '1-1000', '-' for all)"
    )

    # Scan techniques
    scan_type: str = Field(
        "tcp_connect",
        description="Scan type: tcp_connect, syn_stealth, udp, tcp_ack, tcp_window, tcp_maimon, tcp_null, tcp_fin, tcp_xmas, sctp_init, ip_protocol"
    )

    # Timing and performance
    timing_template: str = Field(
        "normal",
        description="Timing template: paranoid, sneaky, polite, normal, aggressive, insane"
    )

    max_parallelism: Optional[int] = Field(
        100,
        ge=1,
        le=1000,
        description="Maximum parallel operations"
    )

    min_rate: Optional[int] = Field(
        None,
        ge=1,
        description="Minimum packet rate per second"
    )

    max_rate: Optional[int] = Field(
        None,
        ge=1,
        description="Maximum packet rate per second"
    )

    # Service/Version detection
    service_detection: bool = Field(
        False,
        description="Enable service version detection"
    )

    version_intensity: int = Field(
        7,
        ge=0,
        le=9,
        description="Version detection intensity (0-9)"
    )

    # OS detection
    os_detection: bool = Field(
        False,
        description="Enable OS detection (requires root)"
    )

    # Script scanning
    default_scripts: bool = Field(
        False,
        description="Run default NSE scripts"
    )

    script_categories: Optional[str] = Field(
        None,
        description="NSE script categories (e.g., 'vuln,safe,discovery')"
    )

    specific_scripts: Optional[str] = Field(
        None,
        description="Specific NSE scripts (e.g., 'http-title,ssh-hostkey')"
    )

    script_args: Optional[str] = Field(
        None,
        description="NSE script arguments"
    )

    # Host discovery
    ping_type: str = Field(
        "tcp_syn",
        description="Ping type: tcp_syn, tcp_ack, udp, sctp, icmp_echo, icmp_timestamp, icmp_netmask, ip_protocol, arp, none"
    )

    no_ping: bool = Field(
        False,
        description="Skip host discovery"
    )

    # Advanced options
    fragment_packets: bool = Field(
        False,
        description="Fragment IP packets"
    )

    mtu: Optional[int] = Field(
        None,
        description="Set custom MTU size"
    )

    decoy_hosts: Optional[str] = Field(
        None,
        description="Decoy hosts for scan spoofing"
    )

    source_port: Optional[int] = Field(
        None,
        description="Source port for scans"
    )

    proxies: Optional[str] = Field(
        None,
        description="HTTP/SOCKS4 proxies"
    )

    # DNS resolution
    dns_resolution: str = Field(
        "sometimes",
        description="DNS resolution: always, never, sometimes"
    )

    # Output options
    output_format: str = Field(
        "normal",
        description="Output format: normal, xml, json, greppable, all"
    )

    verbose_level: int = Field(
        1,
        ge=0,
        le=5,
        description="Verbosity level (0-5)"
    )

    # Safety options
    safe_mode: bool = Field(
        True,
        description="Enable safe mode (avoid dangerous scripts)"
    )

    max_retries: int = Field(
        2,
        ge=0,
        le=10,
        description="Maximum retries for port scans"
    )

    host_timeout: Optional[str] = Field(
        None,
        description="Maximum time per host (e.g., '30m', '2h')"
    )

    @validator('targets')
    def validate_targets(cls, v):
        """Validate and sanitize target specification"""
        # Basic validation for common patterns
        patterns = [
            r'^[\d\.\-\/\,]+$',  # IP ranges
            r'^[a-zA-Z0-9\.\-]+$',  # Hostnames
            r'^[\d\.\:]+$',  # IPv6
        ]

        # Remove any potentially dangerous characters
        cleaned = re.sub(r'[;&|`$()<>]', '', v)
        if cleaned != v:
            logger.warning(f"Cleaned potentially dangerous characters from targets: {v} -> {cleaned}")

        return cleaned

    @validator('ports')
    def validate_ports(cls, v):
        """Validate port specification"""
        if v is None:
            return None

        if v == '-':
            return v

        # Validate port ranges and lists
        port_pattern = r'^[\d\,\-]+$'
        if not re.match(port_pattern, v):
            raise ValueError(f"Invalid port specification: {v}")

        return v


class NmapPortScanner(Tool):
    """
    Comprehensive Nmap port scanning tool with all major features
    """

    # Timing template mappings
    TIMING_TEMPLATES = {
        'paranoid': 0,
        'sneaky': 1,
        'polite': 2,
        'normal': 3,
        'aggressive': 4,
        'insane': 5
    }

    # Scan type mappings
    SCAN_TYPES = {
        'tcp_connect': '-sT',
        'syn_stealth': '-sS',
        'udp': '-sU',
        'tcp_ack': '-sA',
        'tcp_window': '-sW',
        'tcp_maimon': '-sM',
        'tcp_null': '-sN',
        'tcp_fin': '-sF',
        'tcp_xmas': '-sX',
        'sctp_init': '-sY',
        'ip_protocol': '-sO'
    }

    # Ping type mappings
    PING_TYPES = {
        'tcp_syn': '-PS',
        'tcp_ack': '-PA',
        'udp': '-PU',
        'sctp': '-PY',
        'icmp_echo': '-PE',
        'icmp_timestamp': '-PP',
        'icmp_netmask': '-PM',
        'ip_protocol': '-PO',
        'arp': '-PR',
        'none': '-Pn'
    }

    def _build_nmap_arguments(self, params: ToolParameters) -> str:
        """
        Build Nmap command arguments based on parameters
        """
        args = []

        # Scan type
        scan_flag = self.SCAN_TYPES.get(params.scan_type, '-sT')
        args.append(scan_flag)

        # Port specification
        if params.ports:
            if params.ports == '-':
                args.append('-p-')  # All ports
            else:
                args.append(f'-p {params.ports}')

        # Timing template
        timing = self.TIMING_TEMPLATES.get(params.timing_template, 3)
        args.append(f'-T{timing}')

        # Parallelism
        if params.max_parallelism:
            args.append(f'--max-parallelism {params.max_parallelism}')

        # Rate limiting
        if params.min_rate:
            args.append(f'--min-rate {params.min_rate}')
        if params.max_rate:
            args.append(f'--max-rate {params.max_rate}')

        # Service detection
        if params.service_detection:
            args.append('-sV')
            args.append(f'--version-intensity {params.version_intensity}')

        # OS detection
        if params.os_detection:
            args.append('-O')
            args.append('--osscan-guess')

        # Script scanning
        if params.default_scripts:
            args.append('-sC')

        if params.script_categories:
            args.append(f'--script={params.script_categories}')

        if params.specific_scripts:
            args.append(f'--script={params.specific_scripts}')

        if params.script_args:
            args.append(f'--script-args={params.script_args}')

        # Host discovery
        if params.no_ping:
            args.append('-Pn')
        else:
            ping_flag = self.PING_TYPES.get(params.ping_type, '-PS')
            args.append(ping_flag)

        # Advanced options
        if params.fragment_packets:
            args.append('-f')

        if params.mtu:
            args.append(f'--mtu {params.mtu}')

        if params.decoy_hosts:
            args.append(f'-D {params.decoy_hosts}')

        if params.source_port:
            args.append(f'--source-port {params.source_port}')

        if params.proxies:
            args.append(f'--proxies {params.proxies}')

        # DNS resolution
        if params.dns_resolution == 'always':
            args.append('-R')
        elif params.dns_resolution == 'never':
            args.append('-n')

        # Retries
        args.append(f'--max-retries {params.max_retries}')

        # Host timeout
        if params.host_timeout:
            args.append(f'--host-timeout {params.host_timeout}')

        # Verbosity
        if params.verbose_level > 0:
            args.append('-' + 'v' * min(params.verbose_level, 5))

        return ' '.join(args)

    def _parse_nmap_output(self, nm, scan_result: dict) -> dict:
        """
        Parse and structure Nmap output for better readability
        """
        summary = {
            'scan_info': {
                'command': nm.command_line(),
                'version': nm.nmap_version(),
                'start_time': datetime.now().isoformat(),
                'scan_type': scan_result.get('scan', {})
            },
            'statistics': {
                'total_hosts': 0,
                'hosts_up': 0,
                'hosts_down': 0,
                'total_ports_scanned': 0,
                'open_ports': 0,
                'closed_ports': 0,
                'filtered_ports': 0
            },
            'hosts': []
        }

        for host in nm.all_hosts():
            host_info = {
                'address': host,
                'hostname': nm[host].hostname() if nm[host].hostname() else None,
                'state': nm[host].state(),
                'os': {},
                'ports': [],
                'scripts': {}
            }

            # Count host states
            if nm[host].state() == 'up':
                summary['statistics']['hosts_up'] += 1
            else:
                summary['statistics']['hosts_down'] += 1

            # OS information
            if 'osmatch' in nm[host]:
                os_matches = nm[host]['osmatch']
                if os_matches:
                    host_info['os'] = {
                        'name': os_matches[0].get('name', 'Unknown'),
                        'accuracy': os_matches[0].get('accuracy', 0),
                        'cpe': os_matches[0].get('cpe', [])
                    }

            # Port information
            for proto in nm[host].all_protocols():
                ports = nm[host][proto].keys()
                for port in sorted(ports):
                    port_info = nm[host][proto][port]

                    port_data = {
                        'port': port,
                        'protocol': proto,
                        'state': port_info.get('state', 'unknown'),
                        'service': port_info.get('name', ''),
                        'product': port_info.get('product', ''),
                        'version': port_info.get('version', ''),
                        'extrainfo': port_info.get('extrainfo', ''),
                        'cpe': port_info.get('cpe', '')
                    }

                    # Script results for this port
                    if 'script' in port_info:
                        port_data['scripts'] = port_info['script']

                    host_info['ports'].append(port_data)

                    # Update statistics
                    summary['statistics']['total_ports_scanned'] += 1
                    if port_info.get('state') == 'open':
                        summary['statistics']['open_ports'] += 1
                    elif port_info.get('state') == 'closed':
                        summary['statistics']['closed_ports'] += 1
                    elif port_info.get('state') == 'filtered':
                        summary['statistics']['filtered_ports'] += 1

            # Host scripts
            if 'hostscript' in nm[host]:
                for script in nm[host]['hostscript']:
                    host_info['scripts'][script['id']] = script.get('output', '')

            summary['hosts'].append(host_info)
            summary['statistics']['total_hosts'] += 1

        return summary

    def _format_text_output(self, summary: dict) -> str:
        """
        Create a formatted text output for display
        """
        output = []
        output.append("=" * 80)
        output.append("NMAP SCAN RESULTS")
        output.append("=" * 80)
        output.append("")

        # Statistics
        stats = summary['statistics']
        output.append("SCAN STATISTICS:")
        output.append(f"  • Total Hosts Scanned: {stats['total_hosts']}")
        output.append(f"  • Hosts Up: {stats['hosts_up']}")
        output.append(f"  • Hosts Down: {stats['hosts_down']}")
        output.append(f"  • Total Ports Scanned: {stats['total_ports_scanned']}")
        output.append(f"  • Open Ports: {stats['open_ports']}")
        output.append(f"  • Closed Ports: {stats['closed_ports']}")
        output.append(f"  • Filtered Ports: {stats['filtered_ports']}")
        output.append("")

        # Host details
        for host in summary['hosts']:
            output.append("-" * 60)
            output.append(f"HOST: {host['address']}")
            if host['hostname']:
                output.append(f"Hostname: {host['hostname']}")
            output.append(f"State: {host['state']}")

            # OS information
            if host['os'] and host['os'].get('name'):
                output.append(f"OS: {host['os']['name']} (Accuracy: {host['os']['accuracy']}%)")

            # Ports
            if host['ports']:
                output.append("\nOPEN PORTS:")
                for port in host['ports']:
                    if port['state'] == 'open':
                        service_info = port['service']
                        if port['product']:
                            service_info += f" ({port['product']}"
                            if port['version']:
                                service_info += f" {port['version']}"
                            service_info += ")"
                        output.append(f"  {port['port']}/{port['protocol']:<10} {port['state']:<10} {service_info}")

                        # Script results for port
                        if 'scripts' in port and port['scripts']:
                            for script_name, script_output in port['scripts'].items():
                                output.append(f"    |_ {script_name}: {script_output[:100]}...")

            # Host scripts
            if host['scripts']:
                output.append("\nHOST SCRIPTS:")
                for script_name, script_output in host['scripts'].items():
                    output.append(f"  {script_name}:")
                    for line in script_output.split('\n')[:5]:  # First 5 lines
                        output.append(f"    {line}")

            output.append("")

        return "\n".join(output)

    def _invoke(
            self, tool_parameters: dict[str, Any]
    ) -> Generator[ToolInvokeMessage, None, None]:
        """
        Execute Nmap scan with specified parameters
        """
        try:
            params = ToolParameters(**tool_parameters)

            # Import python-nmap
            try:
                import nmap
            except ImportError:
                yield self.create_text_message(
                    "❌ Error: python-nmap library not installed. Please install it using: pip install python-nmap"
                )
                return

            # Initialize Nmap
            nm = nmap.PortScanner()

            # Check if Nmap is installed
            try:
                nm.nmap_version()
            except nmap.PortScannerError:
                yield self.create_text_message(
                    "❌ Error: Nmap is not installed on this system. Please install Nmap first."
                )
                return

            # Build Nmap arguments
            arguments = self._build_nmap_arguments(params)

            # Log the scan command for transparency
            logger.info(f"Executing Nmap scan: nmap {arguments} {params.targets}")

            # Send initial status
            yield self.create_text_message(
                f"🔍 Starting Nmap scan...\n"
                f"Targets: {params.targets}\n"
                f"Scan Type: {params.scan_type}\n"
                f"Arguments: {arguments}\n"
            )

            # Execute the scan
            try:
                # Check if we need sudo (for SYN scan, OS detection, etc.)
                needs_sudo = params.scan_type == 'syn_stealth' or params.os_detection

                if needs_sudo:
                    # Get sudo password from credentials if available
                    sudo_password = self.runtime.credentials.get('sudo_password', '')
                    if not sudo_password:
                        yield self.create_text_message(
                            "⚠️ Warning: SYN scan and OS detection require root privileges. "
                            "Falling back to TCP connect scan."
                        )
                        arguments = arguments.replace('-sS', '-sT').replace('-O', '')

                # Run the scan
                scan_result = nm.scan(
                    hosts=params.targets,
                    arguments=arguments,
                    sudo=needs_sudo and bool(sudo_password)
                )

            except nmap.PortScannerError as e:
                yield self.create_text_message(f"❌ Scan error: {str(e)}")
                return
            except Exception as e:
                yield self.create_text_message(f"❌ Unexpected error during scan: {str(e)}")
                return

            # Parse and format results
            summary = self._parse_nmap_output(nm, scan_result)

            # Send formatted text output
            text_output = self._format_text_output(summary)
            yield self.create_text_message(text_output)

            # Send JSON output for programmatic processing
            yield self.create_json_message(summary)

            # Generate scan report summary
            stats = summary['statistics']
            report_summary = (
                f"\n✅ **SCAN COMPLETED**\n"
                f"━━━━━━━━━━━━━━━━━━━━\n"
                f"📊 **Summary:**\n"
                f"  • Hosts Up: {stats['hosts_up']}/{stats['total_hosts']}\n"
                f"  • Open Ports Found: {stats['open_ports']}\n"
                f"  • Scan Type: {params.scan_type}\n"
                f"  • Timing: {params.timing_template}\n"
            )

            # Add security findings if any
            security_findings = []
            for host in summary['hosts']:
                for port in host['ports']:
                    if port['state'] == 'open':
                        # Check for potentially risky services
                        risky_services = {
                            'telnet': 'Unencrypted remote access',
                            'ftp': 'Unencrypted file transfer',
                            'vnc': 'Remote desktop service',
                            'rdp': 'Windows remote desktop',
                            'smb': 'File sharing service',
                            'netbios': 'Windows networking'
                        }

                        service = port['service'].lower()
                        for risky, description in risky_services.items():
                            if risky in service:
                                security_findings.append(
                                    f"  ⚠️ {host['address']}:{port['port']} - {description} ({service})"
                                )

            if security_findings:
                report_summary += "\n🔒 **Security Considerations:**\n"
                report_summary += "\n".join(security_findings[:10])  # Limit to 10 findings

            yield self.create_text_message(report_summary)

            # Export options
            if params.output_format in ['xml', 'all']:
                # Generate XML output
                xml_output = nm.get_nmap_last_output()
                if xml_output:
                    yield self.create_blob_message(
                        xml_output.encode('utf-8'),
                        meta={
                            'mime_type': 'text/xml',
                            'filename': 'nmap_scan_results.xml'
                        }
                    )

        except Exception as e:
            logger.error(f"Error in Nmap scanner: {str(e)}", exc_info=True)
            yield self.create_text_message(f"❌ Error: {str(e)}")