import logging
from collections.abc import Generator
from typing import Any
import json

from dify_plugin import Tool
from dify_plugin.entities.tool import ToolInvokeMessage
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


class OSFingerprintParameters(BaseModel):
    """
    Parameters for OS fingerprinting
    """
    target: str = Field(
        ...,
        description="Target host or network to fingerprint"
    )

    aggressive_guess: bool = Field(
        True,
        description="Make aggressive OS guesses"
    )

    detect_version: bool = Field(
        True,
        description="Detect OS version details"
    )

    scan_limit: bool = Field(
        True,
        description="Only scan hosts with open and closed ports"
    )


class OSFingerprintTool(Tool):
    """
    Tool for OS detection and fingerprinting
    """

    def _invoke(
            self, tool_parameters: dict[str, Any]
    ) -> Generator[ToolInvokeMessage, None, None]:
        """
        Perform OS fingerprinting scan
        """
        try:
            params = OSFingerprintParameters(**tool_parameters)

            # Import python-nmap
            try:
                import nmap
            except ImportError:
                yield self.create_text_message(
                    "❌ Error: python-nmap library not installed"
                )
                return

            nm = nmap.PortScanner()

            # Check if we have root privileges (required for OS detection)
            import os
            if os.geteuid() != 0:
                yield self.create_text_message(
                    "⚠️ Warning: OS detection requires root privileges. "
                    "Running basic scan instead.\n"
                    "To enable OS detection, run with sudo or provide sudo password in credentials."
                )
                # Fall back to service detection for OS hints
                use_os_detection = False
            else:
                use_os_detection = True

            yield self.create_text_message(
                f"🔍 Starting OS fingerprinting...\n"
                f"Target: {params.target}\n"
                f"Method: {'TCP/IP Stack Fingerprinting' if use_os_detection else 'Service-based Detection'}\n"
            )

            # Build scan arguments
            args = []

            if use_os_detection:
                args.append("-O")  # OS detection

                if params.aggressive_guess:
                    args.append("--osscan-guess")

                if params.scan_limit:
                    args.append("--osscan-limit")
            else:
                # Fallback: use service detection for OS hints
                args.append("-sV")
                args.append("--version-intensity 8")

            # Add some ports to scan for better OS detection
            args.append("-p 21,22,23,25,80,135,139,443,445,3389")

            # Timing
            args.append("-T4")  # Aggressive timing for faster results

            arguments = " ".join(args)

            # Execute scan
            try:
                scan_result = nm.scan(hosts=params.target, arguments=arguments)
            except Exception as e:
                yield self.create_text_message(f"❌ Scan error: {e}")
                return

            # Process results
            os_results = []
            total_hosts = 0
            identified_hosts = 0

            for host in nm.all_hosts():
                if nm[host].state() != "up":
                    continue

                total_hosts += 1
                host_os = {
                    "host": host,
                    "hostname": nm[host].hostname(),
                    "os_matches": [],
                    "os_fingerprint": None,
                    "device_type": None,
                    "running": None,
                    "cpe": [],
                    "tcp_sequence": {},
                    "services_hint": []
                }

                # OS match information
                if 'osmatch' in nm[host]:
                    identified_hosts += 1
                    for match in nm[host]['osmatch'][:3]:  # Top 3 matches
                        os_info = {
                            "name": match.get('name', 'Unknown'),
                            "accuracy": int(match.get('accuracy', 0)),
                            "line": match.get('line', ''),
                            "osclass": []
                        }

                        # OS class information
                        if 'osclass' in match:
                            for osclass in match['osclass']:
                                os_info['osclass'].append({
                                    "type": osclass.get('type', ''),
                                    "vendor": osclass.get('vendor', ''),
                                    "osfamily": osclass.get('osfamily', ''),
                                    "osgen": osclass.get('osgen', ''),
                                    "accuracy": int(osclass.get('accuracy', 0))
                                })

                                # Set device type from first match
                                if not host_os['device_type'] and osclass.get('type'):
                                    host_os['device_type'] = osclass['type']

                                # Set OS family
                                if not host_os['running'] and osclass.get('osfamily'):
                                    host_os['running'] = osclass['osfamily']

                                # Collect CPE
                                if 'cpe' in osclass:
                                    host_os['cpe'].extend(osclass['cpe'])

                        host_os['os_matches'].append(os_info)

                    # Set best match as fingerprint
                    if host_os['os_matches']:
                        best_match = host_os['os_matches'][0]
                        host_os['os_fingerprint'] = best_match['name']

                # TCP sequence predictability (for OS detection)
                if 'tcpsequence' in nm[host]:
                    tcp_seq = nm[host]['tcpsequence']
                    host_os['tcp_sequence'] = {
                        'index': tcp_seq.get('index', ''),
                        'difficulty': tcp_seq.get('difficulty', ''),
                        'values': tcp_seq.get('values', '')
                    }

                # Service-based OS hints (fallback or additional info)
                for proto in nm[host].all_protocols():
                    for port in nm[host][proto].keys():
                        port_info = nm[host][proto][port]
                        if port_info['state'] == 'open':
                            service = port_info.get('name', '')
                            product = port_info.get('product', '')

                            # Infer OS from services
                            if 'microsoft' in product.lower() or 'windows' in product.lower():
                                host_os['services_hint'].append('Windows')
                            elif 'apache' in product.lower() or 'nginx' in product.lower():
                                host_os['services_hint'].append('Linux/Unix')
                            elif 'iis' in service.lower():
                                host_os['services_hint'].append('Windows')
                            elif 'ssh' in service.lower() and 'openssh' in product.lower():
                                host_os['services_hint'].append('Linux/Unix')
                            elif 'netbios' in service.lower() or 'smb' in service.lower():
                                host_os['services_hint'].append('Windows')

                # Deduplicate service hints
                host_os['services_hint'] = list(set(host_os['services_hint']))

                # If no OS detection but have service hints
                if not host_os['os_fingerprint'] and host_os['services_hint']:
                    host_os['os_fingerprint'] = f"Likely {host_os['services_hint'][0]} (service-based)"
                    identified_hosts += 1

                os_results.append(host_os)

            # Create formatted output
            output = []
            output.append("=" * 60)
            output.append("OS FINGERPRINTING RESULTS")
            output.append("=" * 60)
            output.append(f"Hosts Scanned: {total_hosts}")
            output.append(f"OS Identified: {identified_hosts}")
            output.append("")

            # OS distribution summary
            os_distribution = {}
            device_types = {}

            for host_data in os_results:
                if host_data['running']:
                    os_family = host_data['running']
                    os_distribution[os_family] = os_distribution.get(os_family, 0) + 1

                if host_data['device_type']:
                    dev_type = host_data['device_type']
                    device_types[dev_type] = device_types.get(dev_type, 0) + 1

            if os_distribution:
                output.append("OS DISTRIBUTION:")
                output.append("-" * 40)
                for os_family, count in sorted(os_distribution.items(), key=lambda x: x[1], reverse=True):
                    output.append(f"• {os_family}: {count} host(s)")
                output.append("")

            if device_types:
                output.append("DEVICE TYPES:")
                output.append("-" * 40)
                for dev_type, count in sorted(device_types.items(), key=lambda x: x[1], reverse=True):
                    output.append(f"• {dev_type}: {count} device(s)")
                output.append("")

            output.append("DETAILED OS INFORMATION:")
            output.append("-" * 40)

            for host_data in os_results:
                output.append(f"\nHost: {host_data['host']}")
                if host_data['hostname']:
                    output.append(f"Hostname: {host_data['hostname']}")

                if host_data['os_fingerprint']:
                    output.append(f"OS: {host_data['os_fingerprint']}")

                if host_data['device_type']:
                    output.append(f"Device Type: {host_data['device_type']}")

                if host_data['os_matches']:
                    output.append("Possible OS matches:")
                    for i, match in enumerate(host_data['os_matches'][:3], 1):
                        output.append(f"  {i}. {match['name']} ({match['accuracy']}% accuracy)")
                        if match['osclass']:
                            osclass = match['osclass'][0]
                            output.append(f"     Type: {osclass.get('type', 'N/A')}")
                            output.append(f"     Vendor: {osclass.get('vendor', 'N/A')}")
                            output.append(f"     Family: {osclass.get('osfamily', 'N/A')}")
                            output.append(f"     Generation: {osclass.get('osgen', 'N/A')}")

                if host_data['tcp_sequence'] and host_data['tcp_sequence'].get('difficulty'):
                    output.append(f"TCP Sequence Difficulty: {host_data['tcp_sequence']['difficulty']}")

                if host_data['services_hint'] and not host_data['os_matches']:
                    output.append(f"Service-based hints: {', '.join(host_data['services_hint'])}")

                if host_data['cpe']:
                    output.append("CPE:")
                    for cpe in host_data['cpe'][:3]:  # Limit to 3
                        output.append(f"  • {cpe}")

            yield self.create_text_message("\n".join(output))

            # Send JSON summary
            summary = {
                "target": params.target,
                "total_hosts": total_hosts,
                "identified_hosts": identified_hosts,
                "identification_rate": f"{(identified_hosts / total_hosts * 100):.1f}%" if total_hosts > 0 else "0%",
                "os_distribution": os_distribution,
                "device_types": device_types,
                "detailed_results": os_results
            }

            yield self.create_json_message(summary)

            # Security insights
            insights = []

            # Check for outdated OS versions
            for host_data in os_results:
                if host_data['os_fingerprint']:
                    os_name = host_data['os_fingerprint'].lower()

                    # Check for old Windows versions
                    old_windows = ['windows xp', 'windows 2003', 'windows 2000', 'windows 7', 'windows 8']
                    if any(old in os_name for old in old_windows):
                        insights.append(f"⚠️ {host_data['host']}: Outdated Windows version detected - security risk")

                    # Check for old Linux kernels
                    if 'linux 2.' in os_name:
                        insights.append(f"⚠️ {host_data['host']}: Old Linux kernel detected - consider updating")

                    # Check for embedded devices
                    if host_data['device_type'] in ['printer', 'router', 'switch', 'firewall']:
                        insights.append(f"📡 {host_data['host']}: Network device detected - ensure firmware is updated")

            if insights:
                insights_output = "\n🔍 **SECURITY INSIGHTS:**\n"
                insights_output += "━" * 30 + "\n"
                insights_output += "\n".join(insights[:10])  # Limit to 10
                yield self.create_text_message(insights_output)

            # Final summary
            success_rate = (identified_hosts / total_hosts * 100) if total_hosts > 0 else 0
            yield self.create_text_message(
                f"\n✅ **OS Fingerprinting Complete**\n"
                f"Successfully identified OS on {identified_hosts}/{total_hosts} hosts ({success_rate:.1f}%)"
            )

        except Exception as e:
            logger.error(f"OS fingerprinting error: {e}", exc_info=True)
            yield self.create_text_message(f"❌ Error: {e}")
