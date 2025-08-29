import logging
from collections.abc import Generator
from typing import Any
import json

from dify_plugin import Tool
from dify_plugin.entities.tool import ToolInvokeMessage
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


class ServiceDetectorParameters(BaseModel):
    """
    Parameters for service detection
    """
    target: str = Field(
        ...,
        description="Target host to scan"
    )

    ports: str = Field(
        "1-1000",
        description="Port range to scan"
    )

    intensity: int = Field(
        7,
        ge=0,
        le=9,
        description="Version detection intensity (0-9)"
    )

    service_info: bool = Field(
        True,
        description="Get detailed service information"
    )


class ServiceDetectorTool(Tool):
    """
    Tool for detecting and identifying services
    """

    def _invoke(
            self, tool_parameters: dict[str, Any]
    ) -> Generator[ToolInvokeMessage, None, None]:
        """
        Perform service detection scan
        """
        try:
            params = ServiceDetectorParameters(**tool_parameters)

            # Import python-nmap
            try:
                import nmap
            except ImportError:
                yield self.create_text_message(
                    "❌ Error: python-nmap library not installed"
                )
                return

            nm = nmap.PortScanner()

            yield self.create_text_message(
                f"🔍 Starting service detection...\n"
                f"Target: {params.target}\n"
                f"Ports: {params.ports}\n"
                f"Intensity: {params.intensity}/9\n"
            )

            # Build scan arguments
            args = [
                "-sV",  # Service version detection
                f"--version-intensity {params.intensity}",
                "-sC" if params.service_info else "",  # Default scripts for more info
                "-T3",  # Normal timing
                f"-p {params.ports}"
            ]

            arguments = " ".join(filter(None, args))

            # Execute scan
            try:
                scan_result = nm.scan(hosts=params.target, arguments=arguments)
            except Exception as e:
                yield self.create_text_message(f"❌ Scan error: {e}")
                return

            # Process results
            services_found = []
            total_open_ports = 0

            for host in nm.all_hosts():
                if nm[host].state() != "up":
                    continue

                host_services = {
                    "host": host,
                    "hostname": nm[host].hostname(),
                    "services": []
                }

                for proto in nm[host].all_protocols():
                    for port in sorted(nm[host][proto].keys()):
                        port_info = nm[host][proto][port]

                        if port_info['state'] == 'open':
                            total_open_ports += 1

                            service = {
                                "port": port,
                                "protocol": proto,
                                "state": port_info['state'],
                                "service": port_info.get('name', 'unknown'),
                                "product": port_info.get('product', ''),
                                "version": port_info.get('version', ''),
                                "extrainfo": port_info.get('extrainfo', ''),
                                "cpe": port_info.get('cpe', ''),
                                "confidence": port_info.get('conf', '0')
                            }

                            # Add script results if available
                            if 'script' in port_info:
                                service['scripts'] = {}
                                for script_name, script_output in port_info['script'].items():
                                    # Filter for service-related scripts
                                    if any(x in script_name for x in ['banner', 'header', 'title', 'version']):
                                        service['scripts'][script_name] = script_output[:200]

                            host_services['services'].append(service)

                if host_services['services']:
                    services_found.append(host_services)

            # Create formatted output
            output = []
            output.append("=" * 60)
            output.append("SERVICE DETECTION RESULTS")
            output.append("=" * 60)
            output.append(f"Target: {params.target}")
            output.append(f"Open Ports Found: {total_open_ports}")
            output.append("")

            # Service summary by type
            service_types = {}
            for host_data in services_found:
                for service in host_data['services']:
                    svc_name = service['service']
                    if svc_name not in service_types:
                        service_types[svc_name] = []
                    service_types[svc_name].append({
                        'port': service['port'],
                        'version': f"{service['product']} {service['version']}".strip()
                    })

            output.append("SERVICES BY TYPE:")
            output.append("-" * 40)
            for svc_type, instances in sorted(service_types.items()):
                output.append(f"• {svc_type}: {len(instances)} instance(s)")
                for inst in instances[:3]:  # Show first 3
                    version_info = f" - {inst['version']}" if inst['version'] else ""
                    output.append(f"  - Port {inst['port']}{version_info}")

            output.append("")
            output.append("DETAILED SERVICE INFORMATION:")
            output.append("-" * 40)

            for host_data in services_found:
                output.append(f"\nHost: {host_data['host']}")
                if host_data['hostname']:
                    output.append(f"Hostname: {host_data['hostname']}")
                output.append("")

                # Group services by category
                web_services = []
                database_services = []
                remote_access = []
                mail_services = []
                other_services = []

                for service in host_data['services']:
                    svc_info = (
                        f"  Port {service['port']}/{service['protocol']}: "
                        f"{service['service']}"
                    )

                    if service['product']:
                        svc_info += f" ({service['product']}"
                        if service['version']:
                            svc_info += f" {service['version']}"
                        svc_info += ")"

                    if service['extrainfo']:
                        svc_info += f" [{service['extrainfo']}]"

                    # Categorize services
                    svc_name = service['service'].lower()
                    if any(x in svc_name for x in ['http', 'https', 'web']):
                        web_services.append(svc_info)
                    elif any(x in svc_name for x in ['sql', 'mysql', 'postgres', 'mongo', 'redis', 'elastic']):
                        database_services.append(svc_info)
                    elif any(x in svc_name for x in ['ssh', 'telnet', 'rdp', 'vnc']):
                        remote_access.append(svc_info)
                    elif any(x in svc_name for x in ['smtp', 'pop', 'imap', 'mail']):
                        mail_services.append(svc_info)
                    else:
                        other_services.append(svc_info)

                # Output by category
                if web_services:
                    output.append("Web Services:")
                    output.extend(web_services)
                if database_services:
                    output.append("Database Services:")
                    output.extend(database_services)
                if remote_access:
                    output.append("Remote Access:")
                    output.extend(remote_access)
                if mail_services:
                    output.append("Mail Services:")
                    output.extend(mail_services)
                if other_services:
                    output.append("Other Services:")
                    output.extend(other_services)

            yield self.create_text_message("\n".join(output))

            # Send JSON summary
            summary = {
                "target": params.target,
                "total_open_ports": total_open_ports,
                "unique_services": len(service_types),
                "detection_intensity": params.intensity,
                "services_by_type": {
                    k: len(v) for k, v in service_types.items()
                },
                "detailed_services": services_found
            }

            yield self.create_json_message(summary)

            # Security recommendations
            recommendations = []

            # Check for unencrypted services
            unsafe_services = {
                'telnet': 'Use SSH instead',
                'ftp': 'Use SFTP or FTPS',
                'http': 'Use HTTPS',
                'vnc': 'Use VNC over SSH tunnel',
                'mysql': 'Restrict to localhost or use SSL',
                'redis': 'Enable authentication and bind to localhost',
                'mongodb': 'Enable authentication',
                'smtp': 'Use SMTP with TLS'
            }

            for svc_type in service_types.keys():
                svc_lower = svc_type.lower()
                for unsafe, recommendation in unsafe_services.items():
                    if unsafe in svc_lower:
                        recommendations.append(f"⚠️ {svc_type}: {recommendation}")

            if recommendations:
                rec_output = "\n🔒 **SECURITY RECOMMENDATIONS:**\n"
                rec_output += "━" * 30 + "\n"
                rec_output += "\n".join(recommendations[:5])  # Limit to 5
                yield self.create_text_message(rec_output)

            # Final summary
            yield self.create_text_message(
                f"\n✅ **Service Detection Complete**\n"
                f"Found {total_open_ports} open ports running {len(service_types)} unique services"
            )

        except Exception as e:
            logger.error(f"Service detection error: {e}", exc_info=True)
            yield self.create_text_message(f"❌ Error: {e}")
