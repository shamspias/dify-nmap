import logging
from collections.abc import Generator
from typing import Any
import ipaddress
import json

from dify_plugin import Tool
from dify_plugin.entities.tool import ToolInvokeMessage
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


class NetworkDiscoveryParameters(BaseModel):
    """
    Parameters for network discovery and host enumeration
    """
    network: str = Field(
        ...,
        description="Network to scan (CIDR notation like 192.168.1.0/24)"
    )

    discovery_method: str = Field(
        "arp",
        description="Discovery method: arp (local), icmp, tcp, udp, comprehensive"
    )

    resolve_hostnames: bool = Field(
        True,
        description="Resolve IP addresses to hostnames"
    )

    detect_os: bool = Field(
        False,
        description="Basic OS detection"
    )

    show_mac_addresses: bool = Field(
        True,
        description="Show MAC addresses (local network only)"
    )

    scan_speed: str = Field(
        "normal",
        description="Scan speed: slow, normal, fast"
    )


class NetworkDiscoveryTool(Tool):
    """
    Tool for discovering active hosts on a network
    """

    def _invoke(
            self, tool_parameters: dict[str, Any]
    ) -> Generator[ToolInvokeMessage, None, None]:
        """
        Perform network discovery scan
        """
        try:
            params = NetworkDiscoveryParameters(**tool_parameters)

            # Import python-nmap
            try:
                import nmap
            except ImportError:
                yield self.create_text_message(
                    "❌ Error: python-nmap library not installed"
                )
                return

            nm = nmap.PortScanner()

            # Validate network
            try:
                network = ipaddress.ip_network(params.network, strict=False)
                total_hosts = network.num_addresses
            except ValueError as e:
                yield self.create_text_message(f"❌ Invalid network: {e}")
                return

            yield self.create_text_message(
                f"🔍 Starting network discovery...\n"
                f"Network: {params.network}\n"
                f"Total possible hosts: {total_hosts}\n"
                f"Method: {params.discovery_method}\n"
            )

            # Build discovery arguments
            args = []

            # Discovery method
            if params.discovery_method == "arp":
                args.append("-sn -PR")
            elif params.discovery_method == "icmp":
                args.append("-sn -PE")
            elif params.discovery_method == "tcp":
                args.append("-sn -PS21,22,25,80,443")
            elif params.discovery_method == "udp":
                args.append("-sn -PU53,111,137,161")
            elif params.discovery_method == "comprehensive":
                args.append("-sn -PE -PS21,22,25,80,443 -PA80,443 -PP -PM")
            else:
                args.append("-sn")

            # DNS resolution
            if not params.resolve_hostnames:
                args.append("-n")
            else:
                args.append("-R")

            # OS detection (basic)
            if params.detect_os:
                args.append("-O --osscan-limit")

            # Timing
            timing_map = {"slow": "-T2", "normal": "-T3", "fast": "-T4"}
            args.append(timing_map.get(params.scan_speed, "-T3"))

            arguments = " ".join(args)

            # Execute scan
            try:
                scan_result = nm.scan(hosts=params.network, arguments=arguments)
            except Exception as e:
                yield self.create_text_message(f"❌ Scan error: {e}")
                return

            # Process results
            active_hosts = []
            for host in nm.all_hosts():
                if nm[host].state() == "up":
                    host_info = {
                        "ip": host,
                        "state": "up",
                        "hostname": nm[host].hostname() if nm[host].hostname() else None,
                        "mac": None,
                        "vendor": None,
                        "os_guess": None
                    }

                    # MAC address info
                    if 'addresses' in nm[host] and 'mac' in nm[host]['addresses']:
                        host_info['mac'] = nm[host]['addresses']['mac']

                    # Vendor info
                    if 'vendor' in nm[host] and nm[host]['vendor']:
                        vendor_dict = nm[host]['vendor']
                        if vendor_dict:
                            host_info['vendor'] = list(vendor_dict.values())[0]

                    # OS info
                    if 'osmatch' in nm[host] and nm[host]['osmatch']:
                        os_match = nm[host]['osmatch'][0]
                        host_info['os_guess'] = {
                            'name': os_match.get('name', 'Unknown'),
                            'accuracy': os_match.get('accuracy', 0)
                        }

                    active_hosts.append(host_info)

            # Create output
            output = []
            output.append("=" * 60)
            output.append(f"NETWORK DISCOVERY RESULTS")
            output.append("=" * 60)
            output.append(f"Network: {params.network}")
            output.append(f"Active Hosts Found: {len(active_hosts)}/{total_hosts}")
            output.append("")
            output.append("ACTIVE HOSTS:")
            output.append("-" * 40)

            for host in sorted(active_hosts, key=lambda x: ipaddress.ip_address(x['ip'])):
                line = f"• {host['ip']:<15}"

                if host['hostname']:
                    line += f" ({host['hostname']})"

                if host['mac'] and params.show_mac_addresses:
                    line += f"\n  MAC: {host['mac']}"
                    if host['vendor']:
                        line += f" [{host['vendor']}]"

                if host['os_guess']:
                    line += f"\n  OS: {host['os_guess']['name']} ({host['os_guess']['accuracy']}%)"

                output.append(line)

            yield self.create_text_message("\n".join(output))

            # Send JSON summary
            summary = {
                "network": params.network,
                "total_addresses": total_hosts,
                "hosts_discovered": len(active_hosts),
                "discovery_method": params.discovery_method,
                "active_hosts": active_hosts
            }

            yield self.create_json_message(summary)

            # Final summary
            yield self.create_text_message(
                f"\n✅ Discovery Complete!\n"
                f"Found {len(active_hosts)} active hosts in {params.network}"
            )

        except Exception as e:
            logger.error(f"Network discovery error: {e}", exc_info=True)
            yield self.create_text_message(f"❌ Error: {e}")
