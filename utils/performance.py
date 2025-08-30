import asyncio
import ipaddress
from typing import List, Generator, Tuple
import logging

logger = logging.getLogger(__name__)


class ScanOptimizer:
    """Optimize scan performance based on network characteristics"""

    @staticmethod
    def chunk_targets(targets: str, chunk_size: int = 256) -> Generator[str, None, None]:
        """Split large networks into chunks for parallel scanning"""
        try:
            network = ipaddress.ip_network(targets, strict=False)
            hosts = list(network.hosts())

            for i in range(0, len(hosts), chunk_size):
                chunk = hosts[i:i + chunk_size]
                if len(chunk) == 1:
                    yield str(chunk[0])
                else:
                    yield f"{chunk[0]}-{chunk[-1].compressed.split('.')[-1]}"
        except:
            # Not a CIDR, return as-is
            yield targets

    @staticmethod
    def estimate_scan_time(targets: str, ports: str, techniques: List[str]) -> float:
        """Estimate scan duration for better UX"""
        base_time = 10  # seconds

        # Factor in network size
        try:
            network = ipaddress.ip_network(targets, strict=False)
            host_factor = min(network.num_addresses * 0.5, 300)
        except:
            host_factor = 10

        # Factor in port count
        if ports == "-p-":
            port_factor = 100
        elif ports and "," in ports:
            port_factor = len(ports.split(",")) * 2
        else:
            port_factor = 20

        # Factor in scan techniques
        technique_factor = len(techniques) * 10

        return base_time + host_factor + port_factor + technique_factor

    @staticmethod
    def get_optimal_timing(host_count: int, is_local: bool = False) -> str:
        """Determine optimal timing template"""
        if is_local:
            return "-T4"  # Aggressive for local networks
        elif host_count > 1000:
            return "-T3"  # Normal for large networks
        elif host_count > 100:
            return "-T4"  # Aggressive for medium networks
        else:
            return "-T4"  # Aggressive for small networks

    @staticmethod
    async def parallel_scan(scanner, chunks: List[str], args: str, max_workers: int = 5):
        """Run parallel scans on network chunks"""
        results = []
        semaphore = asyncio.Semaphore(max_workers)

        async def scan_chunk(chunk):
            async with semaphore:
                return await scanner.scan_async(chunk, args)

        tasks = [scan_chunk(chunk) for chunk in chunks]
        results = await asyncio.gather(*tasks)

        return results
