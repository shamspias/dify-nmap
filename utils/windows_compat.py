import platform
import subprocess
import ctypes
import os


class WindowsCompatibility:
    """Handle Windows-specific requirements"""

    @staticmethod
    def is_admin() -> bool:
        """Check if running as administrator on Windows"""
        if platform.system() != "Windows":
            return os.geteuid() == 0

        try:
            return ctypes.windll.shell32.IsUserAnAdmin()
        except:
            return False

    @staticmethod
    def get_nmap_path() -> str:
        """Find Nmap installation on Windows"""
        if platform.system() != "Windows":
            return "nmap"

        # Common Windows installation paths
        paths = [
            r"C:\Program Files (x86)\Nmap\nmap.exe",
            r"C:\Program Files\Nmap\nmap.exe",
            r"C:\Nmap\nmap.exe"
        ]

        for path in paths:
            if os.path.exists(path):
                return path

        # Try to find in PATH
        try:
            result = subprocess.run(["where", "nmap"], capture_output=True, text=True)
            if result.returncode == 0:
                return result.stdout.strip()
        except:
            pass

        return "nmap"  # Fallback

    @staticmethod
    def enable_raw_sockets():
        """Enable raw socket support on Windows"""
        if platform.system() != "Windows":
            return True

        try:
            # Windows requires WinPcap/Npcap for raw sockets
            import winreg
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                                 r"SOFTWARE\WOW6432Node\Npcap")
            winreg.CloseKey(key)
            return True
        except:
            return False
