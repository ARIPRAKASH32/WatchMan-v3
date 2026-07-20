"""
utils/system.py — Cross-platform OS and privilege detection.

Centralizes platform-specific checks for Windows, Linux, and Arch.
"""
import os
import platform
import ctypes

def is_admin() -> bool:
    """Return True if the current process has administrative (root/Administrator) privileges."""
    try:
        if os.name == 'nt':
            return ctypes.windll.shell32.IsUserAnAdmin() == 1
        else:
            return os.geteuid() == 0
    except Exception:
        # If in doubt, assume False to gracefully fallback instead of crashing
        return False

def get_os_info() -> str:
    """Return a combined string of the OS and architecture."""
    return f"{platform.system()} {platform.release()} ({platform.machine()})"
