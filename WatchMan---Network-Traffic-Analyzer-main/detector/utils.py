import time
from collections import deque

def prune_window(window: deque, now: float, window_secs: float) -> None:
    """Remove timestamps older than window_secs from the left of the deque."""
    cutoff = now - window_secs
    while window and window[0] < cutoff:
        window.popleft()

def enforce_cap(d: dict, cap: int = 500) -> None:
    """If dict exceeds cap, remove the entry with the oldest last timestamp."""
    if len(d) > cap:
        # For simplicity, remove the key whose deque/dict has the oldest value or is empty
        oldest_key = min(d, key=lambda k: d[k][-1] if isinstance(d[k], deque) and d[k] else (d[k].get("last_time", 0) if isinstance(d[k], dict) else 0))
        del d[oldest_key]
