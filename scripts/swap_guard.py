"""Check whether Linux cgroup v2 prevents swapping key-handling processes."""
import sys
from pathlib import Path


def guarded(pid):
    try:
        line = next(v for v in Path(f"/proc/{pid}/cgroup").read_text().splitlines() if v.startswith("0::"))
        directory = Path("/sys/fs/cgroup") / line[3:].lstrip("/")
        root = Path("/sys/fs/cgroup")
        while directory.is_relative_to(root):
            limit = directory / "memory.swap.max"
            if limit.exists() and limit.read_text().strip() == "0":
                return True
            if directory == root:
                break
            directory = directory.parent
    except (OSError, StopIteration):
        pass
    return False


if __name__ == "__main__":
    if len(Path("/proc/swaps").read_text().splitlines()) <= 1:
        raise SystemExit(0)
    raise SystemExit(0 if guarded(sys.argv[1] if len(sys.argv) > 1 else "self") else 1)
