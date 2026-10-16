import sys

if sys.version_info < (3, 10):
    major, minor = sys.version_info[:2]
    sys.exit(f"需要 Python 3.10 或更高版本（当前 {major}.{minor}）。可用 `uv run python -m webui` 自动选择合适的解释器。")

from .server import main

if __name__ == "__main__":
    sys.exit(main())
