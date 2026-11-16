"""
Live file tailing
Watches a directory of log files and ingests new lines as they are appended,
to simulate real-time streaming. Files must be named '<log_source>.log'
(linux_auth.log, firewall.log, web.log, ...), which is what
simulation/logGenerator.py writes.

    python collector/fileTail.py data/generated
    python simulation/logGenerator.py --stream      # in another terminal
"""

import argparse
import sys
from pathlib import Path
from typing import Dict, List

from watchfiles import watch

# Add backend to path to import ingestion module
sys.path.insert(0, str(Path(__file__).parent.parent))
from backend.ingestion import ingest_batch
from backend.models import LogSource

KNOWN_SOURCES = {source.value for source in LogSource}


class FileTailer:
    """Remembers how far each file has been read and ingests what is new."""

    def __init__(self, directory, from_start: bool = False):
        self.directory = Path(directory)
        self.offsets: Dict[Path, int] = {}
        if not from_start:  # only lines written from now on
            for path in self.log_files():
                self.offsets[path] = path.stat().st_size

    def log_files(self) -> List[Path]:
        return sorted(p for p in self.directory.glob("*.log") if p.stem in KNOWN_SOURCES)

    def read_new_lines(self, path: Path) -> List[str]:
        """Return the complete lines appended since the last read."""
        size = path.stat().st_size
        offset = self.offsets.get(path, 0)
        if size < offset:  # file was truncated or rotated
            offset = 0
        with open(path, "rb") as handle:
            handle.seek(offset)
            data = handle.read()
        end = data.rfind(b"\n") + 1  # leave a half-written last line for next time
        self.offsets[path] = offset + end
        return data[:end].decode("utf-8", errors="replace").splitlines()

    def poll(self) -> List[dict]:
        """Ingest new lines from every file. Returns one summary per batch."""
        results = []
        for path in self.log_files():
            lines = self.read_new_lines(path)
            if lines:
                results.append(ingest_batch(lines, path.stem))
        return results


def main():
    parser = argparse.ArgumentParser(description="ARGUS live file tailing")
    parser.add_argument("directory", nargs="?",
                        default=str(Path(__file__).parent.parent / "data" / "generated"))
    parser.add_argument("--from-start", action="store_true",
                        help="also ingest what the files already contain")
    args = parser.parse_args()

    Path(args.directory).mkdir(parents=True, exist_ok=True)
    tailer = FileTailer(args.directory, args.from_start)
    print(f"🔄 Tailing {args.directory} (Ctrl+C to stop)")
    try:
        tailer.poll()
        for _ in watch(args.directory):
            for result in tailer.poll():
                print(f"✓ {result['count']} logs ingested "
                      f"({result['parse_errors']} parse errors, stored={result['stored']})")
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
