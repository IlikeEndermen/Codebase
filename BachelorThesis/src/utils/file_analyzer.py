"""
utils/file_analyzer.py

Detects MIME type and basic file type info for a given file path.
Requires: python-magic  (pip install python-magic)
On Debian/Ubuntu also: apt install libmagic1
"""

import logging
from pathlib import Path
from typing import Tuple

import magic  # python-magic

logger = logging.getLogger(__name__)

# Mapping from MIME type → human-readable label shown in the GUI/CLI
MIME_LABELS: dict[str, str] = {
    "image/png":               "PNG Image",
    "image/jpeg":              "JPEG Image",
    "application/pcap":        "PCAP Network Capture",
    "application/zip":         "ZIP Archive",
    "application/x-rar":       "RAR Archive",
    "application/gzip":        "GZIP Archive",
    "application/octet-stream": "Raw Binary / Unknown",
}


class FileAnalyzer:
    """Detect the MIME type and a human-readable label for a file."""

    def __init__(self) -> None:
        # mime=True returns the MIME string; keep_going=False stops at first match
        self._magic = magic.Magic(mime=True)

    def analyze(self, file_path: str) -> Tuple[str, str]:
        """
        Detect the MIME type of *file_path*.

        Returns
        -------
        mime_type : str
            e.g. "image/png"
        label : str
            Human-readable description, e.g. "PNG Image"
        """
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")
        if not path.is_file():
            raise ValueError(f"Path is not a file: {file_path}")

        mime_type: str = self._magic.from_file(str(path))
        label = MIME_LABELS.get(mime_type, f"Unknown ({mime_type})")
        logger.debug(f"Detected MIME type for {path.name!r}: {mime_type}")
        return mime_type, label
