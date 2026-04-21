"""
utils/file_analyzer.py

Detects MIME type and basic file type info for a given file path.
Requires: python-magic  (pip install python-magic)
On Debian/Ubuntu also: apt install libmagic1
"""

from dataclasses import dataclass
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

# Maps all known MIME variants → single canonical internal type
MIME_NORMALIZATION: dict[str, str] = {
    # PCAP
    "application/vnd.tcpdump.pcap":  "application/pcap",
    "application/x-pcap":            "application/pcap",

    # JPEG
    "image/jpg":                     "image/jpeg",
    "image/pjpeg":                   "image/jpeg",

    # ZIP
    "application/x-zip-compressed":  "application/zip",
    "application/x-zip":             "application/zip",

    # RAR
    "application/x-rar-compressed":  "application/x-rar",
    "application/vnd.rar":           "application/x-rar",

    # GZIP
    "application/x-gzip":            "application/gzip",
}

def normalize_mime(mime: str) -> str:
    return MIME_NORMALIZATION.get(mime, mime)

@dataclass
class ArtifactInfo:
    path: str
    raw_mime: str
    mime_type: str
    label: str

class FileAnalyzer:
    """Detect the MIME type and a human-readable label for a file."""

    def __init__(self) -> None:
        # mime=True returns the MIME string; keep_going=False stops at first match
        self._magic = magic.Magic(mime=True)

    def analyze(self, file_path: str) -> ArtifactInfo:
        """
        Detect the MIME type of *file_path*.

        Returns
        -------
        ArtifactInfo
            Contains path, raw_mime, canonical mime_type, and label.
        """
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")
        if not path.is_file():
            raise ValueError(f"Path is not a file: {file_path}")

        raw_mime: str = self._magic.from_file(str(path))
        canonical_mime = normalize_mime(raw_mime)
        label = MIME_LABELS.get(canonical_mime, f"Unknown ({canonical_mime})")
        logger.debug(f"Detected MIME type for {path.name!r}: {raw_mime} -> {canonical_mime}")
        return ArtifactInfo(
            path=str(path),
            raw_mime=raw_mime,
            mime_type=canonical_mime,
            label=label,
        )