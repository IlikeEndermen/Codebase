"""
utils/file_analyzer.py

Detects MIME type and basic file type info for a given file path.
Requires: python-magic  (pip install python-magic)
On Debian/Ubuntu also: apt install libmagic1
"""

from dataclasses import dataclass
import logging
from pathlib import Path
from typing import Optional

import magic  # python-magic

logger = logging.getLogger(__name__)


# Mapping from MIME type → human-readable label shown in the GUI/CLI
MIME_LABELS: dict[str, str] = {
    "image/png":                "PNG Image",
    "image/jpeg":               "JPEG Image",
    "application/pcap":         "PCAP Network Capture",
    "application/zip":          "ZIP Archive",
    "application/x-rar":        "RAR Archive",
    "application/gzip":         "GZIP Archive",
    "application/octet-stream": "Raw Binary / Unknown",
    "text/plain":              "binary", # .bin, .txt
    "application/octet-stream": "binary", # fallback for unknown types
    "inode/x-empty":           "binary", #empty files are common in CTFs, treat as binary
}


# Maps all known MIME variants → single canonical internal type
MIME_NORMALIZATION: dict[str, str] = {
    # PCAP
    "application/vnd.tcpdump.pcap": "application/pcap",
    "application/x-pcap":           "application/pcap",

    # PCAPNG
    "application/x-pcapng":         "application/pcap",
    "application/pcapng":           "application/pcap",

    # JPEG
    "image/jpg":                    "image/jpeg",
    "image/pjpeg":                  "image/jpeg",

    # ZIP
    "application/x-zip-compressed": "application/zip",
    "application/x-zip":            "application/zip",

    # RAR
    "application/x-rar-compressed": "application/x-rar",
    "application/vnd.rar":          "application/x-rar",

    # GZIP
    "application/x-gzip":           "application/gzip",

     # Binary / unknown — route everything unrecognised to binary ruleset
    "application/octet-stream":     "binary",
    "inode/x-empty":                "binary",
    "text/plain":                   "binary",  # .bin files with ASCII content
    "text/html":                    "binary",  # corrupted/misidentified files
    "application/x-executable":    "binary",
    "application/x-sharedlib":     "binary",
    "application/x-object":        "binary",
    "application/x-dosexec":       "binary",  # Windows PE/.exe files
}


# Fallback: maps magic description substrings → canonical MIME type.
# Used when libmagic returns application/octet-stream but the description
# string still identifies the format (e.g. pcapng files).
DESCRIPTION_NORMALIZATION: dict[str, str] = {
    # PCAP variants
    "pcapng capture file":          "application/pcap",
    "pcap capture file":            "application/pcap",
    "tcpdump capture file":         "application/pcap",

    # Image formats that libmagic sometimes misidentifies
    "png image data":               "image/png",
    "jpeg image data":              "image/jpeg",
    "gif image data":               "image/gif",
    "bitmap image":                 "image/bmp",
    "pc bitmap":                    "image/bmp",

    # Archive formats
    "zip archive data":             "application/zip",
    "rar archive data":             "application/x-rar",
    "7-zip archive data":           "application/x-7z-compressed",
    "gzip compressed data":         "application/gzip",
    "bzip2 compressed data":        "application/x-bzip2",
    "posix tar archive":            "application/x-tar",

    # Binary / unknown — anything unrecognised goes to binary rules
    "data":                         "binary",
    "ascii text":                   "binary",
    "utf-8 unicode text":           "binary",
    "very short file":              "binary",
    "empty":                        "binary",
}


def normalize_mime(mime: str) -> str:
    """Map a raw MIME string to its canonical internal type."""
    return MIME_NORMALIZATION.get(mime, mime)


def normalize_by_description(description: str) -> Optional[str]:
    """
    Check the magic description string when the MIME type is ambiguous
    (i.e. fell back to application/octet-stream).

    Returns the canonical MIME type if a match is found, else None.
    """
    description_lower = description.lower()
    for key, canonical in DESCRIPTION_NORMALIZATION.items():
        if key in description_lower:
            return canonical
    return None


@dataclass
class ArtifactInfo:
    path: str
    raw_mime: str
    mime_type: str
    label: str


class FileAnalyzer:
    """Detect the MIME type and a human-readable label for a file."""

    def __init__(self) -> None:
        self._magic_mime = magic.Magic(mime=True)   # returns MIME string
        self._magic_desc = magic.Magic(mime=False)  # returns human-readable description

    def analyze(self, file_path: str) -> ArtifactInfo:
        """
        Detect the MIME type of *file_path*.

        Detection is two-stage:
          1. MIME-based normalisation via MIME_NORMALIZATION.
          2. Description-string fallback via DESCRIPTION_NORMALIZATION,
             used when libmagic cannot assign a proper MIME type and
             returns application/octet-stream instead.

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

        raw_mime: str = self._magic_mime.from_file(str(path))
        canonical_mime = normalize_mime(raw_mime)

        # Stage 2: description-string fallback for ambiguous formats
        if canonical_mime == "application/octet-stream":
            description: str = self._magic_desc.from_file(str(path))
            logger.debug(
                f"Ambiguous MIME for {path.name!r}, checking description: {description!r}"
            )
            remapped = normalize_by_description(description)
            if remapped:
                canonical_mime = remapped

        label = MIME_LABELS.get(canonical_mime, f"Unknown ({canonical_mime})")
        logger.debug(
            f"Detected MIME for {path.name!r}: {raw_mime!r} -> {canonical_mime!r}"
        )
        return ArtifactInfo(
            path=str(path),
            raw_mime=raw_mime,
            mime_type=canonical_mime,
            label=label,
        )