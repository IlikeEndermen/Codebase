"""
main.py - Big Sister with rule-based forensic triage
"""

import logging
import argparse
from pathlib import Path

from rules.rule_engine import RuleEngine
from rules.rule_executor import RuleExecutor
from utils.file_analyzer import FileAnalyzer

logging.basicConfig(
    level=logging.WARNING,
    format="%(levelname)s | %(name)s | %(message)s",
)
logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Legacy helpers (kept for backwards compatibility & direct CLI use)
# ---------------------------------------------------------------------------

def run_metadata_chain(file_path: str) -> dict:
    """
    Original metadata chain: ExifTool → Steghide → Binwalk.
    Still used by the GUI for image-only workflows.
    """
    from metadata.exiftool_scraper import MetadataScraper
    from steganography.steghide_scraper import SteghideScraper
    from steganography.binwalk_scraper import BinwalkScraper
    from metadata.parser import MetadataParser

    parser = MetadataParser()
    combined: dict = {}

    exif_scraper = MetadataScraper()
    raw_exif = exif_scraper.scrape(file_path)
    exif_scraper.display_metadata(raw_exif)
    combined.update(parser.parse_exif(raw_exif))

    steg_scraper = SteghideScraper()
    raw_steg = steg_scraper.scrape(file_path)
    steg_scraper.display_metadata(raw_steg)
    combined.update(parser.parse_steghide(raw_steg))

    bw_scraper = BinwalkScraper()
    raw_bw = bw_scraper.scrape(file_path, extract=False)
    bw_scraper.display_metadata(raw_bw)
    combined.update(parser.parse_binwalk(raw_bw))

    return combined


def run_image_search(file_path: str) -> None:
    from iris.image_search import ImageSearchIRIS
    searcher = ImageSearchIRIS()
    searcher.display_results(searcher.search_image(file_path))


# ---------------------------------------------------------------------------
# New rule-based analysis
# ---------------------------------------------------------------------------

def run_rule_based_analysis(file_path: str, verbose: bool = False) -> dict:
    """
    Run rule-based forensic triage on the given file.
    Returns a dict of all findings collected across every matched rule.
    """
    analyzer = FileAnalyzer()
    engine   = RuleEngine()
    executor = RuleExecutor()

    info = analyzer.analyze(file_path)
    print(f"\n[ File Analysis ]")
    print(f"  Path      : {info.path}")
    print(f"  MIME Type : {info.mime_type}")
    print(f"  File Type : {info.label}")

    rules = engine.get_applicable_rules(info.mime_type)
    print(f"\n[ Applicable Rules ]")
    if not rules:
        print("  ⚠️  No rules matched this artifact type.")
        return {}
    for rule in rules:
        print(f"  - {rule.name}  (priority: {rule.priority})")

    combined: dict = {}
    print(f"\n[ Rule Execution ]")
    for rule in rules:
        print(f"\n  → {rule.name}")
        results = executor.execute_rule(file_path, rule, combined, verbose=verbose)
        combined.update(results)

    print(f"\n{'=' * 60}")
    print("Analysis Complete".center(60))
    print(f"{'=' * 60}")
    for k, v in combined.items():
        print(f"  {k:<25}: {v}")

    return combined


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    ap = argparse.ArgumentParser(
        description="Big Sister — Rule-Based Forensic Triage for CTF"
    )
    ap.add_argument("file",         nargs="?",          help="Artifact to analyse")
    ap.add_argument("--gui",        action="store_true", help="Launch GUI interface")
    ap.add_argument("--verbose", "-v", action="store_true", help="Verbose tool output")
    ap.add_argument("--list-rules", action="store_true", help="List all loaded rules")
    args = ap.parse_args()

    if args.list_rules:
        engine = RuleEngine()
        print("Loaded rules:")
        for rule in engine.rules:
            print(f"  {rule.name:<35} priority={rule.priority}  trigger={rule.trigger}")
        return

    if args.gui:
        from utils.gui import startGUI
        startGUI()
        return

    if not args.file:
        ap.print_help()
        return

    run_rule_based_analysis(args.file, verbose=args.verbose)


if __name__ == "__main__":
    main()
