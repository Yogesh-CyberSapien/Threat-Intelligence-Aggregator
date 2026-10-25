"""
main.py — Threat Intelligence Aggregator CLI

Usage examples
--------------
# Query a single IP from both sources
python main.py --type ip --values 8.8.8.8

# Query multiple domains, output as JSON
python main.py --type domain --values evil.com bad-actor.net --format json

# Query file hashes, save CSV report
python main.py --type hash --values d41d8cd98f00b204e9800998ecf8427e --format csv --output report.csv

# Pull latest subscribed OTX pulses (no --values needed)
python main.py --pulses --limit 10 --format table

# Use only one source
python main.py --type ip --values 1.2.3.4 --sources virustotal
python main.py --type ip --values 1.2.3.4 --sources alienvault

# Filter by minimum threat score
python main.py --type domain --values evil.com --min-score 50
"""

import argparse
import logging
import sys
from typing import List

from config import Config
from aggregator import aggregate
from formatters import format_table, format_json, format_csv, format_summary
from models import IoC


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="threat-intel",
        description="Threat Intelligence Aggregator — pulls live IoCs from VirusTotal & AlienVault OTX",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )

    # --- Target selection ---
    group = p.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--type", "-t",
        choices=["ip", "domain", "url", "hash"],
        dest="ioc_type",
        help="IoC type to query",
    )
    group.add_argument(
        "--pulses",
        action="store_true",
        help="Fetch IoCs from latest subscribed AlienVault OTX pulses",
    )

    p.add_argument(
        "--values", "-v",
        nargs="+",
        metavar="INDICATOR",
        help="One or more IoC values (IPs, domains, hashes, URLs)",
    )

    # --- Source selection ---
    p.add_argument(
        "--sources", "-s",
        nargs="+",
        choices=["virustotal", "alienvault"],
        default=["virustotal", "alienvault"],
        help="Which sources to query (default: both)",
    )

    # --- OTX pulse options ---
    p.add_argument(
        "--limit", "-l",
        type=int,
        default=5,
        metavar="N",
        help="Number of OTX pulses to fetch when using --pulses (default: 5)",
    )

    # --- Output options ---
    p.add_argument(
        "--format", "-f",
        choices=["table", "json", "csv", "summary"],
        default="table",
        dest="output_format",
        help="Output format (default: table)",
    )
    p.add_argument(
        "--output", "-o",
        metavar="FILE",
        help="Write output to FILE instead of stdout",
    )
    p.add_argument(
        "--min-score",
        type=float,
        default=0.0,
        metavar="SCORE",
        help="Only show IoCs with threat_score >= SCORE",
    )
    p.add_argument(
        "--no-colour",
        action="store_true",
        help="Disable ANSI colour codes in table output",
    )

    # --- Logging ---
    p.add_argument(
        "--verbose", "-V",
        action="store_true",
        help="Enable verbose (DEBUG) logging",
    )

    return p


def collect_iocs(args: argparse.Namespace) -> List[IoC]:
    """Run the requested queries and return a flat list of raw IoCs."""
    raw: List[IoC] = []

    if args.pulses:
        # AlienVault pulse mode — no --values needed
        from alienvault_client import AlienVaultClient
        client = AlienVaultClient()
        print(f"[*] Fetching {args.limit} latest OTX pulses …", file=sys.stderr)
        raw.extend(client.fetch_subscribed_pulses(limit=args.limit))
        return raw

    if not args.values:
        print("error: --values is required when --type is specified.", file=sys.stderr)
        sys.exit(1)

    # Per-source queries
    if "virustotal" in args.sources:
        from virustotal_client import VirusTotalClient
        vt = VirusTotalClient()
        print(
            f"[*] VirusTotal: querying {len(args.values)} {args.ioc_type}(s) …",
            file=sys.stderr,
        )
        raw.extend(vt.fetch_iocs(args.ioc_type, args.values))

    if "alienvault" in args.sources:
        from alienvault_client import AlienVaultClient
        otx = AlienVaultClient()
        print(
            f"[*] AlienVault OTX: querying {len(args.values)} {args.ioc_type}(s) …",
            file=sys.stderr,
        )
        raw.extend(otx.fetch_iocs(args.ioc_type, args.values))

    return raw


def render(iocs: List[IoC], args: argparse.Namespace) -> str:
    colour = not args.no_colour
    fmt = args.output_format

    if fmt == "table":
        return format_summary(iocs) + "\n\n" + format_table(iocs, colour=colour)
    if fmt == "json":
        return format_json(iocs)
    if fmt == "csv":
        return format_csv(iocs)
    if fmt == "summary":
        return format_summary(iocs)
    return format_table(iocs, colour=colour)


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    # Configure logging
    level = logging.DEBUG if args.verbose else logging.WARNING
    logging.basicConfig(
        level=level,
        format="%(levelname)s %(name)s: %(message)s",
        stream=sys.stderr,
    )

    # Validate API keys
    try:
        Config.validate()
    except EnvironmentError as exc:
        print(f"[!] Configuration error: {exc}", file=sys.stderr)
        sys.exit(1)

    # Collect IoCs
    raw = collect_iocs(args)
    if not raw:
        print("[!] No IoCs returned from any source.", file=sys.stderr)
        sys.exit(0)

    # Aggregate (deduplicate + merge)
    iocs = aggregate(raw)

    # Filter by minimum score
    if args.min_score > 0:
        before = len(iocs)
        iocs = [i for i in iocs if i.threat_score >= args.min_score]
        print(
            f"[*] Filtered {before - len(iocs)} IoCs below score {args.min_score:.1f}",
            file=sys.stderr,
        )

    # Render output
    output = render(iocs, args)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            # Strip ANSI codes when writing to file
            import re
            clean = re.sub(r"\x1b\[[0-9;]*m", "", output)
            fh.write(clean)
        print(f"[+] Report written to {args.output}", file=sys.stderr)
    else:
        print(output)


if __name__ == "__main__":
    main()
