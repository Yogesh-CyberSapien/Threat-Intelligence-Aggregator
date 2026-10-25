"""
formatters.py — Output formatters: pretty table, JSON, CSV.
"""

import csv
import io
import json
from typing import List

from colorama import Fore, Style, init as colorama_init
from tabulate import tabulate

from aggregator import severity_label, SEVERITY_HIGH, SEVERITY_MEDIUM
from models import IoC

colorama_init(autoreset=True)

# Column order for table / CSV output
_TABLE_HEADERS = [
    "Type", "Value", "Score", "Severity",
    "Malicious", "Suspicious", "Sources",
    "Country", "ASN", "Pulses", "Labels",
]


def _row(ioc: IoC) -> list:
    sev = severity_label(ioc.threat_score)
    return [
        ioc.ioc_type.upper(),
        ioc.value[:60],                         # truncate very long URLs
        f"{ioc.threat_score:.1f}",
        sev,
        ioc.malicious_votes,
        ioc.suspicious_votes,
        ", ".join(ioc.sources),
        ioc.country or "—",
        ioc.asn or "—",
        ioc.pulse_count,
        ", ".join(ioc.threat_labels[:3]) or "—",   # show up to 3 labels
    ]


def _severity_colour(score: float) -> str:
    if score >= SEVERITY_HIGH:
        return Fore.RED
    if score >= SEVERITY_MEDIUM:
        return Fore.YELLOW
    if score > 0:
        return Fore.CYAN
    return Fore.GREEN


# ------------------------------------------------------------------
# Public formatters
# ------------------------------------------------------------------

def format_table(iocs: List[IoC], colour: bool = True) -> str:
    """Return a pretty-printed ASCII table."""
    rows = []
    for ioc in iocs:
        row = _row(ioc)
        if colour:
            c = _severity_colour(ioc.threat_score)
            row = [f"{c}{cell}{Style.RESET_ALL}" for cell in row]
        rows.append(row)

    if not rows:
        return "No IoCs found."

    return tabulate(rows, headers=_TABLE_HEADERS, tablefmt="rounded_outline")


def format_json(iocs: List[IoC], indent: int = 2) -> str:
    """Return JSON string of all IoCs."""
    return json.dumps([ioc.to_dict() for ioc in iocs], indent=indent, default=str)


def format_csv(iocs: List[IoC]) -> str:
    """Return CSV string of all IoCs."""
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(_TABLE_HEADERS)
    for ioc in iocs:
        writer.writerow(_row(ioc))
    return buf.getvalue()


def format_summary(iocs: List[IoC]) -> str:
    """Return a one-paragraph plaintext summary."""
    if not iocs:
        return "No IoCs to summarise."

    high   = sum(1 for i in iocs if i.threat_score >= SEVERITY_HIGH)
    medium = sum(1 for i in iocs if SEVERITY_MEDIUM <= i.threat_score < SEVERITY_HIGH)
    low    = sum(1 for i in iocs if 0 < i.threat_score < SEVERITY_MEDIUM)
    clean  = len(iocs) - high - medium - low

    types  = {}
    for i in iocs:
        types[i.ioc_type] = types.get(i.ioc_type, 0) + 1

    type_str = ", ".join(f"{v} {k}" for k, v in sorted(types.items()))

    lines = [
        f"{Fore.CYAN}=== Threat Intelligence Summary ==={Style.RESET_ALL}",
        f"Total unique IoCs : {len(iocs)}  ({type_str})",
        f"{Fore.RED}HIGH severity     : {high}{Style.RESET_ALL}",
        f"{Fore.YELLOW}MEDIUM severity   : {medium}{Style.RESET_ALL}",
        f"{Fore.CYAN}LOW severity      : {low}{Style.RESET_ALL}",
        f"{Fore.GREEN}CLEAN             : {clean}{Style.RESET_ALL}",
    ]
    return "\n".join(lines)
