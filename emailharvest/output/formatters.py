"""
Output formatters: plain text, JSON, CSV, and rich terminal table.
"""

import csv
import io
import json
import os
from datetime import datetime
from typing import Dict, Optional, Set


def _build_records(
    emails: Dict[str, Set[str]],
    domain: str,
    modules_used: list,
) -> list:
    """Flatten email->sources mapping into sortable record list."""
    records = []
    for email, sources in emails.items():
        records.append(
            {
                "email": email,
                "domain": email.split("@")[-1],
                "sources": sorted(sources),
                "source_count": len(sources),
            }
        )
    records.sort(key=lambda r: (r["domain"], r["email"]))
    return records


def to_plain(emails: Dict[str, Set[str]], **kwargs) -> str:
    """One email per line."""
    return "\n".join(sorted(emails.keys()))


def to_json(
    emails: Dict[str, Set[str]],
    domain: str = "",
    modules_used: Optional[list] = None,
    **kwargs,
) -> str:
    records = _build_records(emails, domain, modules_used or [])
    output = {
        "meta": {
            "target": domain,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "total": len(emails),
            "modules": modules_used or [],
        },
        "results": records,
    }
    return json.dumps(output, indent=2)


def to_csv(emails: Dict[str, Set[str]], domain: str = "", modules_used: Optional[list] = None, **kwargs) -> str:
    records = _build_records(emails, domain, modules_used or [])
    buf = io.StringIO()
    writer = csv.DictWriter(
        buf,
        fieldnames=["email", "domain", "source_count", "sources"],
        quoting=csv.QUOTE_ALL,
    )
    writer.writeheader()
    for rec in records:
        writer.writerow(
            {
                "email": rec["email"],
                "domain": rec["domain"],
                "source_count": rec["source_count"],
                "sources": "; ".join(rec["sources"]),
            }
        )
    return buf.getvalue()


def save(content: str, path: str) -> None:
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)
    print(f"[+] Saved to {path}")


def print_rich_table(
    emails: Dict[str, Set[str]],
    domain: str = "",
    modules_used: Optional[list] = None,
) -> None:
    """Print a formatted table using the rich library."""
    try:
        from rich.console import Console
        from rich.table import Table
        from rich import box
        from rich.text import Text

        console = Console()
        records = _build_records(emails, domain, modules_used or [])

        console.print()
        console.rule(f"[bold cyan]EmailHarvest Results — {domain or 'unknown'}")
        console.print(
            f"[green]Found [bold]{len(records)}[/bold] unique email(s)   "
            f"[dim]modules: {', '.join(modules_used or ['?'])}[/dim]"
        )
        console.print()

        table = Table(box=box.ROUNDED, show_lines=True, expand=False)
        table.add_column("#", style="dim", width=4)
        table.add_column("Email", style="bold cyan", min_width=30)
        table.add_column("Domain", style="yellow")
        table.add_column("Sources", style="dim", min_width=20)

        for i, rec in enumerate(records, 1):
            sources_str = "\n".join(
                s[:80] + ("…" if len(s) > 80 else "") for s in rec["sources"][:3]
            )
            if len(rec["sources"]) > 3:
                sources_str += f"\n[dim](+{len(rec['sources'])-3} more)[/dim]"
            table.add_row(str(i), rec["email"], rec["domain"], sources_str)

        console.print(table)
        console.print()

    except ImportError:
        # Fallback to plain output
        print("\n=== EmailHarvest Results ===")
        for i, email in enumerate(sorted(emails.keys()), 1):
            print(f"  {i:3d}. {email}")
        print(f"\nTotal: {len(emails)}\n")
