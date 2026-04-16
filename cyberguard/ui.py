"""Terminal UI components and display utilities."""
import logging
from typing import Any, Dict, List, Optional, Tuple

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from cyberguard.constants import APP_NAME, VERSION, Severity

_log = logging.getLogger("cyberguard")

console = Console()

class UI:
    """Rich-based terminal UI: banners, tables, panels, menus."""

    BANNER = r"""
   ______      __              ______                     __
  / ____/_  __/ /_  ___  _____/ ____/_  ______ __________/ /
 / /   / / / / __ \/ _ \/ ___/ / __/ / / / __ `/ ___/ __  /
/ /___/ /_/ / /_/ /  __/ /  / /_/ / /_/ / /_/ / /  / /_/ /
\____/\__, /_.___/\___/_/   \____/\__,_/\__,_/_/   \__,_/
     /____/           Professional Security Toolkit v{}
"""

    @staticmethod
    def show_banner():
        banner_text = UI.BANNER.format(VERSION)
        panel = Panel(
            Text(banner_text, style="bold cyan"),
            border_style="bright_blue",
            box=box.DOUBLE,
            padding=(0, 2),
        )
        console.print(panel)

    @staticmethod
    def print_success(msg: str):
        console.print(f"  [bold green]✓[/bold green] {msg}")

    @staticmethod
    def print_error(msg: str):
        console.print(f"  [bold red]✗[/bold red] {msg}")

    @staticmethod
    def print_warning(msg: str):
        console.print(f"  [bold yellow]![/bold yellow] {msg}")

    @staticmethod
    def print_info(msg: str):
        console.print(f"  [bold blue]ℹ[/bold blue] {msg}")

    @staticmethod
    def print_section(title: str):
        console.print(f"\n[bold cyan]{'─' * 60}[/bold cyan]")
        console.print(f"[bold cyan]  {title}[/bold cyan]")
        console.print(f"[bold cyan]{'─' * 60}[/bold cyan]")

    @staticmethod
    def print_subsection(title: str):
        console.print(f"\n  [bold yellow]▸ {title}[/bold yellow]")

    @staticmethod
    def print_finding(severity: str, title: str, details: str = ""):
        colors = {"CRITICAL": "red", "HIGH": "bright_red", "MEDIUM": "yellow", "LOW": "green"}
        color = colors.get(severity, "white")
        console.print(f"  [{color}][{severity}][/{color}] {title}")
        if details:
            console.print(f"          {details}")

    @staticmethod
    def print_check(status: str, title: str, details: str = ""):
        if status == "PASS":
            console.print(f"  [green]✓ PASS[/green]  {title}")
        else:
            console.print(f"  [red]✗ FAIL[/red]  {title}")
        if details:
            console.print(f"           [dim]{details}[/dim]")

    @staticmethod
    def print_table(title: str, columns: List[Tuple[str, str]], rows: List[List[str]],
                    show_lines: bool = False):
        if not rows:
            UI.print_warning(f"No data for: {title}")
            return
        table = Table(title=title, box=box.ROUNDED, show_lines=show_lines,
                      title_style="bold cyan", border_style="bright_blue")
        for col_name, col_style in columns:
            table.add_column(col_name, style=col_style)
        for row in rows:
            table.add_row(*[str(c) for c in row])
        console.print(table)

    @staticmethod
    def print_key_value(data: Dict[str, Any], title: str = ""):
        table = Table(box=box.SIMPLE, show_header=False, border_style="bright_blue",
                      title=title if title else None, title_style="bold cyan")
        table.add_column("Key", style="bold yellow", min_width=20)
        table.add_column("Value", style="white")
        for k, v in data.items():
            table.add_row(str(k), str(v))
        console.print(table)

    @staticmethod
    def print_score_panel(score: float, grade: str, title: str = "Security Score"):
        colors = {"A": "green", "B": "bright_green", "C": "yellow", "D": "bright_red", "F": "red"}
        color = colors.get(grade, "white")
        text = Text(f"\n  {score}/100  Grade: {grade}\n", style=f"bold {color}")
        panel = Panel(text, title=title, border_style=color, box=box.DOUBLE)
        console.print(panel)

    @staticmethod
    def print_summary_panel(data: Dict[str, Any], title: str):
        lines = []
        for k, v in data.items():
            lines.append(f"  [bold yellow]{k}:[/bold yellow] {v}")
        content = "\n".join(lines)
        panel = Panel(content, title=title, border_style="bright_blue", box=box.DOUBLE)
        console.print(panel)

    @staticmethod
    def ask_menu(title: str, choices: List[str]) -> Optional[str]:
        try:
            return questionary.select(title, choices=choices).ask()
        except (KeyboardInterrupt, EOFError):
            return None

    @staticmethod
    def ask_input(prompt: str, validate: callable = None) -> Optional[str]:
        try:
            val = Prompt.ask(f"  {prompt}")
            if validate and val and not validate(val):
                UI.print_error("Invalid input")
                return None
            return val
        except (KeyboardInterrupt, EOFError):
            return None

    @staticmethod
    def confirm(prompt: str) -> bool:
        try:
            return Confirm.ask(f"  {prompt}")
        except (KeyboardInterrupt, EOFError):
            return False

    @staticmethod
    def print_port_scan_results(target: str, results: List[dict]):
        if not results:
            UI.print_warning(f"No open ports found on {target}")
            return
        table = Table(title=f"Port Scan Results: {target}", box=box.ROUNDED,
                      title_style="bold cyan", border_style="bright_blue")
        table.add_column("Port", style="bold yellow")
        table.add_column("State", style="green")
        table.add_column("Service", style="white")
        table.add_column("Banner", style="dim")
        for r in results:
            table.add_row(
                str(r.get("port", "")),
                r.get("state", "open"),
                r.get("service", "unknown"),
                r.get("banner", "")[:60],
            )
        console.print(table)

    @staticmethod
    def print_dns_results(domain: str, records: Dict[str, List]):
        table = Table(title=f"DNS Records: {domain}", box=box.ROUNDED,
                      title_style="bold cyan", border_style="bright_blue")
        table.add_column("Type", style="bold yellow")
        table.add_column("Value", style="white")
        for rtype, values in records.items():
            for v in values:
                table.add_row(rtype, str(v))
        console.print(table)

    @staticmethod
    def print_connections_table(connections: List[dict]):
        if not connections:
            UI.print_warning("No connections found")
            return
        table = Table(title="Network Connections", box=box.ROUNDED,
                      title_style="bold cyan", border_style="bright_blue")
        table.add_column("Proto", style="bold")
        table.add_column("Local Address", style="cyan")
        table.add_column("Remote Address", style="yellow")
        table.add_column("State", style="green")
        table.add_column("PID/Process", style="white")
        for c in connections[:100]:
            state_style = "red" if c.get("suspicious") else "green"
            table.add_row(
                c.get("proto", ""),
                c.get("local", ""),
                c.get("remote", ""),
                f"[{state_style}]{c.get('state', '')}[/{state_style}]",
                c.get("process", ""),
            )
        console.print(table)

    @staticmethod
    def print_process_table(processes: List[dict]):
        if not processes:
            return
        table = Table(title="Suspicious Processes", box=box.ROUNDED,
                      title_style="bold red", border_style="red")
        table.add_column("PID", style="bold yellow")
        table.add_column("User", style="cyan")
        table.add_column("CPU%", style="white")
        table.add_column("MEM%", style="white")
        table.add_column("Command", style="white")
        table.add_column("Reason", style="red")
        for p in processes[:50]:
            table.add_row(
                str(p.get("pid", "")),
                p.get("user", ""),
                f"{p.get('cpu', 0):.1f}",
                f"{p.get('mem', 0):.1f}",
                p.get("cmd", "")[:60],
                p.get("reason", ""),
            )
        console.print(table)

    @staticmethod
    def print_log_events(events: List[dict], title: str = "Log Events"):
        if not events:
            UI.print_warning(f"No events found for: {title}")
            return
        table = Table(title=title, box=box.ROUNDED,
                      title_style="bold cyan", border_style="bright_blue")
        table.add_column("Time", style="dim")
        table.add_column("Source", style="bold yellow")
        table.add_column("Severity", style="white")
        table.add_column("Message", style="white")
        for e in events[:100]:
            sev = e.get("severity", Severity.INFO)
            colors = {"CRITICAL": "red", "HIGH": "bright_red", "MEDIUM": "yellow",
                      "LOW": "green", "INFO": "blue"}
            color = colors.get(sev, "white")
            table.add_row(
                e.get("timestamp", ""),
                e.get("source", ""),
                f"[{color}]{sev}[/{color}]",
                e.get("message", "")[:80],
            )
        console.print(table)

    @staticmethod
    def print_remediation_table(items: List[dict]):
        if not items:
            UI.print_info("No remediation items")
            return
        table = Table(title="Remediation Tracker", box=box.ROUNDED,
                      title_style="bold cyan", border_style="bright_blue")
        table.add_column("ID", style="bold")
        table.add_column("Severity", style="white")
        table.add_column("Title", style="white")
        table.add_column("Status", style="white")
        table.add_column("Due Date", style="dim")
        for item in items:
            sev = item.get("severity", Severity.LOW)
            colors = {"CRITICAL": "red", "HIGH": "bright_red", "MEDIUM": "yellow", "LOW": "green"}
            color = colors.get(sev, "white")
            st = item.get("status", "open")
            st_color = "green" if st == "resolved" else "yellow" if st == "in-progress" else "red"
            table.add_row(
                str(item.get("id", "")),
                f"[{color}]{sev}[/{color}]",
                item.get("title", "")[:50],
                f"[{st_color}]{st}[/{st_color}]",
                item.get("due_date", "N/A"),
            )
        console.print(table)

    @staticmethod
    def print_threat_intel(data: dict, source: str):
        """Display threat intelligence results."""
        panel_data = {}
        if source == "virustotal":
            attrs = data.get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            panel_data = {
                "Owner": attrs.get("as_owner", "N/A"),
                "ASN": attrs.get("asn", "N/A"),
                "Country": attrs.get("country", "N/A"),
                "Malicious": stats.get("malicious", 0),
                "Suspicious": stats.get("suspicious", 0),
                "Harmless": stats.get("harmless", 0),
                "Undetected": stats.get("undetected", 0),
                "Reputation": attrs.get("reputation", "N/A"),
            }
        elif source == "abuseipdb":
            d = data.get("data", {})
            panel_data = {
                "IP": d.get("ipAddress", "N/A"),
                "Abuse Score": f"{d.get('abuseConfidenceScore', 0)}%",
                "ISP": d.get("isp", "N/A"),
                "Country": d.get("countryCode", "N/A"),
                "Domain": d.get("domain", "N/A"),
                "Total Reports": d.get("totalReports", 0),
                "Distinct Users": d.get("numDistinctUsers", 0),
                "Whitelisted": d.get("isWhitelisted", False),
            }
        UI.print_key_value(panel_data, f"Threat Intelligence: {source.upper()}")


# ═══════════════════════════════════════════════════════════════════════════
# CYBERGUARD TOOLKIT (Main Class)
# ═══════════════════════════════════════════════════════════════════════════
