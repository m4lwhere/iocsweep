"""
IOCSweep CLI - Advanced PCAP Intelligence Extraction & IOC Hunting Tool

Maximum Intel Value for Security Analysts.
"""

from __future__ import annotations

import sys
from datetime import datetime
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.panel import Panel
from rich.progress import (
    Progress,
    SpinnerColumn,
    TextColumn,
    BarColumn,
    TaskProgressColumn,
    TimeElapsedColumn,
)
from rich.table import Table
from rich.text import Text
from rich.tree import Tree
from rich import box

from iocsweep import __version__
from iocsweep.core import IOCSweep
from iocsweep.models import Severity

console = Console()


BANNER = r'''
[bold cyan]
  ___  ___   ___  ___
 |_ _|/ _ \ / __/ __|_      _____  ___ _ __
  | || | | | (__\__ \ \ /\ / / _ \/ _ \ '_ \
  | || |_| |\___|___/\ V  V /  __/  __/ |_) |
 |___|\___/          \_/\_/ \___|\___| .__/
                                     |_|
[/bold cyan]
[dim]Advanced PCAP Intelligence Extraction & IOC Hunting[/dim]
[dim]Version {version}[/dim]
'''.format(version=__version__)


def print_banner():
    """Print the banner."""
    console.print(BANNER)


@click.group(invoke_without_command=True)
@click.version_option(version=__version__, prog_name='iocsweep')
@click.pass_context
def main(ctx):
    """
    IOCSweep - Extract MAXIMUM INTEL VALUE from network captures.

    Advanced PCAP analysis tool for threat hunting and incident response.
    """
    if ctx.invoked_subcommand is None:
        print_banner()
        console.print("\nRun [bold cyan]iocsweep --help[/] for usage information.\n")


@main.command()
@click.argument('pcap_file', type=click.Path(exists=True, path_type=Path))
@click.option('-i', '--ioc-file', type=click.Path(exists=True, path_type=Path),
              help='IOC file to match against (one IOC per line)')
@click.option('-o', '--output', type=click.Path(path_type=Path),
              help='Output file path')
@click.option('--format', 'output_format', type=click.Choice(['json', 'csv', 'html', 'stix', 'all']),
              default='json', help='Output format')
@click.option('--geo/--no-geo', default=True, help='Enable geolocation lookups')
@click.option('--files/--no-files', 'extract_files', default=True,
              help='Extract files from traffic')
@click.option('--creds/--no-creds', 'extract_creds', default=True,
              help='Extract credentials from traffic')
@click.option('--beacons/--no-beacons', 'detect_beacons', default=True,
              help='Detect C2 beacon patterns')
@click.option('--exfil/--no-exfil', 'detect_exfil', default=True,
              help='Detect data exfiltration')
@click.option('--maxmind', type=click.Path(exists=True, path_type=Path),
              help='Path to MaxMind GeoIP database')
@click.option('--yara', type=click.Path(exists=True, path_type=Path),
              help='Path to YARA rules file/directory')
@click.option('-q', '--quiet', is_flag=True, help='Minimal output')
@click.option('-v', '--verbose', is_flag=True, help='Verbose output')
def analyze(
    pcap_file: Path,
    ioc_file: Optional[Path],
    output: Optional[Path],
    output_format: str,
    geo: bool,
    extract_files: bool,
    extract_creds: bool,
    detect_beacons: bool,
    detect_exfil: bool,
    maxmind: Optional[Path],
    yara: Optional[Path],
    quiet: bool,
    verbose: bool,
):
    """
    Analyze a PCAP file and extract intelligence.

    PCAP_FILE is the path to the packet capture file to analyze.
    """
    if not quiet:
        print_banner()

    # Validate output path
    if output is None:
        output = pcap_file.with_suffix(f'.{output_format}' if output_format != 'all' else '.analysis')

    console.print(f"\n[bold green]Analyzing:[/] {pcap_file}")
    console.print(f"[bold green]Output:[/] {output}\n")

    # Progress callback
    def progress_callback(current: int, total: int):
        if not quiet:
            pct = (current / total) * 100 if total > 0 else 0
            console.print(f"\r[cyan]Progress:[/] {pct:.1f}%", end='')

    # Create analyzer
    analyzer = IOCSweep(
        ioc_file=ioc_file,
        enable_geo=geo,
        enable_file_extraction=extract_files,
        enable_credential_extraction=extract_creds,
        enable_beacon_detection=detect_beacons,
        enable_exfil_detection=detect_exfil,
        maxmind_db_path=maxmind,
        yara_rules_path=yara,
        progress_callback=progress_callback if not quiet else None,
    )

    # Run analysis with progress
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        TimeElapsedColumn(),
        console=console,
        disable=quiet,
    ) as progress:
        task = progress.add_task("[cyan]Analyzing PCAP...", total=None)

        try:
            result = analyzer.analyze(pcap_file)
            progress.update(task, completed=100, total=100)
        except Exception as e:
            console.print(f"\n[bold red]Error:[/] {e}")
            sys.exit(1)

    console.print("\n")

    # Display results
    if not quiet:
        display_summary(result)

        if result.ioc_matches:
            display_ioc_matches(result)

        if result.suspicious_activities:
            display_suspicious_activities(result)

        if result.beacon_patterns and any(b.is_likely_beacon for b in result.beacon_patterns):
            display_beacons(result)

        if result.exfiltration_suspects:
            display_exfil(result)

        if verbose:
            display_details(result)

    # Export results
    export_results(result, output, output_format)

    console.print(f"\n[bold green]Analysis complete![/] Results saved to {output}\n")

    # Exit with code based on findings
    if result.ioc_matches or any(a.severity == Severity.CRITICAL for a in result.suspicious_activities):
        sys.exit(1)  # Critical findings
    sys.exit(0)


def display_summary(result):
    """Display analysis summary."""
    severity_counts = result.get_severity_counts()

    # Summary panel
    summary_text = Text()
    summary_text.append(f"PCAP: ", style="dim")
    summary_text.append(f"{result.pcap_file}\n", style="bold")
    summary_text.append(f"Duration: ", style="dim")
    summary_text.append(f"{result.analysis_duration_seconds:.2f}s\n", style="bold")
    summary_text.append(f"Packets: ", style="dim")
    summary_text.append(f"{result.total_packets:,}\n", style="bold cyan")
    summary_text.append(f"Traffic: ", style="dim")
    summary_text.append(f"{format_bytes(result.total_bytes)}\n", style="bold cyan")

    console.print(Panel(summary_text, title="[bold]Analysis Summary[/]", border_style="cyan"))

    # Stats table
    table = Table(title="Intelligence Extraction Results", box=box.ROUNDED)
    table.add_column("Metric", style="cyan")
    table.add_column("Count", justify="right", style="bold")
    table.add_column("Status", justify="center")

    # Add rows
    table.add_row(
        "Unique Source IPs",
        str(len(result.unique_src_ips)),
        "[green]OK[/]"
    )
    table.add_row(
        "Unique Destination IPs",
        str(len(result.unique_dst_ips)),
        "[green]OK[/]"
    )
    table.add_row(
        "Unique Domains",
        str(len(result.unique_domains)),
        "[green]OK[/]"
    )
    table.add_row(
        "Network Connections",
        str(len(result.connections)),
        "[green]OK[/]"
    )
    table.add_row(
        "DNS Queries",
        str(len(result.dns_records)),
        "[yellow]REVIEW[/]" if any(d.is_suspicious for d in result.dns_records) else "[green]OK[/]"
    )
    table.add_row(
        "HTTP Transactions",
        str(len(result.http_transactions)),
        "[yellow]REVIEW[/]" if any(h.is_suspicious for h in result.http_transactions) else "[green]OK[/]"
    )
    table.add_row(
        "TLS Sessions",
        str(len(result.tls_sessions)),
        "[yellow]REVIEW[/]" if any(t.is_suspicious for t in result.tls_sessions) else "[green]OK[/]"
    )
    table.add_row(
        "Extracted Files",
        str(len(result.files)),
        "[red]ALERT[/]" if any(f.is_suspicious for f in result.files) else "[green]OK[/]"
    )
    table.add_row(
        "Extracted Credentials",
        str(len(result.credentials)),
        "[red]ALERT[/]" if result.credentials else "[green]NONE[/]"
    )
    table.add_row("", "", "")
    table.add_row(
        "[bold]IOC Matches[/]",
        f"[bold red]{len(result.ioc_matches)}[/]" if result.ioc_matches else "[green]0[/]",
        "[red]ALERT[/]" if result.ioc_matches else "[green]CLEAN[/]"
    )
    table.add_row(
        "[bold]Suspicious Activities[/]",
        f"[bold yellow]{len(result.suspicious_activities)}[/]" if result.suspicious_activities else "[green]0[/]",
        "[yellow]REVIEW[/]" if result.suspicious_activities else "[green]CLEAN[/]"
    )
    table.add_row(
        "[bold]Beacon Patterns[/]",
        f"[bold red]{len([b for b in result.beacon_patterns if b.is_likely_beacon])}[/]",
        "[red]ALERT[/]" if any(b.is_likely_beacon for b in result.beacon_patterns) else "[green]NONE[/]"
    )
    table.add_row(
        "[bold]Exfil Suspects[/]",
        f"[bold red]{len(result.exfiltration_suspects)}[/]" if result.exfiltration_suspects else "[green]0[/]",
        "[red]ALERT[/]" if result.exfiltration_suspects else "[green]NONE[/]"
    )

    console.print(table)

    # Severity breakdown
    if any(severity_counts.values()):
        sev_table = Table(title="Threat Severity Breakdown", box=box.SIMPLE)
        sev_table.add_column("Severity", style="bold")
        sev_table.add_column("Count", justify="right")

        for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
            count = severity_counts.get(sev, 0)
            if count > 0:
                color = {
                    Severity.CRITICAL: "red bold",
                    Severity.HIGH: "red",
                    Severity.MEDIUM: "yellow",
                    Severity.LOW: "blue",
                    Severity.INFO: "dim",
                }[sev]
                sev_table.add_row(f"[{color}]{sev.value.upper()}[/]", str(count))

        console.print(sev_table)


def display_ioc_matches(result):
    """Display IOC matches."""
    console.print("\n[bold red]IOC MATCHES DETECTED[/]\n")

    table = Table(box=box.ROUNDED, border_style="red")
    table.add_column("Type", style="cyan")
    table.add_column("Value", style="bold")
    table.add_column("Severity", justify="center")
    table.add_column("Found In")
    table.add_column("Context")

    for match in result.ioc_matches:
        severity_color = {
            Severity.CRITICAL: "red bold",
            Severity.HIGH: "red",
            Severity.MEDIUM: "yellow",
            Severity.LOW: "blue",
            Severity.INFO: "dim",
        }.get(match.severity, "white")

        table.add_row(
            match.ioc_type.value,
            match.ioc_value,
            f"[{severity_color}]{match.severity.value.upper()}[/]",
            match.matched_in,
            match.context or "-"
        )

    console.print(table)


def display_suspicious_activities(result):
    """Display suspicious activities."""
    console.print("\n[bold yellow]SUSPICIOUS ACTIVITIES[/]\n")

    for activity in result.suspicious_activities[:20]:
        severity_color = {
            Severity.CRITICAL: "red",
            Severity.HIGH: "red",
            Severity.MEDIUM: "yellow",
            Severity.LOW: "blue",
            Severity.INFO: "dim",
        }.get(activity.severity, "white")

        panel_text = Text()
        panel_text.append(f"{activity.description}\n\n", style="bold")

        if activity.src_ip:
            panel_text.append(f"Source: ", style="dim")
            panel_text.append(f"{activity.src_ip}\n", style="cyan")
        if activity.dst_ip:
            panel_text.append(f"Destination: ", style="dim")
            panel_text.append(f"{activity.dst_ip}\n", style="cyan")
        if activity.port:
            panel_text.append(f"Port: ", style="dim")
            panel_text.append(f"{activity.port}\n")

        if activity.mitre_techniques:
            panel_text.append(f"\nMITRE ATT&CK: ", style="dim")
            panel_text.append(", ".join(activity.mitre_techniques), style="magenta")

        if activity.evidence:
            panel_text.append(f"\n\nEvidence: ", style="dim")
            panel_text.append("\n".join(f"  - {e}" for e in activity.evidence))

        console.print(Panel(
            panel_text,
            title=f"[{severity_color}][{activity.severity.value.upper()}] {activity.activity_type}[/]",
            border_style=severity_color
        ))


def display_beacons(result):
    """Display beacon patterns."""
    likely_beacons = [b for b in result.beacon_patterns if b.is_likely_beacon]
    if not likely_beacons:
        return

    console.print("\n[bold red]POTENTIAL C2 BEACONS DETECTED[/]\n")

    table = Table(box=box.ROUNDED, border_style="red")
    table.add_column("Destination", style="cyan")
    table.add_column("Port", justify="right")
    table.add_column("Interval", justify="right")
    table.add_column("Jitter", justify="right")
    table.add_column("Connections", justify="right")
    table.add_column("Confidence", justify="center")

    for beacon in likely_beacons[:10]:
        conf_pct = int(beacon.confidence * 100)
        conf_color = "green" if conf_pct >= 80 else "yellow" if conf_pct >= 50 else "red"

        table.add_row(
            beacon.dst_ip,
            str(beacon.dst_port),
            f"{beacon.interval_mean:.1f}s",
            f"{beacon.jitter_percent:.1f}%",
            str(beacon.connection_count),
            f"[{conf_color}]{conf_pct}%[/]"
        )

    console.print(table)


def display_exfil(result):
    """Display potential data exfiltration."""
    if not result.exfiltration_suspects:
        return

    console.print("\n[bold red]POTENTIAL DATA EXFILTRATION[/]\n")

    table = Table(box=box.ROUNDED, border_style="red")
    table.add_column("Destination", style="cyan")
    table.add_column("Port", justify="right")
    table.add_column("Sent", justify="right", style="bold")
    table.add_column("Received", justify="right")
    table.add_column("Ratio", justify="right")
    table.add_column("Protocol")
    table.add_column("Reason")

    for exfil in result.exfiltration_suspects[:10]:
        ratio_str = f"{exfil.ratio:.1f}:1" if exfil.ratio != float('inf') else "inf"

        table.add_row(
            exfil.dst_ip,
            str(exfil.dst_port),
            format_bytes(exfil.bytes_sent),
            format_bytes(exfil.bytes_received),
            ratio_str,
            exfil.protocol.value,
            exfil.suspicion_reasons[0] if exfil.suspicion_reasons else "-"
        )

    console.print(table)


def display_details(result):
    """Display detailed extraction results."""
    console.print("\n[bold cyan]EXTRACTED INTELLIGENCE[/]\n")

    # Create tree view
    tree = Tree("[bold]Extracted IOCs[/]")

    # IPs
    ip_branch = tree.add(f"[cyan]IP Addresses ({len(result.extracted_ips)})[/]")
    for ip in sorted(result.extracted_ips)[:20]:
        ip_branch.add(ip)
    if len(result.extracted_ips) > 20:
        ip_branch.add(f"[dim]... and {len(result.extracted_ips) - 20} more[/]")

    # Domains
    domain_branch = tree.add(f"[cyan]Domains ({len(result.extracted_domains)})[/]")
    for domain in sorted(result.extracted_domains)[:20]:
        domain_branch.add(domain)
    if len(result.extracted_domains) > 20:
        domain_branch.add(f"[dim]... and {len(result.extracted_domains) - 20} more[/]")

    # JA3
    if result.extracted_ja3_hashes:
        ja3_branch = tree.add(f"[cyan]JA3 Hashes ({len(result.extracted_ja3_hashes)})[/]")
        for ja3 in sorted(result.extracted_ja3_hashes)[:10]:
            ja3_branch.add(ja3)

    # User Agents
    if result.extracted_user_agents:
        ua_branch = tree.add(f"[cyan]User Agents ({len(result.extracted_user_agents)})[/]")
        for ua in sorted(result.extracted_user_agents)[:10]:
            ua_branch.add(ua[:80] + "..." if len(ua) > 80 else ua)

    console.print(tree)


def export_results(result, output: Path, format: str):
    """Export results to specified format."""
    from iocsweep.exporters import JSONExporter, CSVExporter, STIXExporter, HTMLExporter

    if format == 'all':
        output.mkdir(parents=True, exist_ok=True)

        JSONExporter().export(result, output / 'analysis.json')
        CSVExporter().export_all(result, output / 'csv')
        HTMLExporter().export(result, output / 'report.html')
        STIXExporter().export(result, output / 'stix.json')

        console.print(f"[green]Exported all formats to {output}/[/]")

    elif format == 'json':
        JSONExporter().export(result, output)

    elif format == 'csv':
        output.mkdir(parents=True, exist_ok=True)
        CSVExporter().export_all(result, output)

    elif format == 'html':
        HTMLExporter().export(result, output)

    elif format == 'stix':
        STIXExporter().export(result, output)


@main.command()
@click.argument('pcap_file', type=click.Path(exists=True, path_type=Path))
@click.option('-o', '--output', type=click.Path(path_type=Path),
              help='Output file path')
def dns(pcap_file: Path, output: Optional[Path]):
    """
    Extract and dump DNS queries from PCAP.

    Quick extraction mode for DNS analysis.
    """
    print_banner()
    console.print(f"\n[bold green]Extracting DNS from:[/] {pcap_file}\n")

    analyzer = IOCSweep(
        enable_geo=False,
        enable_file_extraction=False,
        enable_credential_extraction=False,
        enable_beacon_detection=False,
        enable_exfil_detection=False,
    )

    result = analyzer.analyze(pcap_file)

    table = Table(title="DNS Queries", box=box.ROUNDED)
    table.add_column("Query", style="cyan")
    table.add_column("Type")
    table.add_column("Response")
    table.add_column("Entropy", justify="right")
    table.add_column("Suspicious", justify="center")

    for dns in result.dns_records[:100]:
        suspicious = "[red]YES[/]" if dns.is_suspicious else "[green]NO[/]"
        table.add_row(
            dns.query_name,
            dns.query_type,
            ", ".join(dns.response_data) if dns.response_data else "-",
            f"{dns.entropy:.2f}" if dns.entropy else "-",
            suspicious
        )

    console.print(table)

    if output:
        from iocsweep.exporters import JSONExporter
        JSONExporter().export(result, output)
        console.print(f"\n[green]Saved to {output}[/]")


@main.command()
@click.argument('pcap_file', type=click.Path(exists=True, path_type=Path))
@click.option('-o', '--output', type=click.Path(path_type=Path),
              help='Output directory for extracted files')
def extract(pcap_file: Path, output: Optional[Path]):
    """
    Extract files from PCAP.

    Carves files from network traffic.
    """
    print_banner()
    console.print(f"\n[bold green]Extracting files from:[/] {pcap_file}\n")

    analyzer = IOCSweep(
        enable_geo=False,
        enable_file_extraction=True,
        enable_credential_extraction=False,
        enable_beacon_detection=False,
        enable_exfil_detection=False,
    )

    result = analyzer.analyze(pcap_file)

    if not result.files:
        console.print("[yellow]No files extracted from traffic.[/]")
        return

    table = Table(title=f"Extracted Files ({len(result.files)})", box=box.ROUNDED)
    table.add_column("Filename", style="cyan")
    table.add_column("Type")
    table.add_column("Size", justify="right")
    table.add_column("SHA256")
    table.add_column("Suspicious", justify="center")

    for f in result.files:
        suspicious = "[red]YES[/]" if f.is_suspicious else "[green]NO[/]"
        table.add_row(
            f.filename or "unknown",
            f.magic_type or f.content_type or "unknown",
            format_bytes(f.size),
            f.sha256[:16] + "..." if f.sha256 else "-",
            suspicious
        )

    console.print(table)

    if output:
        output.mkdir(parents=True, exist_ok=True)
        for i, f in enumerate(result.files):
            if f.data:
                fname = f.filename or f"file_{i}.bin"
                fpath = output / fname
                fpath.write_bytes(f.data)
        console.print(f"\n[green]Saved {len(result.files)} files to {output}[/]")


def format_bytes(bytes_val: int) -> str:
    """Format bytes in human-readable form."""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if bytes_val < 1024:
            return f'{bytes_val:.1f} {unit}'
        bytes_val /= 1024
    return f'{bytes_val:.1f} PB'


if __name__ == '__main__':
    main()
