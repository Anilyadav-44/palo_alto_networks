"""
Project Unit42-FirmwareX — Sample Firmware CLI Analysis Runner
Executes an end-to-end security analysis run and prints diagnostic reports.
"""

import sys
import json
from pathlib import Path

# Add project root to path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from firmwarex.pipeline.orchestrator import FirmwareAnalysisPipeline
from firmwarex.config import settings

console = Console()

def main():
    console.print(Panel.fit(
        "[bold red]Unit42-FirmwareX[/bold red] — Automated IoT Vulnerability Analysis Engine\n"
        "[italic white]Palo Alto Networks // Unit 42 Threat Research[/italic white]",
        border_style="red"
    ))

    fw_path = Path("samples/openwrt_mips_router.bin")
    if len(sys.argv) > 1:
        fw_path = Path(sys.argv[1])

    if not fw_path.exists():
        console.print(f"[bold red]Error: Firmware image {fw_path} not found![/bold red]")
        sys.exit(1)

    console.print(f"\n[bold green]Ingesting and analyzing firmware:[/bold green] {fw_path.name}")
    pipeline = FirmwareAnalysisPipeline()
    
    report = pipeline.run_full_analysis(fw_path)

    # 1. Metadata Panel
    console.print(f"\n[bold cyan]--- Analysis Metadata ---[/bold cyan]")
    console.print(f"Firmware ID:      [yellow]{report.metadata.firmware_id}[/yellow]")
    console.print(f"Format Detected:  {report.metadata.format_detected}")
    console.print(f"Mean Entropy:     {report.metadata.entropy_mean:.2f} bits/byte")
    console.print(f"Total Files:      {report.metadata.total_files}")
    console.print(f"Binaries Audited: {report.metadata.total_binaries}")
    color = 'green' if report.overall_posture_score >= 70 else 'red'
    console.print(f"Overall Posture:  [bold {color}]{report.overall_posture_score} / 100[/bold {color}]")

    # 2. Hardening Matrix
    console.print(f"\n[bold cyan]--- Exploit Mitigation Matrix (Checksec) ---[/bold cyan]")
    matrix_table = Table(title="Binary Hardening Status", border_style="blue")
    matrix_table.add_column("Binary", style="cyan")
    matrix_table.add_column("Arch", style="magenta")
    matrix_table.add_column("NX", justify="center")
    matrix_table.add_column("PIE", justify="center")
    matrix_table.add_column("RELRO", justify="center")
    matrix_table.add_column("Canary", justify="center")
    matrix_table.add_column("FORTIFY", justify="center")
    matrix_table.add_column("Risk Score", justify="right")

    for b in report.audit_matrix:
        matrix_table.add_row(
            b.path,
            f"{b.architecture} ({b.bits}-bit)",
            "[green]YES[/green]" if b.nx else "[red]NO[/red]",
            "[green]YES[/green]" if b.pie else "[red]NO[/red]",
            b.relro.upper(),
            "[green]YES[/green]" if b.stack_canary else "[red]NO[/red]",
            "[green]YES[/green]" if b.fortify else "[red]NO[/red]",
            str(b.risk_score)
        )
    console.print(matrix_table)

    # 3. Vulnerability Findings
    console.print(f"\n[bold cyan]--- CWE-Classified Vulnerability Findings ---[/bold cyan]")
    vuln_table = Table(title=f"Discovered Findings ({len(report.vulnerabilities)} total)", border_style="red")
    vuln_table.add_column("CWE", style="bold red")
    vuln_table.add_column("Category", style="yellow")
    vuln_table.add_column("Risk", style="bold")
    vuln_table.add_column("Binary", style="cyan")
    vuln_table.add_column("Sink / Target", style="white")
    vuln_table.add_column("Redacted Evidence Ref", style="dim")

    for f in report.vulnerabilities[:10]: # Print top 10
        vuln_table.add_row(
            f.cwe,
            f.category.value,
            f.risk_rating.value.upper(),
            f.binary,
            f.sink or f.source or "N/A",
            f.evidence_ref[:60] + "..." if len(f.evidence_ref) > 60 else f.evidence_ref
        )
    console.print(vuln_table)

    console.print(f"\n[bold green]Report persisted to:[/bold green] {settings.REPORT_DIR / f'{report.metadata.firmware_id}_report.json'}")

if __name__ == "__main__":
    main()
