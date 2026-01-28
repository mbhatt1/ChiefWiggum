"""
ChiefWiggum Loop command-line interface
"""

import click
import json
from pathlib import Path
from tabulate import tabulate
from urllib.parse import urlparse

from .project import create_project, load_project, get_project_info, init_in_place, init_from_url
from .core import Evaluator, EvidenceType


@click.group()
def main():
    """ChiefWiggum Loop - D'oh! I found it!"""
    pass


@main.command()
@click.option("--target-url", required=True, help="Target URL (extracts project name from URL)")
@click.option("--path", default=None, help="Project root directory (defaults to current dir)")
def init(target_url, path):
    """Initialize a new ChiefWiggum vulnerability analysis project"""
    try:
        if path:
            # Initialize in specified directory
            project_root = init_from_url(target_url, path)
        else:
            # Initialize in current directory
            project_root = init_in_place(target_url)

        click.echo(f"✓ Initialized ChiefWiggum project")
        click.echo(f"  Target: {target_url}")
        click.echo(f"  Root: {project_root}")
        click.echo(f"")
        click.echo(f"Next steps:")
        click.echo(f"  1. Edit ground_truth/TARGET.md with threat model")
        click.echo(f"  2. Enumerate surfaces: surfaces/SURFACES.yaml")
        click.echo(f"  3. Form hypotheses: hypotheses/*.md")
        click.echo(f"  4. Test with: chiefwiggum analyze --surface ... --hypothesis ...")
    except Exception as e:
        click.echo(f"✗ Error: {e}", err=True)


@main.command()
@click.option("--path", default=".", help="Project root")
def info(path):
    """Show project information"""
    try:
        project_root = load_project(path)
        info_data = get_project_info(project_root)
        click.echo(json.dumps(info_data, indent=2))
    except Exception as e:
        click.echo(f"✗ Error: {e}", err=True)


@main.group()
def ledger():
    """Query evidence ledger"""
    pass


@ledger.command()
@click.option("--path", default=".", help="Project root")
def list(path):
    """View all confirmed, disproven, and unclear test results"""
    try:
        project_root = load_project(path)
        evaluator = Evaluator(project_root)
        summary = evaluator.get_summary()

        click.echo(f"\n✓ Confirmed:  {summary['confirmed']}")
        click.echo(f"✗ Disproven:  {summary['disproven']}")
        click.echo(f"? Unclear:    {summary['unclear']}")

        # Show confirmed
        confirmed = evaluator.ledger.list_confirmed()
        if confirmed:
            click.echo("\n=== CONFIRMED ===")
            for e in confirmed:
                click.echo(f"  {e.hypothesis_id}: {e.code_location}")

        # Show disproven
        disproven = evaluator.ledger.list_disproven()
        if disproven:
            click.echo("\n=== DISPROVEN ===")
            for e in disproven:
                click.echo(f"  {e.hypothesis_id}: {e.description}")

    except Exception as e:
        click.echo(f"✗ Error: {e}", err=True)


@main.group()
def report():
    """Generate reports and hardening backlogs"""
    pass


@report.command()
@click.option("--path", default=".", help="Project root")
@click.option("--format", type=click.Choice(["text", "json"]), default="text", help="Output format")
def generate(path, format):
    """Produce a prioritized hardening backlog with patches, controls, and instrumentation needs"""
    try:
        project_root = load_project(path)
        evaluator = Evaluator(project_root)

        if format == "json":
            summary = evaluator.get_summary()
            click.echo(json.dumps(summary, indent=2))
        else:
            click.echo(evaluator.control_map_report())
    except Exception as e:
        click.echo(f"✗ Error: {e}", err=True)


@main.command()
@click.argument("hypothesis_id")
@click.option("--confirmed", is_flag=True, help="Mark as confirmed")
@click.option("--disproven", is_flag=True, help="Mark as disproven")
@click.option("--location", required=True, help="Code location (file:line)")
@click.option("--description", required=True, help="What we learned")
@click.option("--action", type=click.Choice(["PATCH", "CONTROL", "INSTRUMENT", "BLOCKER"]),
              default="PATCH", help="Action type for confirmed/disproven result")
@click.option("--control", default=None, help="Control ID if action=CONTROL (e.g., C-007)")
@click.option("--patch-location", default=None, help="File/function to patch if action=PATCH")
@click.option("--test-case", default=None, help="Regression test requirement")
@click.option("--blocking-reason", default=None, help="Why it's safe (if disproven)")
@click.option("--instrumentation", default=None, help="What data would resolve (if unclear)")
@click.option("--path", default=".", help="Project root")
def record(hypothesis_id, confirmed, disproven, location, description, action,
           control, patch_location, test_case, blocking_reason, instrumentation, path):
    """Record a test result with actionable output"""
    try:
        project_root = load_project(path)
        evaluator = Evaluator(project_root)

        # Determine evidence type
        if confirmed:
            evidence_type = EvidenceType.CONFIRMED
        elif disproven:
            evidence_type = EvidenceType.DISPROVEN
        else:
            evidence_type = EvidenceType.UNCLEAR

        # Validate required fields based on action
        if action == "PATCH" and not patch_location:
            click.echo("✗ Error: PATCH action requires --patch-location", err=True)
            return
        if action == "CONTROL" and not control:
            click.echo("✗ Error: CONTROL action requires --control (e.g., C-007)", err=True)
            return

        # Record evidence with full action info
        from .core import ActionType
        evaluator.ledger.add_evidence(
            hypothesis_id=hypothesis_id,
            evidence_type=evidence_type,
            code_location=location,
            description=description,
            action=ActionType[action],
            control_id=control,
            patch_location=patch_location,
            test_case=test_case,
            blocking_reason=blocking_reason,
            instrumentation=instrumentation,
        )

        status = "✓ Confirmed" if confirmed else ("✗ Disproven" if disproven else "? Unclear")
        click.echo(f"{status}: {hypothesis_id}")
        click.echo(f"  Action: {action}")
        if control:
            click.echo(f"  Control: {control}")
        if patch_location:
            click.echo(f"  Patch: {patch_location}")

    except Exception as e:
        click.echo(f"✗ Error: {e}", err=True)


@main.command()
@click.option("--surface", required=True, help="Path to surfaces file (SURFACES.yaml)")
@click.option("--hypothesis", required=True, help="Path to hypothesis file (.md)")
@click.option("--path", default=".", help="Project root")
def analyze(surface, hypothesis, path):
    """Test a hypothesis against enumerated attack surfaces"""
    try:
        project_root = load_project(path)
        evaluator = Evaluator(project_root)

        # Load surface and hypothesis files
        surface_file = Path(surface)
        hypothesis_file = Path(hypothesis)

        if not surface_file.exists():
            raise FileNotFoundError(f"Surface file not found: {surface}")
        if not hypothesis_file.exists():
            raise FileNotFoundError(f"Hypothesis file not found: {hypothesis}")

        click.echo(f"Analyzing surface: {surface}")
        click.echo(f"Testing hypothesis: {hypothesis}")
        click.echo("")
        click.echo("✓ Analysis framework ready")
        click.echo("  See: hypotheses/*.md for hypothesis template")
        click.echo("  Run: chiefwiggum record <hypothesis_id> --confirmed ...")

    except Exception as e:
        click.echo(f"✗ Error: {e}", err=True)


if __name__ == "__main__":
    main()
