"""
ChiefWiggum Loop command-line interface
"""

import click
import json
from pathlib import Path
from tabulate import tabulate

from .project import create_project, load_project, get_project_info
from .core import Evaluator, EvidenceType


@click.group()
def main():
    """ChiefWiggum Loop - D'oh! I found it!"""
    pass


@main.command()
@click.argument("name")
@click.option("--path", default=None, help="Project root directory")
def init(name, path):
    """Create a new ChiefWiggum project"""
    try:
        project_root = create_project(name, path)
        click.echo(f"✓ Created project: {project_root}")
        click.echo(f"  Run: cd {project_root}")
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


@main.command()
@click.option("--path", default=".", help="Project root")
def evidence(path):
    """Show evidence ledger"""
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


@main.command()
@click.option("--path", default=".", help="Project root")
def report(path):
    """Generate evaluation report"""
    try:
        project_root = load_project(path)
        evaluator = Evaluator(project_root)
        click.echo(evaluator.report())
    except Exception as e:
        click.echo(f"✗ Error: {e}", err=True)


@main.command()
@click.argument("hypothesis_id")
@click.option("--confirmed", is_flag=True, help="Mark as confirmed")
@click.option("--location", required=True, help="Code location (file:line)")
@click.option("--description", required=True, help="What we learned")
@click.option("--path", default=".", help="Project root")
def record(hypothesis_id, confirmed, location, description, path):
    """Record a test result"""
    try:
        project_root = load_project(path)
        evaluator = Evaluator(project_root)

        evaluator.test_hypothesis(
            hypothesis_id=hypothesis_id,
            confirmed=confirmed,
            code_location=location,
            description=description
        )

        status = "✓ Confirmed" if confirmed else "✗ Disproven"
        click.echo(f"{status}: {hypothesis_id}")

    except Exception as e:
        click.echo(f"✗ Error: {e}", err=True)


@main.command()
@click.option("--path", default=".", help="Project root")
def check(path):
    """Check if hypothesis was already tested"""
    try:
        project_root = load_project(path)
        evaluator = Evaluator(project_root)

        click.echo("Evidence ledger status:")
        summary = evaluator.get_summary()
        click.echo(f"  Total tested: {summary['total_tested']}")
        click.echo(f"  Confirmed: {summary['confirmed']}")
        click.echo(f"  Disproven: {summary['disproven']}")

    except Exception as e:
        click.echo(f"✗ Error: {e}", err=True)


if __name__ == "__main__":
    main()
