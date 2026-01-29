"""
ChiefWiggum Loop command-line interface
"""

import click
import json
import os
from pathlib import Path
from tabulate import tabulate
from urllib.parse import urlparse

from .project import create_project, load_project, get_project_info, init_in_place, init_from_url
from .core import Evaluator, EvidenceType, ActionType


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


@main.command()
@click.option("--hypothesis", required=True, help="Path to hypothesis file (.md)")
@click.option("--codebase-path", required=True, help="Path to target codebase")
@click.option("--path", default=".", help="Project root")
def validate(hypothesis, codebase_path, path):
    """Validate hypothesis against actual source code"""
    try:
        import re
        from pathlib import Path

        project_root = load_project(path)
        evaluator = Evaluator(project_root)

        # Read hypothesis file
        hyp_file = Path(hypothesis)
        if not hyp_file.exists():
            raise FileNotFoundError(f"Hypothesis file not found: {hypothesis}")

        hyp_content = hyp_file.read_text()

        # Extract hypothesis ID from filename
        hyp_id = hyp_file.stem

        # Extract key sections from hypothesis
        location_match = re.search(r'\*\*Location:\*\*\s*`([^`]+)`', hyp_content)
        sink_match = re.search(r'\*\*Function:\*\*\s*`([^`]+)`', hyp_content)

        location = location_match.group(1) if location_match else "unknown"
        sink = sink_match.group(1) if sink_match else "unknown"

        click.echo(f"\n{'='*80}")
        click.echo(f"Validating: {hyp_id}")
        click.echo(f"Location: {location}")
        click.echo(f"Sink: {sink}")
        click.echo(f"Codebase: {codebase_path}")
        click.echo(f"{'='*80}\n")

        # Search codebase for vulnerability pattern
        codebase = Path(codebase_path)
        if not codebase.exists():
            raise FileNotFoundError(f"Codebase not found: {codebase_path}")

        # Extract file path from location (e.g., "org/apache/.../File.java:method()")
        file_parts = location.split(":")[0].replace(".", "/").replace("/java", ".java")

        # Search for vulnerable patterns
        found = False
        evidence = []

        for java_file in codebase.rglob("*.java"):
            # Try to match by filename
            if file_parts in str(java_file):
                content = java_file.read_text()

                # Extract sink function name
                sink_func = sink.split("(")[0] if "(" in sink else sink

                # Search for dangerous patterns
                if "readObject" in sink or "deserial" in sink.lower():
                    if "ObjectInputStream" in content or "readObject" in content:
                        found = True
                        evidence.append((str(java_file), "ObjectInputStream deserialization found"))

                if "Class.forName" in sink or "ClassLoader" in sink:
                    if "Class.forName" in content and ("newInstance" in content or "getConstructor" in content):
                        found = True
                        evidence.append((str(java_file), "Unsafe Class.forName() + instantiation found"))

                if "exec" in sink or "Runtime" in sink:
                    if "Runtime.getRuntime()" in content or "ProcessBuilder" in content:
                        found = True
                        evidence.append((str(java_file), "Runtime.exec() or ProcessBuilder found"))

                if "parse" in sink.lower() and "expression" in hyp_id.lower():
                    if "parseExpression" in content or "evaluate" in content:
                        found = True
                        evidence.append((str(java_file), "Expression evaluation found"))

        # Report results
        if found and evidence:
            click.echo(f"✓ CONFIRMED - Vulnerable pattern exists\n")
            for file_path, finding in evidence:
                click.echo(f"  Found in: {file_path}")
                click.echo(f"  Evidence: {finding}")
                click.echo()

            status = "CONFIRMED"
            result = True
        else:
            click.echo(f"⚠ UNCLEAR - Code pattern not found in search\n")
            click.echo(f"  Searched for: {sink}")
            click.echo(f"  In path: {location}")
            click.echo(f"  Note: Manual code review may be needed")
            click.echo()

            status = "UNCLEAR"
            result = None

        click.echo(f"{'='*80}")
        click.echo(f"Status: {status}")
        click.echo(f"Next: Run 'chiefwiggum record {hyp_id} --{status.lower()} ...' to record result")
        click.echo(f"{'='*80}\n")

    except Exception as e:
        click.echo(f"✗ Error: {e}", err=True)


@main.command()
@click.option("--target-url", required=True, help="Target URL (extracts project name from URL)")
@click.option("--path", default=".", help="Project root directory")
@click.option("--validate/--no-validate", default=False, help="Validate hypotheses against codebase")
@click.option("--codebase-path", default=None, help="Path to target codebase for validation")
@click.option("--openai-base-url", default=None, help="Custom OpenAI API base URL (e.g., http://localhost:11434/v1 for Ollama)")
@click.option("--model", default=None, help="Model to use for analysis (default: gpt-4o-mini)")
def orchestrate(target_url, path, validate, codebase_path, openai_base_url, model):
    """Run end-to-end vulnerability testing loop: init → enumerate → analyze → record → report"""
    try:
        from pathlib import Path

        project_path = Path(path)

        click.echo("=" * 80)
        click.echo("ChiefWiggum Loop Orchestration")
        if validate:
            click.echo("(with codebase validation)")
        click.echo("=" * 80)

        # Phase 1: Initialize project if needed
        click.echo("\n[1/5] Initialize project...")
        if not (project_path / "ground_truth").exists():
            click.echo(f"  Initializing {target_url}")
            init_in_place(target_url)
            click.echo("  ✓ Project initialized")
        else:
            click.echo("  ✓ Project already initialized")

        # Phase 2: Load project
        click.echo("\n[2/5] Load project...")
        project_root_str = load_project(str(project_path))
        evaluator = Evaluator(project_root_str)
        click.echo(f"  ✓ Loaded from {project_root_str}")

        # Phase 3: Enumerate and analyze surfaces
        click.echo("\n[3/5] Enumerate attack surfaces...")
        surfaces_file = str(Path(project_root_str) / "surfaces" / "SURFACES.yaml")
        if Path(surfaces_file).exists():
            click.echo(f"  ✓ Found surfaces file")
        else:
            click.echo(f"  ⚠ No surfaces file")

        # Phase 4: Vulnerability Analysis (LLM-based)
        click.echo("\n[4/5] Analyze code for vulnerabilities...")

        if validate and codebase_path:
            codebase = Path(codebase_path)
            if codebase.exists():
                from .llm_analyzer import analyze_with_gpt

                # Resolve configuration: CLI flags > env vars > defaults
                resolved_base_url = openai_base_url or os.getenv("OPENAI_BASE_URL")
                resolved_model = model or os.getenv("OPENAI_MODEL", "gpt-4o-mini")

                click.echo(f"  Running LLM-based vulnerability analysis...")
                if resolved_base_url:
                    click.echo(f"  Using custom base URL: {resolved_base_url}")
                click.echo(f"  Using model: {resolved_model}")
                click.echo(f"  (Analyzing first 50 Java files)")

                gpt_findings = analyze_with_gpt(
                    codebase,
                    file_patterns=["*.java"],
                    model=resolved_model,
                    base_url=resolved_base_url
                )

                if gpt_findings:
                    click.echo(f"\n  ✓ Found {len(gpt_findings)} vulnerabilities")

                    # Group by severity
                    critical = [f for f in gpt_findings if f.get('severity') == 'CRITICAL']
                    high = [f for f in gpt_findings if f.get('severity') == 'HIGH']
                    medium = [f for f in gpt_findings if f.get('severity') == 'MEDIUM']
                    low = [f for f in gpt_findings if f.get('severity') == 'LOW']

                    if critical:
                        click.echo(f"\n  🔴 CRITICAL ({len(critical)}):")
                        for finding in critical[:5]:
                            click.echo(f"    • {finding['type']} - {finding.get('location', 'unknown')}")

                    if high:
                        click.echo(f"\n  🟠 HIGH ({len(high)}):")
                        for finding in high[:5]:
                            click.echo(f"    • {finding['type']} - {finding.get('location', 'unknown')}")

                    if medium:
                        click.echo(f"\n  🟡 MEDIUM ({len(medium)}):")
                        for finding in medium[:3]:
                            click.echo(f"    • {finding['type']}")

                    # Record in evidence ledger
                    for finding in gpt_findings:
                        evaluator.ledger.add_evidence(
                            hypothesis_id=finding['id'],
                            evidence_type=EvidenceType.CONFIRMED,
                            code_location=finding['file'],
                            description=f"{finding['type']} ({finding.get('severity', 'UNKNOWN')})",
                            details=finding,
                            action=ActionType.PATCH,
                            patch_location=finding['file'],
                            test_case=f"Verify {finding['type']} is fixed"
                        )
                else:
                    click.echo(f"  ✓ No vulnerabilities found")
            else:
                click.echo(f"  ⚠ Codebase path not found: {codebase_path}")
        else:
            click.echo(f"  To analyze code, run with:")
            click.echo(f"    --validate --codebase-path /path/to/source")

        # Phase 5: Generate report
        click.echo("\n[5/5] Generate hardening backlog...")
        report_output = evaluator.control_map_report()
        click.echo(report_output)

        click.echo("\n" + "=" * 80)
        click.echo("Loop Complete: D'oh! I found it!")
        click.echo("=" * 80)

    except Exception as e:
        click.echo(f"\n✗ Error: {e}", err=True)


if __name__ == "__main__":
    main()
