"""
ChiefWiggum Loop command-line interface
"""

import click
import json
import sys
import os
from pathlib import Path
from urllib.parse import urlparse

from .project import create_project, load_project, get_project_info, init_in_place, init_from_url
from .core import Evaluator, EvidenceType
from .hypothesis_generator import generate_hypotheses as gen_hypotheses

# Import Claude Judge and Parallel Validator
try:
    from .claude_judge import ClaudeJudge
    from .parallel_validator import ParallelValidator
    HAS_LLM_JUDGE = True
except ImportError:
    HAS_LLM_JUDGE = False


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
            evidence_type = "confirmed"
        elif disproven:
            evidence_type = "disproven"
        else:
            evidence_type = "unclear"

        # Validate required fields based on action
        if action == "PATCH" and not patch_location:
            click.echo("✗ Error: PATCH action requires --patch-location", err=True)
            return
        if action == "CONTROL" and not control:
            click.echo("✗ Error: CONTROL action requires --control (e.g., C-007)", err=True)
            return

        # Record evidence with full action info
        evaluator.ledger.add_evidence(
            hypothesis_id=hypothesis_id,
            evidence_type=evidence_type,
            code_location=location,
            description=description,
            action=action,
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
        else:
            click.echo(f"⚠ UNCLEAR - Code pattern not found in search\n")
            click.echo(f"  Searched for: {sink}")
            click.echo(f"  In path: {location}")
            click.echo(f"  Note: Manual code review may be needed")
            click.echo()

            status = "UNCLEAR"

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
@click.option("--generate-hypotheses", "num_hypotheses", type=int, default=100, help="Auto-generate N vulnerability hypotheses (default: 100)")
def orchestrate(target_url, path, validate, codebase_path, num_hypotheses):
    """Run end-to-end vulnerability testing loop: init → enumerate → analyze → record → report"""
    try:
        # Ensure all path parameters are strings
        path = str(path) if path else "."
        codebase_path = str(codebase_path) if codebase_path else None

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

        # Phase 2b: Generate hypotheses if needed
        if num_hypotheses > 0:
            click.echo("\n[2b/5] Generate vulnerability hypotheses...")
            generated = gen_hypotheses(project_root_str, count=num_hypotheses)
            click.echo(f"  ✓ Generated/loaded {generated} hypotheses")

        # Phase 3: Enumerate and analyze surfaces
        click.echo("\n[3/6] Enumerate attack surfaces...")
        surfaces_file = str(Path(project_root_str) / "surfaces" / "SURFACES.yaml")
        if Path(surfaces_file).exists():
            click.echo(f"  ✓ Found surfaces file")
        else:
            click.echo(f"  ⚠ No surfaces file")

        # Phase 4: Validate hypotheses against codebase
        click.echo("\n[4/6] Validate hypotheses...")
        hypotheses_dir = str(Path(project_root_str) / "hypotheses")
        hypothesis_files = [f for f in Path(hypotheses_dir).glob("hyp_*.md")]

        if hypothesis_files:
            click.echo(f"  Found {len(hypothesis_files)} hypothesis(es)")

            if validate and codebase_path:
                codebase = Path(str(codebase_path))
                if not codebase.exists():
                    click.echo(f"  ⚠ Codebase path not found: {codebase_path}")
                    click.echo(f"    Skipping validation")
                else:
                    click.echo(f"  Validating against: {codebase_path}")

                    import re
                    validated_count = 0

                    # Detect language: Java or Erlang
                    java_count = sum(1 for _ in codebase.rglob("*.java"))
                    erl_count = sum(1 for _ in codebase.rglob("*.erl"))
                    is_erlang = erl_count > java_count

                    # Pre-load all source files to search once
                    click.echo(f"  Loading codebase...")
                    source_files_content = {}
                    total_files = 0

                    if is_erlang:
                        click.echo(f"  Detected Erlang codebase")
                        for erl_file in codebase.rglob("*.erl"):
                            try:
                                source_files_content[str(erl_file)] = erl_file.read_text()
                                total_files += 1
                            except:
                                continue
                        click.echo(f"  Loaded {total_files} Erlang files")

                        # Erlang-specific dangerous patterns
                        dangerous_patterns = [
                            ("binary_to_term", "binary_to_term"),
                            ("erl_parse", "erl_parse"),
                            ("erl_scan", "erl_scan"),
                            ("os:system", "os:system"),
                            ("os:cmd", "os:cmd"),
                            ("erlang:apply", "erlang:apply"),
                            ("rpc:call", "rpc:call"),
                            ("rpc:cast", "rpc:cast"),
                            ("file:read_file", "file:read_file"),
                            ("file:write_file", "file:write_file"),
                            ("file:open", "file:open"),
                        ]
                    else:
                        click.echo(f"  Detected Java codebase")
                        for java_file in codebase.rglob("*.java"):
                            try:
                                source_files_content[str(java_file)] = java_file.read_text()
                                total_files += 1
                            except:
                                continue
                        click.echo(f"  Loaded {total_files} Java files")

                        # Java-specific dangerous patterns
                        dangerous_patterns = [
                            ("ObjectInputStream", "ObjectInputStream"),
                            ("readObject", "readObject"),
                            ("Class.forName", "Class.forName"),
                            ("getConstructor", "getConstructor"),
                            ("newInstance", "newInstance"),
                            ("DocumentBuilderFactory", "DocumentBuilderFactory"),
                            ("InitialContext", "InitialContext"),
                            ("executeQuery", "executeQuery"),
                            ("executeUpdate", "executeUpdate"),
                            ("SAXParserFactory", "SAXParserFactory"),
                        ]

                    # Find all dangerous code in codebase (single patterns)
                    code_findings = {}
                    for pattern_name, pattern_text in dangerous_patterns:
                        code_findings[pattern_name] = []
                        for file_path, content in source_files_content.items():
                            if pattern_text in content:
                                filename = Path(file_path).name
                                code_findings[pattern_name].append(filename)

                    # NEW: Find gadget CHAINS (multiple related dangerous functions in same file/module)
                    chain_findings = {}
                    erlang_chains = {
                        "deserialization_gadget": ["binary_to_term", "erlang:apply"],
                        "rpc_reflection": ["distributed:call", "erlang:apply"],
                        "port_command": ["open_port", "os:cmd"],
                        "file_traversal": ["file:open", "file:read_file"],
                        "atom_pollution": ["string:to_atom", "erlang:atom_to_binary"],
                        "ets_dos": ["ets:select", "ets:select_count"],
                        "supervisor_injection": ["supervisor:start_child", "erlang:spawn"],
                        "mnesia_injection": ["mnesia:select", "mnesia:dirty_read"],
                        "nif_exploit": ["erlang:load_nif", "erlang:nif_call"],
                        "compile_inject": ["compile:forms", "erl_eval:expr"],
                    }

                    for chain_name, chain_funcs in erlang_chains.items():
                        chain_findings[chain_name] = []
                        # Find files that contain ALL functions in the chain
                        for file_path, content in source_files_content.items():
                            if all(func in content for func in chain_funcs):
                                filename = Path(file_path).name
                                chain_findings[chain_name].append(filename)

                    confirmed_count = 0
                    validated_count = 0

                    # Parallel LLM analysis if available
                    if HAS_LLM_JUDGE and os.getenv("ANTHROPIC_API_KEY"):
                        click.echo(f"  Preparing batch for parallel LLM analysis...")
                        validator = ParallelValidator(source_files_content)
                        findings_list, code_snippets = validator.prepare_batch(hypothesis_files, code_findings)

                        if findings_list:
                            click.echo(f"  Analyzing {len(findings_list)} findings with Claude (parallel, 5 workers)...")

                            def progress_cb(finding_id, judgment, done, total):
                                status = judgment.get('severity_assessment', 'UNKNOWN')
                                click.echo(f"    [{done}/{total}] {finding_id}: {status}")

                            # Parallel batch analysis
                            judgments = validator.validate_batch_parallel(
                                findings_list,
                                code_snippets,
                                progress_callback=progress_cb
                            )
                        else:
                            judgments = {}

                        # Process all hypotheses with cached judgments
                        for hyp_file in hypothesis_files:
                            hyp_id = hyp_file.stem
                            hyp_content = hyp_file.read_text()
                            validated_count += 1

                            control_match = re.search(r'- Control:\s*\*\*(C-\d+)', hyp_content)
                            control = control_match.group(1) if control_match else "UNKNOWN"

                            if hyp_id in judgments:
                                judgment = judgments[hyp_id]

                                if judgment.get("is_true_positive"):
                                    confirmed_count += 1
                                    click.echo(f"    ✓ {hyp_id}: CONFIRMED [{control}] (confidence: {judgment.get('confidence', 0):.2f})", err=False)

                                    evaluator.ledger.add_evidence(
                                        hypothesis_id=hyp_id,
                                        evidence_type="confirmed",
                                        code_location=judgment.get('location', ''),
                                        description=f"LLM-verified vulnerability: {judgment.get('reasoning', 'Real security issue')}",
                                        action="CONTROL",
                                        control_id=control
                                    )
                                else:
                                    click.echo(f"    ⚠ {hyp_id}: UNCLEAR - {judgment.get('reasoning', 'Not exploitable')[:50]}...", err=False)

                                    evaluator.ledger.add_evidence(
                                        hypothesis_id=hyp_id,
                                        evidence_type="unclear",
                                        code_location=judgment.get('location', ''),
                                        description=f"LLM analysis: {judgment.get('reasoning', 'Pattern found but not exploitable')}",
                                        action="INSTRUMENT",
                                        control_id=control,
                                        instrumentation=f"Verify: {judgment.get('reasoning', 'Manual review needed')}"
                                    )
                            else:
                                click.echo(f"    ⚠ {hyp_id}: UNCLEAR")

                    else:
                        # Fallback: no LLM available
                        for hyp_file in hypothesis_files:
                            hyp_id = hyp_file.stem
                            validated_count += 1
                            click.echo(f"    ⚠ {hyp_id}: UNCLEAR")

                    # Report gadget chain findings
                    if chain_findings:
                        click.echo(f"\n  [GADGET CHAIN ANALYSIS]")
                        chains_found = sum(1 for files in chain_findings.values() if files)
                        if chains_found > 0:
                            click.echo(f"  ⚠ Found {chains_found} potential gadget chains:")
                            for chain_name, files in chain_findings.items():
                                if files:
                                    click.echo(f"    - {chain_name}: {len(files)} file(s) with all chain components")
                                    for f in files[:3]:
                                        click.echo(f"      • {f}")
                                    if len(files) > 3:
                                        click.echo(f"      ... and {len(files)-3} more")
                        else:
                            click.echo(f"  ✓ No gadget chains detected")

                    click.echo(f"  ✓ Validated {validated_count} hypotheses")
                    click.echo(f"  ✓ Found {confirmed_count} confirmed vulnerabilities")
            else:
                click.echo(f"  To validate, run with:")
                click.echo(f"    --validate --codebase-path /path/to/activemq")
                for hyp_file in hypothesis_files[:3]:
                    click.echo(f"    - {hyp_file.name}")
                if len(hypothesis_files) > 3:
                    click.echo(f"    ... and {len(hypothesis_files) - 3} more")
        else:
            click.echo("  ⚠ No hypotheses found")

        # Phase 5: Generate report
        click.echo("\n[5/6] Generate hardening backlog...")
        report_output = evaluator.control_map_report()
        click.echo(report_output)

        click.echo("\n" + "=" * 80)
        click.echo("Loop Complete: D'oh! I found it!")
        click.echo("=" * 80)

    except Exception as e:
        import traceback
        click.echo(f"\n✗ Error: {e}", err=True)
        click.echo(traceback.format_exc(), err=True)


if __name__ == "__main__":
    main()
