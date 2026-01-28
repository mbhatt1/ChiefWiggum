"""
ChiefWiggum project management - create, load, manage projects
"""

from pathlib import Path
import json
from urllib.parse import urlparse


def create_project(name: str, path: str = None) -> Path:
    """
    Create a new ChiefWiggum project.

    Args:
        name: Project name
        path: Optional root directory

    Returns:
        Path to project
    """
    if path:
        project_root = Path(path)
    else:
        project_root = Path.cwd() / name

    # Create directory structure
    project_root.mkdir(parents=True, exist_ok=True)

    directories = [
        "ground_truth",
        "surfaces",
        "hypotheses",
        "controls",
        "patches",
        "examples",
        "evidence/confirmed",
        "evidence/disproven",
        "evidence/unclear",
    ]

    for directory in directories:
        (project_root / directory).mkdir(parents=True, exist_ok=True)

    # Create project metadata
    metadata = {
        "name": name,
        "created": "2026-01-27",
        "version": "0.1",
    }

    with open(project_root / "chiefwiggum.json", "w") as f:
        json.dump(metadata, f, indent=2)

    # Create a template TARGET.md
    target_template = f"""# Target: {name}

**Project:** {name}
**Date:** 2026-01-27

## Asset

**Name:** {name}
**Version:** 0.1

## Threat Model

**Who attacks?** [Specify]
**What do they want?** [Specify]
**Constraints?** [Specify]

## Assumptions

- [ ] [Assumption 1]
- [ ] [Assumption 2]

## Success Criteria

- [ ] Found critical vulnerability
- [ ] Validated patches
- [ ] Complete evidence ledger
"""

    with open(project_root / "ground_truth" / "TARGET.md", "w") as f:
        f.write(target_template)

    # Create a template SURFACES.yaml
    surfaces_template = """# Attack Surface Enumeration

surfaces:
  - id: surface_1
    name: "[Entry point name]"
    entry: "[HTTP endpoint, CLI flag, etc.]"
    chain:
      - step: "[Step 1]"
        location: "[file.c:line]"
      - step: "[Step 2]"
        location: "[file.c:line]"
    status: untested
    notes: "D'oh!"
"""

    with open(project_root / "surfaces" / "SURFACES.yaml", "w") as f:
        f.write(surfaces_template)

    return project_root


def load_project(path: str) -> Path:
    """Load an existing ChiefWiggum project"""
    project_root = Path(path)

    if not (project_root / "chiefwiggum.json").exists():
        raise ValueError(f"Not a ChiefWiggum project: {path}")

    return project_root


def get_project_info(project_root: Path) -> dict:
    """Get project metadata"""
    metadata_file = project_root / "chiefwiggum.json"

    if not metadata_file.exists():
        return {"error": "No project metadata found"}

    with open(metadata_file) as f:
        return json.load(f)


def _extract_project_name_from_url(target_url: str) -> str:
    """Extract project name from URL

    Examples:
      http://localhost:8161 → localhost-8161
      https://github.com/apache/activemq → activemq
      http://example.com/path → example-com
    """
    parsed = urlparse(target_url)
    path = parsed.path.strip("/")

    # If path exists, use last component
    if path:
        name = path.split("/")[-1]
        # Remove extensions like .git
        name = name.replace(".git", "")
    else:
        # Use netloc, replace : with -
        name = parsed.netloc.replace(":", "-")

    return name or "project"


def init_in_place(target_url: str) -> Path:
    """Initialize a ChiefWiggum project in the current directory"""
    project_root = Path.cwd()
    name = _extract_project_name_from_url(target_url)

    # Create directory structure
    directories = [
        "ground_truth",
        "surfaces",
        "hypotheses",
        "controls",
        "patches",
        "examples",
        "evidence/confirmed",
        "evidence/disproven",
        "evidence/unclear",
    ]

    for directory in directories:
        (project_root / directory).mkdir(parents=True, exist_ok=True)

    # Create project metadata
    metadata = {
        "name": name,
        "target_url": target_url,
        "created": "2026-01-27",
        "version": "0.1",
    }

    with open(project_root / "chiefwiggum.json", "w") as f:
        json.dump(metadata, f, indent=2)

    # Create TARGET.md
    target_template = f"""# Target: {name}

**Project:** {name}
**Target:** {target_url}
**Date:** 2026-01-27

## Asset

**Name:** {name}
**URL:** {target_url}
**Version:** Unknown (enumerate in analysis)

## Threat Model

**Who attacks?** [Specify]
**What do they want?** [Specify]
**Constraints?** [Specify]

## Assumptions

- [ ] [Assumption 1]
- [ ] [Assumption 2]

## Success Criteria

- [ ] Found critical vulnerability
- [ ] Validated patches
- [ ] Complete evidence ledger
"""

    with open(project_root / "ground_truth" / "TARGET.md", "w") as f:
        f.write(target_template)

    # Create SURFACES.yaml template
    surfaces_template = """# Attack Surface Enumeration

surfaces:
  - id: surface_1
    name: "[Entry point name]"
    entry: "[HTTP endpoint, CLI flag, etc.]"
    chain:
      - step: "[Step 1]"
        location: "[file.c:line]"
      - step: "[Step 2]"
        location: "[file.c:line]"
    status: untested
    notes: "D'oh!"
"""

    with open(project_root / "surfaces" / "SURFACES.yaml", "w") as f:
        f.write(surfaces_template)

    # Create hypothesis template
    hypothesis_template = """# Hypothesis: [Name]

## Ralphization Checklist

### 1. REACHABILITY
Exact entry point → dangerous sink
- Entry: [HTTP endpoint or CLI flag]
- Sink: [Function name]
- Path: [File:line → file:line → ...]

### 2. SINK
What function/API is dangerous?
- Function: [Name]
- Location: [file:line]
- Danger: [Why is this dangerous?]

### 3. CONTROL
Which C-001 to C-012 blocks this?
- Control: [C-XXX]
- Name: [Control name]
- Mitigation: [How would this prevent the vulnerability?]

### 4. PATCH
File/function to change
- Location: [file:line]
- Change: [Specific code change]
- Test: [What regression test validates this?]

### 5. TEST
Regression test to prevent re-exposure
- Test case: [Exact test to run]
- Expected: [Expected result]
"""

    with open(project_root / "hypotheses" / "template.md", "w") as f:
        f.write(hypothesis_template)

    return project_root


def init_from_url(target_url: str, path: str) -> Path:
    """Initialize a ChiefWiggum project in a specified directory"""
    project_root = Path(path)
    name = _extract_project_name_from_url(target_url)

    # Create directory structure
    project_root.mkdir(parents=True, exist_ok=True)

    directories = [
        "ground_truth",
        "surfaces",
        "hypotheses",
        "controls",
        "patches",
        "examples",
        "evidence/confirmed",
        "evidence/disproven",
        "evidence/unclear",
    ]

    for directory in directories:
        (project_root / directory).mkdir(parents=True, exist_ok=True)

    # Create project metadata
    metadata = {
        "name": name,
        "target_url": target_url,
        "created": "2026-01-27",
        "version": "0.1",
    }

    with open(project_root / "chiefwiggum.json", "w") as f:
        json.dump(metadata, f, indent=2)

    # Create TARGET.md
    target_template = f"""# Target: {name}

**Project:** {name}
**Target:** {target_url}
**Date:** 2026-01-27

## Asset

**Name:** {name}
**URL:** {target_url}
**Version:** Unknown (enumerate in analysis)

## Threat Model

**Who attacks?** [Specify]
**What do they want?** [Specify]
**Constraints?** [Specify]

## Assumptions

- [ ] [Assumption 1]
- [ ] [Assumption 2]

## Success Criteria

- [ ] Found critical vulnerability
- [ ] Validated patches
- [ ] Complete evidence ledger
"""

    with open(project_root / "ground_truth" / "TARGET.md", "w") as f:
        f.write(target_template)

    # Create SURFACES.yaml template
    surfaces_template = """# Attack Surface Enumeration

surfaces:
  - id: surface_1
    name: "[Entry point name]"
    entry: "[HTTP endpoint, CLI flag, etc.]"
    chain:
      - step: "[Step 1]"
        location: "[file.c:line]"
      - step: "[Step 2]"
        location: "[file.c:line]"
    status: untested
    notes: "D'oh!"
"""

    with open(project_root / "surfaces" / "SURFACES.yaml", "w") as f:
        f.write(surfaces_template)

    # Create hypothesis template
    hypothesis_template = """# Hypothesis: [Name]

## Ralphization Checklist

### 1. REACHABILITY
Exact entry point → dangerous sink
- Entry: [HTTP endpoint or CLI flag]
- Sink: [Function name]
- Path: [File:line → file:line → ...]

### 2. SINK
What function/API is dangerous?
- Function: [Name]
- Location: [file:line]
- Danger: [Why is this dangerous?]

### 3. CONTROL
Which C-001 to C-012 blocks this?
- Control: [C-XXX]
- Name: [Control name]
- Mitigation: [How would this prevent the vulnerability?]

### 4. PATCH
File/function to change
- Location: [file:line]
- Change: [Specific code change]
- Test: [What regression test validates this?]

### 5. TEST
Regression test to prevent re-exposure
- Test case: [Exact test to run]
- Expected: [Expected result]
"""

    with open(project_root / "hypotheses" / "template.md", "w") as f:
        f.write(hypothesis_template)

    return project_root
