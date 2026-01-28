"""
ChiefWiggum project management - create, load, manage projects
"""

from pathlib import Path
import json


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
        "pocs",
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
    target_template = """# Target: {name}

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
        f.write(target_template.format(name=name))

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
