"""
ChiefWiggum Control Library - Reusable, composable hardening controls

These 12 standard controls form the backbone of the patch pipeline.
Every vulnerability maps to one or more controls.
"""

from dataclasses import dataclass
from typing import List
from enum import Enum


class ControlCategory(Enum):
    """Classification of controls"""
    EXECUTION = "Execution Controls"
    PARSER = "Parser Controls"
    IO = "IO Controls"
    AUTHZ = "Authorization Controls"
    NETWORK = "Network Controls"


@dataclass
class Control:
    """A reusable hardening control"""
    id: str                    # e.g., "C-001"
    name: str                  # Human-readable name
    category: ControlCategory
    description: str           # What does it prevent?
    implementation: str        # How to implement (code example or pattern)
    testing: str              # How to test it stays fixed
    references: List[str]     # CWE, CVE, or OWASP references


# The 12 Standard Controls Library
STANDARD_CONTROLS = {
    "C-001": Control(
        id="C-001",
        name="Shell Execution Wrapper",
        category=ControlCategory.EXECUTION,
        description="No raw system/popen/spawn. All shell execution goes through safe wrapper.",
        implementation="""
def safe_exec(cmd: List[str], *args) -> Result:
    '''Execute with argv array, never shell string'''
    return subprocess.run(cmd, shell=False, *args)

# Instead of:
#   system("unzip -d /tmp " + filename)
# Use:
#   safe_exec(["unzip", "-d", "/tmp", filename])
        """,
        testing="Test that shell metacharacters in args don't execute",
        references=["CWE-78", "CWE-77"]
    ),

    "C-002": Control(
        id="C-002",
        name="Argument Allowlist + No Shell Parsing",
        category=ControlCategory.EXECUTION,
        description="Arguments validated against allowlist before use. No shell metacharacters accepted.",
        implementation="""
SAFE_CHARS = set('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-')

def validate_arg(arg: str) -> bool:
    return all(c in SAFE_CHARS for c in arg)

# Before calling safe_exec, validate:
if not validate_arg(filename):
    raise ValueError(f"Invalid filename: {filename}")
        """,
        testing="Fuzz args with shell metacharacters; all must be rejected or escaped",
        references=["CWE-78", "CWE-434"]
    ),

    "C-003": Control(
        id="C-003",
        name="Path Canonicalization + Allowlist",
        category=ControlCategory.IO,
        description="All file paths canonicalized and checked against allowlist. No .. or symlinks.",
        implementation="""
import os

ALLOWED_DIRS = ["/tmp/app", "/var/app/data"]

def safe_path(user_path: str) -> str:
    # Resolve symlinks and ..
    canonical = os.path.realpath(user_path)

    # Check allowlist
    for allowed in ALLOWED_DIRS:
        if canonical.startswith(os.path.realpath(allowed)):
            return canonical

    raise ValueError(f"Path not allowed: {canonical}")
        """,
        testing="Test that ../../../etc/passwd is blocked, symlink to /etc is blocked",
        references=["CWE-22", "CWE-59"]
    ),

    "C-004": Control(
        id="C-004",
        name="Zip/Tar Safe Extract",
        category=ControlCategory.IO,
        description="Archive extraction disabled for symlinks, relative paths (..), size limits.",
        implementation="""
import zipfile

def safe_extract_zip(archive_path: str, extract_to: str, max_size: int = 1GB) -> None:
    with zipfile.ZipFile(archive_path) as zf:
        total_size = 0
        for member in zf.infolist():
            # Block symlinks
            if member.is_symlink():
                raise ValueError(f"Symlinks not allowed: {member.filename}")

            # Block relative paths
            if ".." in member.filename or member.filename.startswith("/"):
                raise ValueError(f"Invalid path: {member.filename}")

            # Block oversized files
            if member.file_size > max_size:
                raise ValueError(f"File too large: {member.filename}")

            total_size += member.file_size

        zf.extractall(extract_to)
        """,
        testing="Test with malicious zips: symlinks, ../, huge files",
        references=["CWE-22", "CWE-409"]
    ),

    "C-005": Control(
        id="C-005",
        name="YAML Safe Loader Only",
        category=ControlCategory.PARSER,
        description="Only yaml.safe_load, never yaml.load. Disables code execution in YAML.",
        implementation="""
import yaml

# GOOD:
config = yaml.safe_load(file_content)

# BAD (never do this):
# config = yaml.load(file_content, Loader=yaml.FullLoader)
        """,
        testing="Test YAML with !!python/object:os.system - must be rejected",
        references=["CWE-502"]
    ),

    "C-006": Control(
        id="C-006",
        name="XML External Entities (XXE) Disabled",
        category=ControlCategory.PARSER,
        description="XML parsers configured to disable entity expansion and external DTDs.",
        implementation="""
from xml.etree import ElementTree as ET

def safe_parse_xml(xml_string: str):
    # Disable XXE
    parser = ET.XMLParser()
    parser.parser.DefaultHandler = None
    parser.parser.ExternalEntityDeclHandler = None

    return ET.fromstring(xml_string, parser=parser)
        """,
        testing="Test with XXE payloads; all must be rejected",
        references=["CWE-611"]
    ),

    "C-007": Control(
        id="C-007",
        name="Deserialization Allowlist/Ban",
        category=ControlCategory.PARSER,
        description="Dangerous deserialization (pickle, Java serialization) banned. Safe formats only (JSON, MessagePack with allowlist).",
        implementation="""
# GOOD:
data = json.loads(user_input)

# OK (with allowlist):
import pickle
ALLOWED_CLASSES = {MyClass, OtherClass}

def safe_pickle_load(data):
    # Use RestrictedUnpickler or allowlist
    # Custom loader that only allows ALLOWED_CLASSES
    pass

# BAD (never do this):
# pickle.loads(untrusted_data)  # ← DANGEROUS
        """,
        testing="Attempt pickle payloads; all must be rejected",
        references=["CWE-502"]
    ),

    "C-008": Control(
        id="C-008",
        name="SSRF Outbound Allowlist + DNS Pinning",
        category=ControlCategory.NETWORK,
        description="Outbound requests validated against allowlist. DNS responses pinned to prevent rebinding.",
        implementation="""
import requests
import socket

ALLOWED_DOMAINS = ["api.trusted.com", "cdn.trusted.com"]

def safe_fetch(url: str) -> str:
    # Validate domain
    from urllib.parse import urlparse
    domain = urlparse(url).netloc

    if domain not in ALLOWED_DOMAINS:
        raise ValueError(f"Domain not allowed: {domain}")

    # Pin DNS: resolve once, use IP directly
    ip = socket.getaddrinfo(domain, 443)[0][4][0]

    # Fetch with pinned IP
    return requests.get(url)
        """,
        testing="Test with localhost:8080, 127.0.0.1, cloud metadata endpoints",
        references=["CWE-918"]
    ),

    "C-009": Control(
        id="C-009",
        name="Template Rendering Sandboxing",
        category=ControlCategory.PARSER,
        description="Template engines configured to sandbox execution. No arbitrary code in templates.",
        implementation="""
from jinja2 import Environment, select_autoescape

# GOOD: Sandboxed
env = Environment(
    autoescape=select_autoescape(['html', 'xml']),
    # Disable dangerous functions:
    trim_blocks=True,
    lstrip_blocks=True
)

# Don't allow custom globals/filters that call exec/eval
        """,
        testing="Test template with {system('id')} - must be escaped or rejected",
        references=["CWE-94"]
    ),

    "C-010": Control(
        id="C-010",
        name="Rate Limits + Payload Size Caps",
        category=ControlCategory.EXECUTION,
        description="Rate limiting on requests. Payload sizes capped. Prevents DoS and resource exhaustion.",
        implementation="""
from functools import wraps
import time

def rate_limit(max_per_second: int):
    def decorator(func):
        calls = []

        @wraps(func)
        def wrapper(*args, **kwargs):
            now = time.time()
            calls[:] = [t for t in calls if t > now - 1]

            if len(calls) >= max_per_second:
                raise Exception("Rate limit exceeded")

            calls.append(now)
            return func(*args, **kwargs)

        return wrapper
    return decorator

MAX_PAYLOAD = 10 * 1024 * 1024  # 10MB

@rate_limit(100)
def process_request(data):
    if len(data) > MAX_PAYLOAD:
        raise ValueError("Payload too large")
    # Process...
        """,
        testing="Send rapid requests and oversized payloads; both must be rejected",
        references=["CWE-400"]
    ),

    "C-011": Control(
        id="C-011",
        name="Privilege Drop + Sandbox Around Risky Ops",
        category=ControlCategory.AUTHZ,
        description="Dangerous operations run with minimal privileges. Use OS sandboxing (seccomp, pledge, pledge).",
        implementation="""
import os
import subprocess

def safe_unzip(archive_path: str, extract_dir: str):
    # Drop privileges before extraction
    os.setgid(65534)  # nobody group
    os.setuid(65534)  # nobody user

    # Or use seccomp/pledge to limit syscalls:
    # Linux: filter only: open, read, write, close, stat, mmap
    # OpenBSD: pledge("stdio rpath wpath cpath")

    subprocess.run(["unzip", archive_path, "-d", extract_dir], check=True)
        """,
        testing="Verify process runs as unprivileged user, cannot access /etc",
        references=["CWE-269"]
    ),

    "C-012": Control(
        id="C-012",
        name="Audit Logging on Trust Boundaries",
        category=ControlCategory.AUTHZ,
        description="All trust boundary crossings logged immutably. Who, what, when, where.",
        implementation="""
import json
import hashlib
from datetime import datetime

class AuditLog:
    def __init__(self, path: str):
        self.path = path
        self.last_hash = ""

    def log(self, actor: str, action: str, resource: str, result: str):
        entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "actor": actor,
            "action": action,
            "resource": resource,
            "result": result,
            "prev_hash": self.last_hash,
        }

        # Hash-chain for tamper detection
        entry_str = json.dumps(entry, sort_keys=True)
        entry["hash"] = hashlib.sha256(entry_str.encode()).hexdigest()

        with open(self.path, "a") as f:
            f.write(entry_str + "\\n")

        self.last_hash = entry["hash"]

audit = AuditLog("/var/log/app-audit.log")
audit.log("agent-123", "execute", "unzip", "success")
        """,
        testing="Verify logs are immutable (hash chain), cannot be forged",
        references=["CWE-778"]
    ),
}


def get_control(control_id: str) -> Control:
    """Get a control by ID"""
    if control_id not in STANDARD_CONTROLS:
        raise ValueError(f"Unknown control: {control_id}")
    return STANDARD_CONTROLS[control_id]


def list_controls_by_category(category: ControlCategory):
    """Get all controls in a category"""
    return [c for c in STANDARD_CONTROLS.values() if c.category == category]


def map_surface_to_controls(surface_type: str) -> List[str]:
    """Suggest controls for a surface type"""
    mapping = {
        "shell_injection": ["C-001", "C-002"],
        "path_traversal": ["C-003", "C-004"],
        "yaml_injection": ["C-005"],
        "xxe": ["C-006"],
        "deserialization": ["C-007"],
        "ssrf": ["C-008"],
        "template_injection": ["C-009"],
        "dos": ["C-010"],
        "privilege_escalation": ["C-011"],
        "audit": ["C-012"],
    }
    return mapping.get(surface_type, [])
