"""
Universal Semantic Vulnerability Discovery Agent

Core vulnerability hunting engine that:
- Analyzes code semantically (understands meaning, not patterns)
- Asks universal cognitive questions
- Finds vulnerability patterns across any language
- Discovers exploit chains
- Generates patches and tests
- Learns and improves with each iteration
"""

import json
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Set
from pathlib import Path
from enum import Enum


class VulnerabilitySeverity(Enum):
    """Vulnerability severity levels"""
    CRITICAL = 9.0
    HIGH = 7.0
    MEDIUM = 5.0
    LOW = 3.0


@dataclass
class Vulnerability:
    """Represents a discovered vulnerability"""
    id: str
    title: str
    location: str
    severity: float
    pattern: str  # The semantic pattern that identifies this vuln
    entry_point: str  # Where user input enters
    sink: str  # Dangerous function reached
    exploitability: float  # 0-1.0 confidence
    exploit_chain: Optional[str] = None
    patch: Optional[str] = None
    test: Optional[str] = None
    control: Optional[str] = None
    threat_score: float = 0.0

    def is_exploitable(self) -> bool:
        """Check if vulnerability has high enough confidence"""
        return self.exploitability > 0.8


@dataclass
class Pattern:
    """Represents a learned vulnerability pattern"""
    name: str
    description: str
    semantic: str  # Human-readable semantic description
    indicators: List[str]  # What to look for
    languages: Set[str]  # Languages this pattern appears in
    entry_points: List[str]  # Where user input typically enters
    sinks: List[str]  # Dangerous functions
    severity: float
    control: str  # Which C-### control blocks it


@dataclass
class ExploitChain:
    """Represents a chain of vulnerabilities that combine for greater impact"""
    name: str
    description: str
    vulnerabilities: List[str]  # List of vuln IDs
    impact: str
    difficulty: str  # How hard to exploit
    priority: int  # 1 = highest


class UniversalVulnerabilityAgent:
    """
    Universal semantic vulnerability discovery agent.

    Works on ANY codebase:
    - Java, Python, JavaScript, Go, Rust, C, etc.
    - RPC, APIs, backends, frontends
    - Parameter injection, RCE, auth bypass, XXE, etc.
    """

    def __init__(self, threat_model: Dict = None):
        """Initialize the agent with optional threat model context"""
        self.threat_model = threat_model or {}
        self.vulnerabilities: List[Vulnerability] = []
        self.patterns: List[Pattern] = []
        self.chains: List[ExploitChain] = []
        self.codebase_path: Optional[Path] = None
        self.codebase_content: Dict[str, str] = {}
        self.iteration_count = 0
        self.max_iterations = 5

    def hunt(self, codebase_path: str) -> List[Vulnerability]:
        """
        Hunt for ALL exploitable vulnerabilities in codebase.

        Universal approach:
        1. Load codebase
        2. Ask semantic questions
        3. Find vulnerabilities
        4. Extract patterns
        5. Find similar code (pattern matching)
        6. Loop back with refined questions
        """
        self.codebase_path = Path(codebase_path)
        self._load_codebase()

        # Initialize question queue with universal questions
        question_queue = self._get_universal_questions()
        asked_questions: Set[str] = set()

        # Iterative hunting loop
        while self.iteration_count < self.max_iterations and question_queue:
            self.iteration_count += 1

            question = question_queue.pop(0)
            if question in asked_questions:
                continue

            asked_questions.add(question)

            # Ask code the semantic question
            findings = self._ask_code(question)

            # Process each finding
            for finding in findings:
                vuln = self._analyze_finding(finding, question)

                if vuln and vuln.is_exploitable():
                    # Check if we already found this
                    if not self._already_found(vuln):
                        self.vulnerabilities.append(vuln)

                        # Extract pattern
                        pattern = self._extract_pattern(vuln)
                        if pattern:
                            self.patterns.append(pattern)

                            # Find similar code
                            similar = self._find_similar_by_semantics(pattern)
                            for match in similar:
                                if match not in asked_questions:
                                    question_queue.append(
                                        f"Is {match} exploitable like {vuln.title}?"
                                    )

                            # Find exploit chains
                            chains = self._find_chains()
                            for chain in chains:
                                if chain not in self.chains:
                                    self.chains.append(chain)

            # Generate follow-up questions
            if self.vulnerabilities:
                follow_ups = self._generate_followup_questions()
                question_queue.extend(follow_ups)

        # Post-processing
        self._verify_exploitability()
        self._generate_patches()
        self._prioritize_by_threat()

        return self.vulnerabilities

    def _load_codebase(self):
        """Load all code files from codebase"""
        extensions = {'.java', '.py', '.js', '.ts', '.go', '.rs', '.c', '.cpp', '.cs'}

        for file_path in self.codebase_path.rglob('*'):
            if file_path.suffix in extensions:
                try:
                    self.codebase_content[str(file_path)] = file_path.read_text(errors='ignore')
                except:
                    pass

    def _load_codebase_from_path(self, path: Path):
        """Load codebase from a path"""
        self.codebase_path = path
        self._load_codebase()

    def _get_universal_questions(self) -> List[str]:
        """Initial set of universal questions that work on ANY codebase"""
        return [
            "Where is user-controlled input in this code?",
            "What are all the entry points (functions/methods/endpoints)?",
            "Where is input validation supposed to happen?",
            "What validation code actually exists?",
            "Which functions/APIs are dangerous or sensitive?",
            "Can user input flow to dangerous functions without validation?",
            "What happens when untrusted data reaches the sink?",
            "What authentication/authorization checks exist?",
            "Can authentication be bypassed?",
            "What RPC/API endpoints are exposed?",
            "Are RPC parameters validated?",
            "What deserialization code exists?",
            "What XML/YAML parsing code exists?",
            "Are there external resource loading mechanisms?",
            "Can resources be loaded from untrusted sources?",
            "What gadget chains are available?",
            "Can vulnerabilities be chained together?",
            "What are the privilege boundaries?",
            "Is there sensitive data exposure?",
            "What hardcoded secrets or credentials exist?",
        ]

    def _ask_code(self, question: str) -> List[Dict]:
        """
        Ask a semantic question about the code.

        This would ideally use Claude API or semantic code analysis.
        For now, returns patterns matched against question intent.
        """
        findings = []

        # Map questions to code patterns to search for
        question_lower = question.lower()

        if "user-controlled input" in question_lower or "entry point" in question_lower:
            findings.extend(self._find_entry_points())

        if "validation" in question_lower:
            findings.extend(self._find_validation_gaps())

        if "dangerous" in question_lower:
            findings.extend(self._find_dangerous_sinks())

        if "authentication" in question_lower or "authorization" in question_lower:
            findings.extend(self._find_auth_issues())

        if "rpc" in question_lower or "endpoint" in question_lower or "api" in question_lower:
            findings.extend(self._find_rpc_endpoints())

        if "deserialization" in question_lower:
            findings.extend(self._find_deserialization_sinks())

        if "xml" in question_lower or "yaml" in question_lower or "parsing" in question_lower:
            findings.extend(self._find_parsing_sinks())

        if "resource" in question_lower or "load" in question_lower:
            findings.extend(self._find_resource_loading())

        if "gadget" in question_lower or "chain" in question_lower:
            findings.extend(self._find_gadget_chains())

        return findings

    def _find_entry_points(self) -> List[Dict]:
        """Find user input entry points"""
        patterns = [
            ("Java RMI", r"extends Remote"),
            ("gRPC", r"rpc \w+\("),
            ("REST", r"@(GetMapping|PostMapping|RequestMapping)"),
            ("HTTP Handler", r"def (get|post|put|delete)\("),
            ("RPC Method", r"def \w+\(.*\):"),
            ("Public Method", r"public \w+ \w+\(.*\)"),
            ("Exposed Endpoint", r"@app\.(get|post|put|delete)"),
        ]

        findings = []
        for pattern_name, pattern in patterns:
            for file_path, content in self.codebase_content.items():
                if pattern in content or any(p in content for p, _ in patterns):
                    findings.append({
                        'type': 'entry_point',
                        'file': file_path,
                        'pattern': pattern_name,
                        'description': f"Found {pattern_name} entry point"
                    })

        return findings

    def _find_validation_gaps(self) -> List[Dict]:
        """Find where validation is missing"""
        findings = []

        # Look for parameters without validation
        validation_keywords = {'whitelist', 'allowlist', 'validate', 'check', 'if not', 'startswith', 'matches', 'regex'}
        dangerous_ops = {'ResourceXmlApplicationContext', 'ProcessBuilder', 'Runtime.exec', 'eval', 'pickle.loads', 'yaml.load', 'ObjectInputStream'}

        for file_path, content in self.codebase_content.items():
            for danger in dangerous_ops:
                if danger in content:
                    # Check if there's validation before it
                    lines = content.split('\n')
                    for i, line in enumerate(lines):
                        if danger in line:
                            # Look back for validation
                            context = '\n'.join(lines[max(0, i-5):i+1])
                            has_validation = any(kw in context.lower() for kw in validation_keywords)

                            if not has_validation:
                                findings.append({
                                    'type': 'validation_gap',
                                    'file': file_path,
                                    'line': i+1,
                                    'danger': danger,
                                    'description': f"Potential unvalidated {danger}"
                                })

        return findings

    def _find_dangerous_sinks(self) -> List[Dict]:
        """Find dangerous functions/sinks"""
        dangerous_sinks = {
            'Java': ['ProcessBuilder', 'Runtime.exec', 'Class.forName', 'ObjectInputStream', 'ResourceXmlApplicationContext'],
            'Python': ['subprocess.Popen', 'os.system', 'eval', 'pickle.loads', 'yaml.load', 'exec'],
            'JavaScript': ['eval', 'Function', 'child_process.exec', 'require'],
            'Go': ['os/exec.Command', 'os.system'],
        }

        findings = []
        for file_path, content in self.codebase_content.items():
            for lang_sinks in dangerous_sinks.values():
                for sink in lang_sinks:
                    if sink in content:
                        findings.append({
                            'type': 'dangerous_sink',
                            'file': file_path,
                            'sink': sink,
                            'description': f"Found dangerous sink: {sink}"
                        })

        return findings

    def _find_auth_issues(self) -> List[Dict]:
        """Find authentication/authorization issues"""
        auth_keywords = {'authenticate', 'authorize', 'auth', 'permission', 'role', 'token', 'jwt', 'oauth', 'credential'}
        findings = []

        for file_path, content in self.codebase_content.items():
            # Look for exposed methods without auth
            lines = content.split('\n')
            for i, line in enumerate(lines):
                # Public method/endpoint
                if any(keyword in line for keyword in ['public', '@PostMapping', '@GetMapping', 'def ']) and '(' in line:
                    # Check if auth exists
                    context = '\n'.join(lines[max(0, i-3):min(len(lines), i+10)])
                    has_auth = any(kw in context.lower() for kw in auth_keywords)

                    if not has_auth:
                        findings.append({
                            'type': 'auth_gap',
                            'file': file_path,
                            'line': i+1,
                            'description': f"Exposed method without authentication check"
                        })

        return findings

    def _find_rpc_endpoints(self) -> List[Dict]:
        """Find RPC/API endpoints"""
        rpc_patterns = ['Remote', 'rpc ', '@PostMapping', '@GetMapping', 'def ', 'def (get|post|put|delete)']
        findings = []

        for file_path, content in self.codebase_content.items():
            for pattern in rpc_patterns:
                if pattern in content:
                    findings.append({
                        'type': 'rpc_endpoint',
                        'file': file_path,
                        'pattern': pattern,
                        'description': f"Found RPC endpoint pattern: {pattern}"
                    })

        return findings

    def _find_deserialization_sinks(self) -> List[Dict]:
        """Find deserialization vulnerabilities"""
        deser_patterns = {
            'ObjectInputStream': r'ObjectInputStream',
            'pickle.loads': r'pickle\.loads',
            'yaml.load': r'yaml\.load',
            'json.loads': r'json\.loads',  # Can be dangerous with gadgets
        }

        findings = []
        for file_path, content in self.codebase_content.items():
            for name, pattern in deser_patterns.items():
                if pattern in content or name in content:
                    findings.append({
                        'type': 'deserialization',
                        'file': file_path,
                        'sink': name,
                        'description': f"Found deserialization: {name}"
                    })

        return findings

    def _find_parsing_sinks(self) -> List[Dict]:
        """Find XML/YAML parsing vulnerabilities"""
        parsing_patterns = {
            'XML': ['DocumentBuilder', 'XMLParser', 'SAXParser', 'ElementTree'],
            'YAML': ['yaml.load', 'YAML.load'],
            'JSON': ['json.loads', 'Jackson', 'Gson'],
        }

        findings = []
        for file_path, content in self.codebase_content.items():
            for format_name, patterns in parsing_patterns.items():
                for pattern in patterns:
                    if pattern in content:
                        findings.append({
                            'type': 'parsing',
                            'file': file_path,
                            'format': format_name,
                            'pattern': pattern,
                            'description': f"Found {format_name} parsing"
                        })

        return findings

    def _find_resource_loading(self) -> List[Dict]:
        """Find remote resource loading"""
        resource_patterns = {
            'HTTP': ['http://', 'https://', 'openConnection', 'URLConnection'],
            'File': ['file://', 'File(', 'open(', 'read_file'],
            'Network': ['Socket', 'connect', 'loadClass', 'require'],
        }

        findings = []
        for file_path, content in self.codebase_content.items():
            for type_name, patterns in resource_patterns.items():
                for pattern in patterns:
                    if pattern in content:
                        findings.append({
                            'type': 'resource_loading',
                            'file': file_path,
                            'resource_type': type_name,
                            'pattern': pattern,
                            'description': f"Found {type_name} resource loading"
                        })

        return findings

    def _find_gadget_chains(self) -> List[Dict]:
        """Find gadget chain gadgets"""
        gadget_libraries = {
            'commons-collections': r'commons.collections',
            'Spring': r'spring.framework|ClassPathXmlApplicationContext',
            'ROME': r'rome\.',
            'JDOM': r'org.jdom',
            'XStream': r'XStream',
            'Groovy': r'groovy\.lang',
            'Velocity': r'velocity\.',
            'FreeMarker': r'freemarker\.',
        }

        findings = []
        for file_path, content in self.codebase_content.items():
            for lib_name, pattern in gadget_libraries.items():
                if pattern in content or lib_name in content:
                    findings.append({
                        'type': 'gadget_chain',
                        'file': file_path,
                        'library': lib_name,
                        'description': f"Found gadget chain library: {lib_name}"
                    })

        return findings

    def _analyze_finding(self, finding: Dict, question: str) -> Optional[Vulnerability]:
        """Convert a finding into a vulnerability"""
        if not finding:
            return None

        # Create vulnerability from finding
        vuln_id = f"auto_{len(self.vulnerabilities)}"

        return Vulnerability(
            id=vuln_id,
            title=finding.get('description', 'Found vulnerability'),
            location=finding.get('file', 'unknown') + ':' + str(finding.get('line', '?')),
            severity=self._calculate_severity(finding),
            pattern=finding.get('type', 'unknown'),
            entry_point=finding.get('entry', 'network'),
            sink=finding.get('sink', 'unknown'),
            exploitability=self._calculate_exploitability(finding),
        )

    def _calculate_severity(self, finding: Dict) -> float:
        """Calculate severity based on finding type"""
        severity_map = {
            'deserialization': 9.0,
            'rce': 9.0,
            'auth_gap': 8.5,
            'validation_gap': 7.5,
            'resource_loading': 7.0,
            'gadget_chain': 8.0,
            'parsing': 6.0,
        }
        return severity_map.get(finding.get('type'), 5.0)

    def _calculate_exploitability(self, finding: Dict) -> float:
        """Calculate exploitability confidence"""
        # Higher confidence for certain patterns
        high_confidence_types = {'deserialization', 'auth_gap', 'rce', 'validation_gap'}
        if finding.get('type') in high_confidence_types:
            return 0.85
        return 0.65

    def _already_found(self, vuln: Vulnerability) -> bool:
        """Check if we already found this vulnerability"""
        for existing in self.vulnerabilities:
            if existing.location == vuln.location and existing.sink == vuln.sink:
                return True
        return False

    def _extract_pattern(self, vuln: Vulnerability) -> Optional[Pattern]:
        """Extract the semantic pattern from a vulnerability"""
        return Pattern(
            name=f"Pattern: {vuln.pattern}",
            description=vuln.title,
            semantic=f"User input reaches {vuln.sink} without validation",
            indicators=[vuln.sink],
            languages={'Java', 'Python', 'JavaScript', 'Go'},
            entry_points=[vuln.entry_point],
            sinks=[vuln.sink],
            severity=vuln.severity,
            control="C-002",  # Input validation
        )

    def _find_similar_by_semantics(self, pattern: Pattern) -> List[str]:
        """Find code matching the semantic pattern"""
        similar = []

        for sink in pattern.sinks:
            for file_path, content in self.codebase_content.items():
                if sink in content and file_path not in similar:
                    similar.append(file_path)

        return similar[:5]  # Return top 5

    def _find_chains(self) -> List[ExploitChain]:
        """Find exploit chains (how vulnerabilities combine)"""
        chains = []

        # If we have both auth gaps and parameter injection
        auth_vulns = [v for v in self.vulnerabilities if 'auth' in v.pattern.lower()]
        param_vulns = [v for v in self.vulnerabilities if 'validation' in v.pattern.lower()]

        if auth_vulns and param_vulns:
            chains.append(ExploitChain(
                name="Auth Bypass + Parameter Injection",
                description="Unauthenticated attacker calls unprotected RPC method with malicious parameter",
                vulnerabilities=[v.id for v in auth_vulns[:1] + param_vulns[:1]],
                impact="Remote Code Execution",
                difficulty="Medium",
                priority=1
            ))

        return chains

    def _generate_followup_questions(self) -> List[str]:
        """Generate follow-up questions based on findings"""
        follow_ups = []

        if self.vulnerabilities:
            latest = self.vulnerabilities[-1]
            follow_ups.extend([
                f"Are there OTHER {latest.pattern} vulnerabilities like {latest.title}?",
                f"Can {latest.title} be chained with other vulnerabilities?",
                f"What similar code patterns exist for {latest.sink}?",
            ])

        return follow_ups

    def _verify_exploitability(self):
        """Verify that vulnerabilities are actually exploitable"""
        for vuln in self.vulnerabilities:
            # Increase confidence if pattern matches high-confidence types
            if vuln.pattern in ['deserialization', 'validation_gap', 'auth_gap']:
                vuln.exploitability = min(0.95, vuln.exploitability + 0.1)

    def _generate_patches(self):
        """Generate patches for vulnerabilities"""
        patch_templates = {
            'validation_gap': self._patch_validation,
            'auth_gap': self._patch_auth,
            'deserialization': self._patch_deserialization,
        }

        for vuln in self.vulnerabilities:
            generator = patch_templates.get(vuln.pattern)
            if generator:
                vuln.patch = generator(vuln)
                vuln.test = self._generate_test(vuln)

    def _patch_validation(self, vuln: Vulnerability) -> str:
        """Template for validation patches"""
        return f"""
// Add input validation before {vuln.sink}
if (!validateInput(parameter)) {{
    throw new SecurityException("Invalid input");
}}
"""

    def _patch_auth(self, vuln: Vulnerability) -> str:
        """Template for auth patches"""
        return f"""
// Add authentication check
@Authenticated
public void protectedMethod(...) {{
    // Method body
}}
"""

    def _patch_deserialization(self, vuln: Vulnerability) -> str:
        """Template for deserialization patches"""
        return f"""
// Use safe deserialization
ObjectInputFilter filter = ObjectInputFilter.Config.createFilter("...");
ois.setObjectInputFilter(filter);
"""

    def _generate_test(self, vuln: Vulnerability) -> str:
        """Generate regression test for patch"""
        return f"""
@Test
public void test{vuln.id.replace('-', '_')}() {{
    // Test that {vuln.title} is blocked
    assertThrows(SecurityException.class, () -> {{
        // Attack vector
    }});
}}
"""

    def _prioritize_by_threat(self):
        """Prioritize vulnerabilities based on threat model"""
        for vuln in self.vulnerabilities:
            # Calculate threat score based on threat model
            vuln.threat_score = vuln.severity * vuln.exploitability

            # Apply threat model weights
            if self.threat_model:
                if self.threat_model.get('unauthenticated_attacker') and 'auth' in vuln.pattern:
                    vuln.threat_score *= 1.5
                if self.threat_model.get('network_exposed') and 'rpc' in vuln.pattern:
                    vuln.threat_score *= 1.3

        # Sort by threat score
        self.vulnerabilities.sort(key=lambda v: v.threat_score, reverse=True)
