"""
Hypothesis generator for ChiefWiggum - Auto-generates common vulnerability patterns
"""

from pathlib import Path
from typing import List


def generate_injection_hypotheses():
    """Generate injection-based vulnerability hypotheses"""
    injections = []
    sources = ["HTTP parameter", "URL", "database", "config file", "network message", "file input"]
    # Use actual dangerous function/API names that exist in ActiveMQ
    sinks = ["executeQuery", "executeUpdate", "InitialContext"]

    for i, source in enumerate(sources):
        for j, sink in enumerate(sinks):
            hyp_id = f"hyp_inj_{i}_{j}_injection"
            injections.append({
                "id": hyp_id,
                "title": f"Injection via {sink} from {source}",
                "control": "C-002",
                "sink": sink,
                "description": f"Unsanitized {source} passed to {sink} without input validation"
            })
    return injections

def generate_deserialization_hypotheses():
    """Generate deserialization attack hypotheses"""
    deser = []
    # Map formats to actual dangerous methods
    sink_mappings = ["ObjectInputStream", "readObject", "Class.forName", "getConstructor", "newInstance"]
    gadget_chains = ["commons-collections", "Spring framework", "ROME", "Rome", "JDOM", "XStream"]

    for i, sink in enumerate(sink_mappings):
        for j, gadget in enumerate(gadget_chains):
            hyp_id = f"hyp_deser_{i}_{j}"
            deser.append({
                "id": hyp_id,
                "title": f"Deserialization RCE via {sink} gadget:{gadget}",
                "control": "C-007",
                "sink": sink,
                "description": f"Untrusted object deserialized via {sink} enabling {gadget} gadget chain RCE"
            })
    return deser

def generate_xxe_ssrf_hypotheses():
    """Generate XXE and SSRF hypotheses"""
    xxe_ssrf = []
    # XXE patterns - use actual XML parser functions
    xml_parsers = ["XMLInputFactory", "DocumentBuilderFactory", "SAXParserFactory"]
    for i in range(20):
        parser = xml_parsers[i % len(xml_parsers)]
        xxe_ssrf.append({
            "id": f"hyp_xxe_{i}",
            "title": f"XXE via {parser} variant {i}",
            "control": "C-006",
            "sink": parser,
            "description": f"External entity expansion in {parser} without DTD/entity restrictions"
        })
    # SSRF patterns
    for i in range(20):
        xxe_ssrf.append({
            "id": f"hyp_ssrf_{i}",
            "title": f"SSRF via HTTP client variant {i}",
            "control": "C-008",
            "sink": "HTTP client",
            "description": "Untrusted URL used in outbound request without destination validation"
        })
    return xxe_ssrf

def generate_auth_session_hypotheses():
    """Generate authentication and session management vulnerabilities"""
    auth = []
    auth_issues = [
        ("weak_password_hash", "MD5/SHA1 password hashing", "C-011"),
        ("default_credentials", "Default username/password", "C-011"),
        ("hardcoded_secret", "Hardcoded API key/secret", "C-011"),
        ("jwt_no_verify", "JWT signature not verified", "C-011"),
        ("session_fixation", "Session ID not regenerated on login", "C-012"),
        ("brute_force", "No rate limiting on login", "C-010"),
        ("session_storage_plain", "Session tokens in plaintext", "C-011"),
        ("oauth_token_leak", "OAuth token exposed in logs/URLs", "C-012"),
    ]

    for i, (issue_id, title, control) in enumerate(auth_issues):
        for variant in range(10):
            auth.append({
                "id": f"hyp_auth_{i}_{variant}",
                "title": f"{title} variant {variant}",
                "control": control,
                "sink": "authentication handler",
                "description": f"Vulnerability in auth: {title}"
            })
    return auth

def generate_input_validation_hypotheses():
    """Generate input validation vulnerability hypotheses"""
    validation = []
    validation_types = [
        ("buffer_overflow", "Buffer allocation from user size", "C-010"),
        ("integer_overflow", "Integer arithmetic on user input", "C-010"),
        ("path_traversal", "File path from user input", "C-003"),
        ("symlink_attack", "Symlink following without validation", "C-003"),
        ("null_pointer", "Null check missing on user data", "C-010"),
        ("type_confusion", "Type not validated on user input", "C-002"),
        ("format_string", "User input as format string", "C-010"),
        ("array_bounds", "Array index from user without bounds", "C-010"),
    ]

    for i, (vuln_type, desc, control) in enumerate(validation_types):
        for variant in range(15):
            validation.append({
                "id": f"hyp_validate_{i}_{variant}",
                "title": f"{vuln_type.replace('_', ' ').title()} {variant}",
                "control": control,
                "sink": "input handler",
                "description": desc
            })
    return validation

HYPOTHESIS_TEMPLATES = [
    # C-001: Shell Execution Wrapper
    {
        "id": "hyp_001_shell_injection_system_call",
        "title": "Shell Injection via system() call",
        "control": "C-001",
        "sink": "system()",
        "description": "Unsanitized user input passed to system() without shell metacharacter validation",
    },
    {
        "id": "hyp_002_shell_injection_popen",
        "title": "Shell Injection via popen()",
        "control": "C-001",
        "sink": "popen()",
        "description": "Command constructed from user input and passed to popen() without quoting",
    },
    {
        "id": "hyp_003_shell_injection_runtime_exec",
        "title": "Shell Injection via Runtime.exec()",
        "control": "C-001",
        "sink": "Runtime.exec()",
        "description": "String command passed to Runtime.exec() invokes shell, enabling command injection",
    },
    {
        "id": "hyp_004_process_builder_injection",
        "title": "Process Injection via ProcessBuilder",
        "control": "C-001",
        "sink": "ProcessBuilder",
        "description": "ProcessBuilder argument list constructed from untrusted input without sanitization",
    },

    # C-002: Argument Allowlist
    {
        "id": "hyp_005_argument_metacharacters",
        "title": "Shell Metacharacters in Command Arguments",
        "control": "C-002",
        "sink": "command argument processing",
        "description": "Arguments containing shell metacharacters (|, ;, &, >, <, etc.) not filtered",
    },
    {
        "id": "hyp_006_path_traversal_argument",
        "title": "Path Traversal in Command Arguments",
        "control": "C-002",
        "sink": "argument validation",
        "description": "Command arguments accepting ../ or absolute paths without allowlist",
    },

    # C-003: Path Canonicalization
    {
        "id": "hyp_007_symlink_attack",
        "title": "Symlink Attack on File Operations",
        "control": "C-003",
        "sink": "File.open() / fopen()",
        "description": "File path not canonicalized before opening; symlinks can redirect to sensitive files",
    },
    {
        "id": "hyp_008_path_traversal_directory",
        "title": "Path Traversal via Directory Traversal",
        "control": "C-003",
        "sink": "file path handling",
        "description": "Relative path with ../ traverses out of intended directory without canonicalization",
    },
    {
        "id": "hyp_009_relative_path_escape",
        "title": "Relative Path Escape",
        "control": "C-003",
        "sink": "path resolution",
        "description": "Relative paths resolved against untrusted working directory or base",
    },

    # C-004: Zip/Tar Safe Extract
    {
        "id": "hyp_010_zip_symlink_extract",
        "title": "Symlink Extraction from ZIP",
        "control": "C-004",
        "sink": "ZipInputStream.getNextEntry()",
        "description": "ZIP archive extraction creates symlinks pointing outside intended directory",
    },
    {
        "id": "hyp_011_tar_path_traversal",
        "title": "Path Traversal in TAR Extraction",
        "control": "C-004",
        "sink": "TarInputStream",
        "description": "TAR member with ../ path traverses out of extraction directory",
    },
    {
        "id": "hyp_012_archive_bomb",
        "title": "Archive Bomb (Zip/Tar DoS)",
        "control": "C-004",
        "sink": "archive extraction",
        "description": "No size limit checks; extracting malicious archive exhausts disk/memory",
    },

    # C-005: YAML Safe Loader
    {
        "id": "hyp_013_yaml_unsafe_load",
        "title": "Unsafe YAML Deserialization",
        "control": "C-005",
        "sink": "yaml.load()",
        "description": "yaml.load() used instead of yaml.safe_load(); enables arbitrary code execution",
    },
    {
        "id": "hyp_014_yaml_gadget_chain",
        "title": "YAML Gadget Chain Exploitation",
        "control": "C-005",
        "sink": "YAML parser",
        "description": "YAML payload with malicious object graph triggers RCE via gadget chain",
    },

    # C-006: XXE Disabled
    {
        "id": "hyp_015_xxe_entity_expansion",
        "title": "XXE File Read via Entity Expansion",
        "control": "C-006",
        "sink": "XMLDecoder / XML parser",
        "description": "External entity resolution enabled; allows file:// URI reads",
    },
    {
        "id": "hyp_016_xxe_billion_laughs",
        "title": "XXE Billion Laughs (XML Bomb)",
        "control": "C-006",
        "sink": "XML entity expansion",
        "description": "Nested entity expansion causes exponential memory growth (DoS)",
    },
    {
        "id": "hyp_017_xxe_ssrf",
        "title": "XXE Server-Side Request Forgery",
        "control": "C-006",
        "sink": "XML parser with DOCTYPE",
        "description": "XXE payload forces server to make requests to internal services",
    },

    # C-007: Deserialization Allowlist
    {
        "id": "hyp_018_java_deserialization_rce",
        "title": "Java Deserialization RCE",
        "control": "C-007",
        "sink": "ObjectInputStream.readObject()",
        "description": "Untrusted serialized object deserialized without gadget chain protection",
    },
    {
        "id": "hyp_019_python_pickle_rce",
        "title": "Python Pickle Deserialization RCE",
        "control": "C-007",
        "sink": "pickle.loads()",
        "description": "Untrusted pickle data executed; allows arbitrary code execution",
    },
    {
        "id": "hyp_020_class_forname_reflection",
        "title": "Unsafe Class.forName() with Reflection",
        "control": "C-007",
        "sink": "Class.forName() + newInstance()",
        "description": "Class name from user input; attackers load malicious classes",
    },
    {
        "id": "hyp_021_unsafe_reflection",
        "title": "Unsafe Reflection with User Input",
        "control": "C-007",
        "sink": "Method.invoke()",
        "description": "Method name or class name from untrusted source; enables arbitrary method calls",
    },

    # C-008: SSRF Outbound Allowlist
    {
        "id": "hyp_022_ssrf_file_protocol",
        "title": "SSRF via file:// Protocol",
        "control": "C-008",
        "sink": "URL.openConnection() / HttpClient",
        "description": "URL from user input; file:// protocol reads local files",
    },
    {
        "id": "hyp_023_ssrf_internal_network",
        "title": "SSRF to Internal Network",
        "control": "C-008",
        "sink": "HTTP client",
        "description": "Server makes HTTP request to attacker-controlled URL; internal service accessed",
    },
    {
        "id": "hyp_024_ssrf_gopher_protocol",
        "title": "SSRF via Gopher Protocol",
        "control": "C-008",
        "sink": "URL handler",
        "description": "Gopher protocol handler allows SSRF to interact with legacy services",
    },
    {
        "id": "hyp_025_dns_rebinding",
        "title": "DNS Rebinding SSRF",
        "control": "C-008",
        "sink": "DNS resolution",
        "description": "Attacker controls DNS; resolves to internal IP on second lookup",
    },

    # C-009: Template Rendering Sandboxing
    {
        "id": "hyp_026_spel_injection",
        "title": "Spring Expression Language (SpEL) Injection",
        "control": "C-009",
        "sink": "SpelExpressionParser.parseExpression()",
        "description": "User input evaluated as SpEL; enables arbitrary method calls and RCE",
    },
    {
        "id": "hyp_027_ognl_injection",
        "title": "OGNL Injection",
        "control": "C-009",
        "sink": "Ognl.getValue()",
        "description": "Object-Graph Navigation Language expression from user input; RCE via method invocation",
    },
    {
        "id": "hyp_028_velocity_template_injection",
        "title": "Velocity Template Injection",
        "control": "C-009",
        "sink": "VelocityEngine.evaluate()",
        "description": "User-controlled template content evaluated; runtime method calls possible",
    },
    {
        "id": "hyp_029_freemarker_injection",
        "title": "FreeMarker Template Injection",
        "control": "C-009",
        "sink": "Template.process()",
        "description": "Untrusted FreeMarker template allows object instantiation and method invocation",
    },
    {
        "id": "hyp_030_groovy_script_execution",
        "title": "Groovy Script Execution",
        "control": "C-009",
        "sink": "GroovyShell.evaluate()",
        "description": "Groovy code from user input executed; full Java access available",
    },
    {
        "id": "hyp_031_javascript_eval",
        "title": "JavaScript eval() Injection",
        "control": "C-009",
        "sink": "ScriptEngineManager.eval()",
        "description": "JavaScript from user input evaluated; enables arbitrary code execution",
    },

    # C-010: Rate Limits + Payload Size Caps
    {
        "id": "hyp_032_dos_unbounded_allocation",
        "title": "Denial of Service via Unbounded Memory Allocation",
        "control": "C-010",
        "sink": "malloc / new / memory allocation",
        "description": "User-controlled size parameter allows allocation of huge memory blocks",
    },
    {
        "id": "hyp_033_dos_cpu_intensive",
        "title": "Denial of Service via CPU Intensive Operation",
        "control": "C-010",
        "sink": "cryptographic operations / regex",
        "description": "Attacker provides input that triggers exponential computation time",
    },
    {
        "id": "hyp_034_regex_dos",
        "title": "Regular Expression Denial of Service (ReDoS)",
        "control": "C-010",
        "sink": "Matcher.find() / Pattern.compile()",
        "description": "Regex with catastrophic backtracking; input causes excessive CPU usage",
    },
    {
        "id": "hyp_035_algorithm_complexity_attack",
        "title": "Algorithmic Complexity Attack",
        "control": "C-010",
        "sink": "hash table / sorting",
        "description": "Attacker crafts input to trigger worst-case algorithm complexity",
    },

    # C-011: Privilege Drop + Sandbox
    {
        "id": "hyp_036_privilege_escalation_sudo",
        "title": "Privilege Escalation via Sudo Misconfiguration",
        "control": "C-011",
        "sink": "sudoers rules",
        "description": "setuid binary or sudo rule allows privilege escalation",
    },
    {
        "id": "hyp_037_unsafe_file_permissions",
        "title": "Unsafe File Permissions",
        "control": "C-011",
        "sink": "File.setReadable() / chmod",
        "description": "Temporary files created with world-readable permissions; secrets exposed",
    },
    {
        "id": "hyp_038_race_condition_toctou",
        "title": "Time-of-Check-Time-of-Use (TOCTOU) Race",
        "control": "C-011",
        "sink": "file operations",
        "description": "Check permission, then use file; attacker modifies file between operations",
    },

    # C-012: Audit Logging
    {
        "id": "hyp_039_missing_authentication_log",
        "title": "Missing Authentication Failure Logging",
        "control": "C-012",
        "sink": "authentication handler",
        "description": "Login failures not logged; attackers can probe accounts silently",
    },
    {
        "id": "hyp_040_privilege_escalation_unlogged",
        "title": "Unlogged Privilege Escalation Attempt",
        "control": "C-012",
        "sink": "authorization checks",
        "description": "Privilege escalation attempts not audited; attacks undetectable",
    },
    {
        "id": "hyp_041_sensitive_data_in_logs",
        "title": "Sensitive Data Exposure in Logs",
        "control": "C-012",
        "sink": "logging framework",
        "description": "Passwords, tokens, or PII logged to disk; exposure via log files",
    },

    # Language/Framework Specific
    {
        "id": "hyp_042_sql_injection",
        "title": "SQL Injection",
        "control": "C-002",
        "sink": "SQL execution",
        "description": "SQL query concatenated with user input; database compromise via injection",
    },
    {
        "id": "hyp_043_ldap_injection",
        "title": "LDAP Injection",
        "control": "C-002",
        "sink": "LDAP query",
        "description": "LDAP filter constructed from user input; authentication bypass or data exfiltration",
    },
    {
        "id": "hyp_044_xpath_injection",
        "title": "XPath Injection",
        "control": "C-002",
        "sink": "XPath query",
        "description": "XPath expression from user input; XML data extracted without authorization",
    },
    {
        "id": "hyp_045_command_injection_os_execute",
        "title": "OS Command Injection",
        "control": "C-001",
        "sink": "os.system() / subprocess",
        "description": "OS command constructed from user input; arbitrary command execution",
    },

    # Web/Network Security
    {
        "id": "hyp_046_xss_reflected",
        "title": "Reflected XSS",
        "control": "C-009",
        "sink": "HTML output",
        "description": "User input reflected in HTML without encoding; JavaScript execution in browser",
    },
    {
        "id": "hyp_047_xss_stored",
        "title": "Stored XSS",
        "control": "C-009",
        "sink": "database / HTML output",
        "description": "User input stored and later rendered; persistent JavaScript injection",
    },
    {
        "id": "hyp_048_csrf_token_missing",
        "title": "Cross-Site Request Forgery (CSRF) - Missing Token",
        "control": "C-012",
        "sink": "request validation",
        "description": "State-changing requests not protected by CSRF tokens; attacker forces action",
    },
    {
        "id": "hyp_049_cors_misconfiguration",
        "title": "CORS Misconfiguration",
        "control": "C-008",
        "sink": "CORS headers",
        "description": "Overly permissive CORS policy; any origin can access sensitive endpoints",
    },
    {
        "id": "hyp_050_open_redirect",
        "title": "Open Redirect",
        "control": "C-008",
        "sink": "redirect URL",
        "description": "Redirect parameter not validated; user redirected to attacker's site for phishing",
    },

    # Authentication/Session
    {
        "id": "hyp_051_weak_password_hash",
        "title": "Weak Password Hashing (MD5/SHA1)",
        "control": "C-011",
        "sink": "password hashing",
        "description": "Passwords hashed with weak algorithms; rainbow table attacks feasible",
    },
    {
        "id": "hyp_052_session_fixation",
        "title": "Session Fixation",
        "control": "C-012",
        "sink": "session management",
        "description": "Session ID not regenerated after login; attacker hijacks pre-login session",
    },
    {
        "id": "hyp_053_insecure_jwt",
        "title": "Insecure JWT Signature Verification",
        "control": "C-011",
        "sink": "JWT validation",
        "description": "JWT signature not verified or uses weak secret; token forgery possible",
    },
    {
        "id": "hyp_054_oauth_token_leak",
        "title": "OAuth Token Exposure in Logs/URLs",
        "control": "C-012",
        "sink": "token handling",
        "description": "Bearer tokens logged or visible in URLs; session hijacking via token theft",
    },

    # Cryptography
    {
        "id": "hyp_055_hardcoded_secret",
        "title": "Hardcoded Cryptographic Secret",
        "control": "C-011",
        "sink": "key management",
        "description": "API key or encryption key hardcoded in source; compromise via code access",
    },
    {
        "id": "hyp_056_weak_encryption_algorithm",
        "title": "Use of Weak Encryption (DES, RC4)",
        "control": "C-011",
        "sink": "cipher suite",
        "description": "Cryptographically broken algorithm used; plaintext recovery possible",
    },
    {
        "id": "hyp_057_missing_iv_randomization",
        "title": "Missing IV Randomization",
        "control": "C-011",
        "sink": "cipher mode",
        "description": "IV reused across encryptions; patterns leaked via ciphertext comparison",
    },

    # Data Validation
    {
        "id": "hyp_058_integer_overflow",
        "title": "Integer Overflow",
        "control": "C-010",
        "sink": "arithmetic operation",
        "description": "Integer arithmetic overflows; buffer allocation or loop iteration affected",
    },
    {
        "id": "hyp_059_buffer_overflow",
        "title": "Buffer Overflow",
        "control": "C-010",
        "sink": "strcpy / memcpy",
        "description": "Bounded buffer receives unbounded input; stack/heap corruption",
    },
    {
        "id": "hyp_060_format_string_attack",
        "title": "Format String Vulnerability",
        "control": "C-010",
        "sink": "printf / sprintf",
        "description": "User input used as format string; memory read/write via %x / %n",
    },

    # Information Disclosure
    {
        "id": "hyp_061_directory_listing_enabled",
        "title": "Directory Listing Enabled",
        "control": "C-003",
        "sink": "web server configuration",
        "description": "Directory listing not disabled; attacker enumerates files and structure",
    },
    {
        "id": "hyp_062_error_message_information_leak",
        "title": "Information Disclosure via Error Messages",
        "control": "C-012",
        "sink": "error handler",
        "description": "Detailed error messages expose stack traces, file paths, or configuration",
    },
    {
        "id": "hyp_063_timing_attack",
        "title": "Timing Attack on Secrets",
        "control": "C-011",
        "sink": "comparison operation",
        "description": "String comparison timing varies with correct characters; password guessing via timing",
    },

    # Access Control
    {
        "id": "hyp_064_broken_access_control",
        "title": "Broken Access Control - Direct Object Reference",
        "control": "C-012",
        "sink": "authorization check",
        "description": "User ID in request not validated; attacker accesses other users' data via ID manipulation",
    },
    {
        "id": "hyp_065_insecure_deserialization_gadget",
        "title": "Gadget Chain in Deserialization",
        "control": "C-007",
        "sink": "object deserialization",
        "description": "Dangerous classes in gadget chain (commons-collections, etc.); RCE via object graph",
    },

    # API/Protocol
    {
        "id": "hyp_066_insecure_api_version",
        "title": "Insecure API Version",
        "control": "C-012",
        "sink": "API endpoint",
        "description": "Legacy API version with known vulnerabilities; attacker uses deprecated endpoint",
    },
    {
        "id": "hyp_067_missing_rate_limiting",
        "title": "Missing Rate Limiting",
        "control": "C-010",
        "sink": "request handler",
        "description": "Endpoint lacks rate limiting; brute force or DoS attacks succeed",
    },

    # Supply Chain
    {
        "id": "hyp_068_vulnerable_dependency",
        "title": "Vulnerable Third-Party Library",
        "control": "C-012",
        "sink": "dependency",
        "description": "Outdated or vulnerable library imported; known CVE exploitable",
    },

    # Misc Common
    {
        "id": "hyp_069_null_pointer_dereference",
        "title": "Null Pointer Dereference",
        "control": "C-010",
        "sink": "pointer dereference",
        "description": "Null check missing; attacker triggers crash via null input",
    },
    {
        "id": "hyp_070_uninitialized_variable",
        "title": "Use of Uninitialized Variable",
        "control": "C-010",
        "sink": "variable initialization",
        "description": "Variable used before initialization; data leakage or crash possible",
    },
    {
        "id": "hyp_071_use_after_free",
        "title": "Use After Free",
        "control": "C-010",
        "sink": "memory management",
        "description": "Memory freed but pointer still used; information leak or code execution",
    },
    {
        "id": "hyp_072_double_free",
        "title": "Double Free",
        "control": "C-010",
        "sink": "memory deallocation",
        "description": "Pointer freed twice; heap corruption or code execution",
    },

    # Exception Handling
    {
        "id": "hyp_073_swallowed_exception",
        "title": "Swallowed Exception",
        "control": "C-012",
        "sink": "exception handler",
        "description": "Exception caught and silently ignored; security-critical failure hidden",
    },
    {
        "id": "hyp_074_exception_information_leak",
        "title": "Exception Information Leak",
        "control": "C-012",
        "sink": "exception propagation",
        "description": "Stack trace exposed to user; reveals internal paths, class names, versions",
    },

    # Configuration
    {
        "id": "hyp_075_debug_mode_enabled",
        "title": "Debug Mode Enabled in Production",
        "control": "C-011",
        "sink": "application configuration",
        "description": "Debug mode left on; additional information and functionality exposed",
    },
    {
        "id": "hyp_076_default_credentials",
        "title": "Default Credentials Not Changed",
        "control": "C-011",
        "sink": "authentication",
        "description": "Service uses default username/password; publicly known credentials compromise system",
    },

    # Concurrent Access
    {
        "id": "hyp_077_race_condition_data_validation",
        "title": "Race Condition in Data Validation",
        "control": "C-012",
        "sink": "concurrent access",
        "description": "Validation check not atomic with use; TOCTOU race allows bypass",
    },
    {
        "id": "hyp_078_unsynchronized_access_shared_state",
        "title": "Unsynchronized Access to Shared State",
        "control": "C-012",
        "sink": "concurrent access",
        "description": "Multiple threads access shared variable without synchronization; data corruption",
    },

    # Injection (General)
    {
        "id": "hyp_079_command_line_injection",
        "title": "Command Line Argument Injection",
        "control": "C-002",
        "sink": "command construction",
        "description": "Command-line argument from user input; injection via option parsing",
    },
    {
        "id": "hyp_080_environment_variable_injection",
        "title": "Environment Variable Injection",
        "control": "C-002",
        "sink": "environment setup",
        "description": "User-controlled environment variable; affects subprocess behavior",
    },

    # Sanitization
    {
        "id": "hyp_081_insufficient_input_validation",
        "title": "Insufficient Input Validation",
        "control": "C-002",
        "sink": "input handler",
        "description": "Input validation too lenient; bypass via encoding or special characters",
    },
    {
        "id": "hyp_082_improper_output_encoding",
        "title": "Improper Output Encoding",
        "control": "C-009",
        "sink": "output rendering",
        "description": "Output not properly encoded for context; injection attack succeeds",
    },

    # Miscellaneous
    {
        "id": "hyp_083_insecure_random",
        "title": "Insecure Random Number Generation",
        "control": "C-011",
        "sink": "PRNG",
        "description": "math.random() or weak PRNG used for security; values predictable",
    },
    {
        "id": "hyp_084_hardcoded_test_data",
        "title": "Hardcoded Test Data in Production",
        "control": "C-011",
        "sink": "test fixture",
        "description": "Test credentials or data left in production code; authentication bypass",
    },
    {
        "id": "hyp_085_comments_with_secrets",
        "title": "Secrets Hardcoded in Comments",
        "control": "C-011",
        "sink": "source code comments",
        "description": "API key or password written in code comment; exposed via source review",
    },
    {
        "id": "hyp_086_insecure_temp_file",
        "title": "Insecure Temporary File Creation",
        "control": "C-011",
        "sink": "temp file handling",
        "description": "Temporary file predictable name or world-readable; attacker reads/modifies",
    },
    {
        "id": "hyp_087_world_writable_file",
        "title": "World-Writable Critical File",
        "control": "C-011",
        "sink": "file permissions",
        "description": "Important file has world-write permission; attacker modifies configuration/data",
    },
    {
        "id": "hyp_088_symlink_in_world_writable",
        "title": "Symlink in World-Writable Directory",
        "control": "C-003",
        "sink": "symlink following",
        "description": "Attacker creates symlink in /tmp to modify files application reads/writes",
    },
    {
        "id": "hyp_089_unsafe_temp_directory_usage",
        "title": "Unsafe Temporary Directory Usage",
        "control": "C-011",
        "sink": "temp path handling",
        "description": "/tmp or /var/tmp used for persistent data; world-accessible",
    },
    {
        "id": "hyp_090_missing_input_length_check",
        "title": "Missing Input Length Validation",
        "control": "C-010",
        "sink": "input length check",
        "description": "No maximum length on input; extremely large payload causes DoS or crash",
    },
    {
        "id": "hyp_091_missing_type_check",
        "title": "Missing Type Checking",
        "control": "C-002",
        "sink": "type validation",
        "description": "Input type not validated; wrong type causes unexpected behavior",
    },
    {
        "id": "hyp_092_missing_range_check",
        "title": "Missing Range Validation",
        "control": "C-010",
        "sink": "range check",
        "description": "Numeric input not bounds-checked; out-of-range value causes logic error",
    },
    {
        "id": "hyp_093_missing_null_check",
        "title": "Missing Null Pointer Check",
        "control": "C-010",
        "sink": "null check",
        "description": "Pointer/reference used without null check; crash or undefined behavior",
    },
    {
        "id": "hyp_094_missing_encoding_check",
        "title": "Missing Character Encoding Validation",
        "control": "C-002",
        "sink": "encoding validation",
        "description": "Invalid UTF-8 or non-ASCII characters not filtered; encoding attack possible",
    },
    {
        "id": "hyp_095_unsafe_html_generation",
        "title": "Unsafe HTML Generation",
        "control": "C-009",
        "sink": "HTML construction",
        "description": "HTML generated by string concatenation; XSS possible",
    },
    {
        "id": "hyp_096_unsafe_sql_generation",
        "title": "Unsafe SQL Generation",
        "control": "C-002",
        "sink": "SQL query construction",
        "description": "SQL query built via string concatenation; SQL injection possible",
    },
    {
        "id": "hyp_097_weak_random_token",
        "title": "Weak Random Token Generation",
        "control": "C-011",
        "sink": "token generation",
        "description": "Token or session ID generated with weak randomness; predictable/guessable",
    },
    {
        "id": "hyp_098_missing_csp_header",
        "title": "Missing Content Security Policy Header",
        "control": "C-009",
        "sink": "HTTP headers",
        "description": "CSP header not set; XSS attacks not mitigated",
    },
    {
        "id": "hyp_099_missing_hsts_header",
        "title": "Missing HSTS Header",
        "control": "C-011",
        "sink": "HTTP headers",
        "description": "HSTS not enabled; HTTPS downgrade and SSL stripping possible",
    },
    {
        "id": "hyp_100_missing_samesite_cookie",
        "title": "Missing SameSite Cookie Attribute",
        "control": "C-012",
        "sink": "cookie attributes",
        "description": "SameSite not set; CSRF attacks not mitigated",
    },
]


def generate_hypothesis_markdown(hyp: dict) -> str:
    """Generate markdown for a single hypothesis"""
    return f"""# Hypothesis: {hyp['title']}

## Ralphization Checklist

### 1. REACHABILITY
User input or untrusted data reaches dangerous function

- Entry: [API endpoint, network protocol, file input]
- Sink: `{hyp['sink']}`
- Path: [User input] → [Entry point] → {hyp['sink']}

### 2. SINK
What function/API is dangerous?

- Function: `{hyp['sink']}`
- Location: [Source file location to be determined during validation]
- Danger: {hyp['description']}

### 3. CONTROL
Which C-001 to C-012 blocks this?

- Control: **{hyp['control']}**
- Name: [Control name from C-001 to C-012]
- Mitigation: [How would this control prevent the vulnerability?]

### 4. PATCH
File/function to change

- Location: [File path to be determined during validation]
- Change: [Specific code change required]
- Test: [What regression test validates this?]

### 5. TEST
Regression test to prevent re-exposure

- Test case: [Exact test case]
- Expected: [Expected secure behavior]
"""


def generate_hypotheses(project_root: Path, count: int = 100) -> int:
    """
    Generate vulnerability hypotheses for the project.

    Dynamically generates hypotheses from multiple vulnerability categories
    to support unlimited hypothesis generation (not limited to static templates).

    Args:
        project_root: Root directory of ChiefWiggum project
        count: Number of hypotheses to generate (default 100)

    Returns:
        Number of hypotheses generated
    """
    hypotheses_dir = project_root / "hypotheses"
    hypotheses_dir.mkdir(parents=True, exist_ok=True)

    # Combine all hypothesis sources
    all_hypotheses = []
    all_hypotheses.extend(HYPOTHESIS_TEMPLATES)

    # Generate dynamic hypotheses if count > template count
    if count > len(HYPOTHESIS_TEMPLATES):
        all_hypotheses.extend(generate_injection_hypotheses())
        all_hypotheses.extend(generate_deserialization_hypotheses())
        all_hypotheses.extend(generate_xxe_ssrf_hypotheses())
        all_hypotheses.extend(generate_auth_session_hypotheses())
        all_hypotheses.extend(generate_input_validation_hypotheses())

    generated = 0
    for hyp in all_hypotheses[:count]:
        hyp_file = hypotheses_dir / f"{hyp['id']}.md"

        # Skip if already exists
        if hyp_file.exists():
            continue

        markdown_content = generate_hypothesis_markdown(hyp)
        hyp_file.write_text(markdown_content)
        generated += 1

    return generated
