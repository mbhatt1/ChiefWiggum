"""
LLM-based vulnerability analysis for ChiefWiggum Loop

Uses GPT to analyze code and find security vulnerabilities.
This is the primary detection method (replaces pattern matching).
"""

import os
import json
from pathlib import Path
from typing import List, Dict, Optional
from openai import OpenAI


class LLMAnalyzer:
    """Analyze code for vulnerabilities using GPT"""

    def __init__(self, codebase_path: Path, model: str = "gpt-4o-mini", base_url: Optional[str] = None):
        self.codebase = Path(codebase_path)
        self.model = model
        self.findings = []

        # Initialize OpenAI client with custom base_url if provided
        api_key = os.getenv("OPENAI_API_KEY")
        if base_url:
            # For Ollama and other local providers, use dummy key if not set
            if not api_key:
                api_key = "ollama"
            self.client = OpenAI(api_key=api_key, base_url=base_url)
        else:
            self.client = OpenAI(api_key=api_key)

    def analyze_codebase(self, file_patterns: List[str] = None) -> List[Dict]:
        """
        Scan codebase for vulnerabilities using LLM

        Args:
            file_patterns: List of file patterns to analyze (e.g., ["*.java"])

        Returns:
            List of vulnerability findings
        """
        if file_patterns is None:
            file_patterns = ["*.java"]

        # Find files to analyze
        files_to_analyze = []
        for pattern in file_patterns:
            files_to_analyze.extend(self.codebase.rglob(pattern))

        # Limit to first 50 files for cost/speed
        files_to_analyze = files_to_analyze[:50]

        click_echo = None
        try:
            import click
            click_echo = click.echo
        except:
            pass

        findings = []

        for file_path in files_to_analyze:
            if click_echo:
                click_echo(f"  Analyzing {file_path.name}...", nl=False)

            try:
                content = file_path.read_text(encoding='utf-8', errors='ignore')
            except Exception as e:
                if click_echo:
                    click_echo(f" ✗ (read error)")
                continue

            # Analyze with LLM
            vulns = self._analyze_file(file_path, content)

            if vulns:
                if click_echo:
                    click_echo(f" ✓ ({len(vulns)} found)")
                findings.extend(vulns)
            else:
                if click_echo:
                    click_echo(f" ✓")

        return findings

    def _analyze_file(self, file_path: Path, content: str) -> List[Dict]:
        """Analyze a single file using GPT"""

        # Truncate large files
        if len(content) > 8000:
            content = content[:8000] + "\n... (truncated)"

        prompt = f"""Analyze this code for security vulnerabilities.

FILE: {file_path.name}
PATH: {file_path}

CODE:
```
{content}
```

Find ALL vulnerabilities. For each vulnerability, provide:
1. Type (e.g., RCE, XXE, SQL Injection, Deserialization, etc.)
2. Severity (CRITICAL, HIGH, MEDIUM, LOW)
3. CWE number
4. Location (line/function)
5. Description of the issue
6. Impact
7. How to fix it

Format as JSON array. Example:
[
  {{
    "type": "Deserialization RCE",
    "severity": "CRITICAL",
    "cwe": "CWE-502",
    "location": "line 45, method createThrowable()",
    "description": "ObjectInputStream.readObject() called without validation",
    "impact": "Remote code execution via gadget chain",
    "fix": "Add class allowlist before deserialization"
  }}
]

Return ONLY valid JSON array, no other text.
"""

        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {
                        "role": "system",
                        "content": "You are a security researcher analyzing Java code for vulnerabilities. Always respond with valid JSON only."
                    },
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                temperature=0.3,
                max_tokens=2000
            )

            result_text = response.choices[0].message.content.strip()

            # Parse JSON response
            try:
                vulnerabilities = json.loads(result_text)
            except json.JSONDecodeError:
                # Try to extract JSON from response
                import re
                json_match = re.search(r'\[.*\]', result_text, re.DOTALL)
                if json_match:
                    vulnerabilities = json.loads(json_match.group())
                else:
                    return []

            # Enrich with file location
            for vuln in vulnerabilities:
                vuln['file'] = str(file_path)
                vuln['id'] = f"llm_{file_path.stem}_{len(self.findings)}"
                vuln['action'] = 'PATCH'  # LLM findings are confirmed

            return vulnerabilities

        except Exception as e:
            print(f"Error analyzing {file_path}: {e}")
            return []

    def analyze_all(self) -> List[Dict]:
        """Analyze all Java files in codebase"""
        return self.analyze_codebase(file_patterns=["*.java"])


def analyze_with_gpt(codebase_path: Path, file_patterns: List[str] = None,
                     model: str = "gpt-4o-mini", base_url: Optional[str] = None) -> List[Dict]:
    """
    Public interface for LLM-based vulnerability analysis

    Args:
        codebase_path: Path to the codebase to analyze
        file_patterns: File patterns to analyze (default: ["*.java"])
        model: Model name to use (default: "gpt-4o-mini")
        base_url: Custom OpenAI API base URL (e.g., for Ollama)

    Returns:
        List of detected vulnerabilities
    """
    analyzer = LLMAnalyzer(codebase_path, model=model, base_url=base_url)
    return analyzer.analyze_codebase(file_patterns)
