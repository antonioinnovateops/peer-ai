"""Training data generation for Peer-AI."""

import json
import logging
import re
from pathlib import Path
from typing import Optional

import httpx


logger = logging.getLogger(__name__)


# CWE to category mapping
CWE_CATEGORIES = {
    # Buffer errors
    "CWE-120": ("security", "critical", "Buffer overflow"),
    "CWE-121": ("security", "critical", "Stack-based buffer overflow"),
    "CWE-122": ("security", "critical", "Heap-based buffer overflow"),
    "CWE-787": ("security", "critical", "Out-of-bounds write"),
    "CWE-125": ("security", "high", "Out-of-bounds read"),
    
    # Injection
    "CWE-78": ("security", "critical", "OS command injection"),
    "CWE-89": ("security", "critical", "SQL injection"),
    "CWE-79": ("security", "high", "Cross-site scripting (XSS)"),
    "CWE-94": ("security", "critical", "Code injection"),
    
    # Memory safety
    "CWE-416": ("security", "critical", "Use after free"),
    "CWE-415": ("security", "critical", "Double free"),
    "CWE-476": ("security", "high", "Null pointer dereference"),
    "CWE-401": ("quality", "medium", "Memory leak"),
    
    # Integer issues
    "CWE-190": ("security", "high", "Integer overflow"),
    "CWE-191": ("security", "high", "Integer underflow"),
    "CWE-369": ("bug", "medium", "Divide by zero"),
    
    # Auth/Crypto
    "CWE-798": ("security", "critical", "Hardcoded credentials"),
    "CWE-330": ("security", "high", "Insufficient randomness"),
    "CWE-327": ("security", "high", "Broken crypto algorithm"),
    "CWE-311": ("security", "high", "Missing encryption"),
    
    # Path/File
    "CWE-22": ("security", "high", "Path traversal"),
    "CWE-434": ("security", "high", "Unrestricted file upload"),
    "CWE-732": ("security", "medium", "Incorrect permission assignment"),
    
    # Logic
    "CWE-362": ("security", "high", "Race condition"),
    "CWE-617": ("bug", "medium", "Reachable assertion"),
    "CWE-704": ("bug", "medium", "Incorrect type conversion"),
}


def generate_training_data(
    output_path: str,
    sources: list[str],
    limit: int = 10000,
):
    """Generate training data from various sources.
    
    Args:
        output_path: Path to output JSONL file
        sources: Data sources to use (cve, github-advisories, cwe, synthetic)
        limit: Maximum samples per source
    """
    output_file = Path(output_path)
    output_file.parent.mkdir(parents=True, exist_ok=True)
    
    all_samples = []
    
    for source in sources:
        logger.info(f"Fetching from source: {source}")
        
        if source == "cve":
            samples = _fetch_cve_samples(limit)
        elif source == "github-advisories":
            samples = _fetch_github_advisories(limit)
        elif source == "cwe":
            samples = _generate_cwe_examples(limit)
        elif source == "synthetic":
            samples = _generate_synthetic_examples(limit)
        else:
            logger.warning(f"Unknown source: {source}")
            continue
        
        all_samples.extend(samples)
        logger.info(f"  Got {len(samples)} samples")
    
    # Write to JSONL
    with open(output_file, "w") as f:
        for sample in all_samples:
            f.write(json.dumps(sample) + "\n")
    
    logger.info(f"Wrote {len(all_samples)} samples to {output_path}")


def _fetch_cve_samples(limit: int) -> list[dict]:
    """Fetch samples from NVD CVE database."""
    samples = []
    
    # This would need proper NVD API implementation
    # For now, return placeholder
    logger.warning("CVE fetching not fully implemented - using placeholder data")
    
    return samples


def _fetch_github_advisories(limit: int) -> list[dict]:
    """Fetch samples from GitHub Security Advisories."""
    samples = []
    
    # This would need GitHub GraphQL API
    # For now, return placeholder
    logger.warning("GitHub advisories not fully implemented - using placeholder data")
    
    return samples


def _generate_cwe_examples(limit: int) -> list[dict]:
    """Generate examples for common CWE patterns."""
    samples = []
    
    # C/C++ buffer overflow examples
    c_vulnerable_patterns = [
        # strcpy without bounds
        {
            "code": '''void process_input(char *user_input) {
    char buffer[64];
    strcpy(buffer, user_input);  // Vulnerable: no bounds check
    printf("Got: %s\\n", buffer);
}''',
            "finding": {
                "line": 3,
                "severity": "critical",
                "category": "security",
                "rule": "CWE-120",
                "title": "Buffer overflow via strcpy",
                "message": "strcpy() copies user input without checking the size. If user_input exceeds 64 bytes, this will overflow buffer[] and corrupt the stack.",
                "suggestion": "Use strncpy() with explicit size limit, or better yet, use snprintf():\n```c\nstrncpy(buffer, user_input, sizeof(buffer) - 1);\nbuffer[sizeof(buffer) - 1] = '\\0';\n```"
            },
            "language": "c"
        },
        # sprintf without bounds
        {
            "code": '''void format_message(const char *name, int id) {
    char msg[128];
    sprintf(msg, "User %s has ID %d and joined on %s", name, id, get_date());
    log_message(msg);
}''',
            "finding": {
                "line": 3,
                "severity": "high",
                "category": "security",
                "rule": "CWE-120",
                "title": "Potential buffer overflow via sprintf",
                "message": "sprintf() does not check buffer bounds. If the formatted string exceeds 128 bytes, this will cause a buffer overflow.",
                "suggestion": "Use snprintf() with explicit size:\n```c\nsnprintf(msg, sizeof(msg), \"User %s...\", ...);\n```"
            },
            "language": "c"
        },
        # gets() usage
        {
            "code": '''int main() {
    char password[32];
    printf("Enter password: ");
    gets(password);  // Never use gets()
    if (check_password(password)) {
        grant_access();
    }
}''',
            "finding": {
                "line": 4,
                "severity": "critical",
                "category": "security",
                "rule": "CWE-120",
                "title": "Use of gets() is always unsafe",
                "message": "gets() cannot limit input size and will always overflow the buffer if input is too long. This function has been removed from C11.",
                "suggestion": "Use fgets() with size limit:\n```c\nfgets(password, sizeof(password), stdin);\n```"
            },
            "language": "c"
        },
    ]
    
    # Python injection examples
    python_vulnerable_patterns = [
        # SQL injection
        {
            "code": '''def get_user(username):
    query = f"SELECT * FROM users WHERE name = '{username}'"
    cursor.execute(query)
    return cursor.fetchone()''',
            "finding": {
                "line": 2,
                "severity": "critical",
                "category": "security",
                "rule": "CWE-89",
                "title": "SQL injection vulnerability",
                "message": "User input is directly interpolated into the SQL query. An attacker can inject malicious SQL like: `' OR '1'='1` to bypass authentication or extract data.",
                "suggestion": "Use parameterized queries:\n```python\ncursor.execute(\"SELECT * FROM users WHERE name = ?\", (username,))\n```"
            },
            "language": "python"
        },
        # Command injection
        {
            "code": '''import os

def ping_host(hostname):
    os.system(f"ping -c 1 {hostname}")''',
            "finding": {
                "line": 4,
                "severity": "critical",
                "category": "security",
                "rule": "CWE-78",
                "title": "Command injection vulnerability",
                "message": "User input is passed directly to os.system(). An attacker can inject commands like: `; rm -rf /` or `$(cat /etc/passwd)`",
                "suggestion": "Use subprocess with shell=False and pass arguments as a list:\n```python\nimport subprocess\nsubprocess.run(['ping', '-c', '1', hostname], check=True)\n```"
            },
            "language": "python"
        },
        # eval usage
        {
            "code": '''def calculate(expression):
    return eval(expression)''',
            "finding": {
                "line": 2,
                "severity": "critical",
                "category": "security",
                "rule": "CWE-94",
                "title": "Code injection via eval()",
                "message": "eval() executes arbitrary Python code. An attacker can run malicious code like: `__import__('os').system('rm -rf /')`",
                "suggestion": "Use ast.literal_eval() for safe evaluation of literals, or a proper expression parser for math."
            },
            "language": "python"
        },
    ]
    
    # Go examples
    go_vulnerable_patterns = [
        # SQL injection
        {
            "code": '''func GetUser(db *sql.DB, username string) (*User, error) {
    query := fmt.Sprintf("SELECT * FROM users WHERE name = '%s'", username)
    row := db.QueryRow(query)
    // ...
}''',
            "finding": {
                "line": 2,
                "severity": "critical",
                "category": "security",
                "rule": "CWE-89",
                "title": "SQL injection vulnerability",
                "message": "User input is interpolated into SQL query using fmt.Sprintf. This allows SQL injection attacks.",
                "suggestion": "Use parameterized queries:\n```go\nrow := db.QueryRow(\"SELECT * FROM users WHERE name = ?\", username)\n```"
            },
            "language": "go"
        },
    ]
    
    # Rust examples
    rust_vulnerable_patterns = [
        # Unwrap on user input
        {
            "code": '''fn parse_config(input: &str) -> Config {
    let value: i32 = input.parse().unwrap();  // Panics on invalid input
    Config { value }
}''',
            "finding": {
                "line": 2,
                "severity": "medium",
                "category": "bug",
                "rule": None,
                "title": "Potential panic on invalid input",
                "message": "Using unwrap() on user input will panic if parsing fails. In a server context, this could cause denial of service.",
                "suggestion": "Handle the error gracefully:\n```rust\nlet value: i32 = input.parse().map_err(|_| ConfigError::InvalidValue)?;\n```"
            },
            "language": "rust"
        },
    ]
    
    # Combine all patterns
    all_patterns = (
        c_vulnerable_patterns + 
        python_vulnerable_patterns + 
        go_vulnerable_patterns +
        rust_vulnerable_patterns
    )
    
    # Format as training samples
    for pattern in all_patterns[:limit]:
        sample = {
            "code": pattern["code"],
            "language": pattern["language"],
            "findings": [pattern["finding"]],
        }
        samples.append(sample)
    
    return samples


def _generate_synthetic_examples(limit: int) -> list[dict]:
    """Generate synthetic training examples."""
    # This would generate variations of patterns
    return []


def format_for_training(sample: dict) -> dict:
    """Format a sample for model training.
    
    Converts to instruction/response format for fine-tuning.
    """
    code = sample["code"]
    language = sample.get("language", "")
    findings = sample.get("findings", [])
    
    instruction = f"""Review the following {language} code for security vulnerabilities, bugs, and quality issues:

```{language}
{code}
```

Respond with one JSON object per line for each issue found."""
    
    response_lines = []
    for finding in findings:
        response_lines.append(json.dumps(finding))
    
    if not response_lines:
        response_lines.append('{"no_issues": true}')
    
    return {
        "instruction": instruction,
        "response": "\n".join(response_lines),
    }
