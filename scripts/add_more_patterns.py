#!/usr/bin/env python3
"""Add more diverse patterns including safe examples."""

import json
import random
from pathlib import Path

# More comprehensive patterns
MORE_VULNERABLE_C = [
    # Off-by-one errors
    {
        "code": '''void copy_string(char *dest, const char *src, size_t n) {
    for (size_t i = 0; i <= n; i++) {  // Should be i < n
        dest[i] = src[i];
    }
}''',
        "findings": [{
            "line": 2,
            "severity": "high",
            "category": "security",
            "rule": "CWE-193",
            "title": "Off-by-one error",
            "message": "Loop condition i <= n writes one byte past the buffer. Should be i < n.",
            "suggestion": "Change loop to: for (size_t i = 0; i < n; i++)"
        }],
        "language": "c"
    },
    # Race condition with TOCTOU
    {
        "code": '''int safe_open(const char *path) {
    if (access(path, R_OK) == 0) {
        return open(path, O_RDONLY);
    }
    return -1;
}''',
        "findings": [{
            "line": 2,
            "severity": "high",
            "category": "security",
            "rule": "CWE-367",
            "title": "Time-of-check to time-of-use race condition",
            "message": "File permissions may change between access() check and open() call, allowing privilege escalation.",
            "suggestion": "Use open() directly and check return value, or use O_NOFOLLOW to prevent symlink attacks."
        }],
        "language": "c"
    },
    # Dangerous function
    {
        "code": '''char* make_temp_file() {
    char template[] = "/tmp/myapp_XXXXXX";
    mktemp(template);
    return strdup(template);
}''',
        "findings": [{
            "line": 3,
            "severity": "high",
            "category": "security",
            "rule": "CWE-377",
            "title": "Insecure temporary file creation",
            "message": "mktemp() creates predictable filenames and has race conditions. An attacker can predict the filename.",
            "suggestion": "Use mkstemp() which atomically creates and opens the file."
        }],
        "language": "c"
    },
    # Memory leak
    {
        "code": '''char* process_data(const char *input) {
    char *buffer = malloc(1024);
    if (strlen(input) > 1000) {
        return NULL;  // Memory leak!
    }
    strcpy(buffer, input);
    return buffer;
}''',
        "findings": [
            {
                "line": 4,
                "severity": "medium",
                "category": "quality",
                "rule": "CWE-401",
                "title": "Memory leak on error path",
                "message": "buffer is allocated but not freed before returning NULL.",
                "suggestion": "Free buffer before returning: free(buffer); return NULL;"
            },
            {
                "line": 6,
                "severity": "critical",
                "category": "security",
                "rule": "CWE-120",
                "title": "Buffer overflow via strcpy",
                "message": "strcpy has no bounds checking.",
                "suggestion": "Use strncpy or check length properly."
            }
        ],
        "language": "c"
    },
    # Signed/unsigned comparison
    {
        "code": '''void process_array(int *arr, int len, int index) {
    if (index < len) {
        arr[index] = 0;  // index could be negative!
    }
}''',
        "findings": [{
            "line": 2,
            "severity": "high",
            "category": "security",
            "rule": "CWE-195",
            "title": "Signed to unsigned conversion issue",
            "message": "index is signed and only checked against upper bound. Negative values will access memory before arr.",
            "suggestion": "Check both bounds: if (index >= 0 && index < len)"
        }],
        "language": "c"
    },
]

MORE_VULNERABLE_PYTHON = [
    # YAML unsafe load
    {
        "code": '''import yaml

def load_config(config_file):
    with open(config_file) as f:
        return yaml.load(f)''',
        "findings": [{
            "line": 5,
            "severity": "critical",
            "category": "security",
            "rule": "CWE-502",
            "title": "Unsafe YAML deserialization",
            "message": "yaml.load() without Loader argument can execute arbitrary code via YAML tags like !!python/object.",
            "suggestion": "Use yaml.safe_load(f) or yaml.load(f, Loader=yaml.SafeLoader)"
        }],
        "language": "python"
    },
    # XXE in XML parsing
    {
        "code": '''from xml.etree import ElementTree as ET

def parse_xml(xml_string):
    return ET.fromstring(xml_string)''',
        "findings": [{
            "line": 4,
            "severity": "high",
            "category": "security",
            "rule": "CWE-611",
            "title": "Potential XXE vulnerability",
            "message": "ElementTree may be vulnerable to XXE attacks allowing file disclosure or SSRF.",
            "suggestion": "Use defusedxml library: from defusedxml.ElementTree import fromstring"
        }],
        "language": "python"
    },
    # Template injection
    {
        "code": '''from jinja2 import Template

def render_message(user_template, data):
    template = Template(user_template)
    return template.render(data)''',
        "findings": [{
            "line": 4,
            "severity": "critical",
            "category": "security",
            "rule": "CWE-94",
            "title": "Server-Side Template Injection (SSTI)",
            "message": "User-controlled template can execute arbitrary code via Jinja2 expressions like {{config.items()}}.",
            "suggestion": "Never let users control templates. Use a sandbox: Environment(autoescape=True, sandbox=True)"
        }],
        "language": "python"
    },
    # Regex DoS
    {
        "code": '''import re

def validate_email(email):
    pattern = r'^([a-zA-Z0-9]+)*@[a-zA-Z0-9]+\\.[a-zA-Z]+$'
    return re.match(pattern, email) is not None''',
        "findings": [{
            "line": 4,
            "severity": "medium",
            "category": "security",
            "rule": "CWE-1333",
            "title": "Regular expression denial of service (ReDoS)",
            "message": "Pattern ([a-zA-Z0-9]+)* causes catastrophic backtracking on inputs like 'aaaaaaaaaaaaaaaaaa!'",
            "suggestion": "Remove nested quantifiers: r'^[a-zA-Z0-9]+@[a-zA-Z0-9]+\\\\.[a-zA-Z]+$'"
        }],
        "language": "python"
    },
    # Open redirect
    {
        "code": '''from flask import redirect, request

@app.route('/redirect')
def do_redirect():
    url = request.args.get('url')
    return redirect(url)''',
        "findings": [{
            "line": 6,
            "severity": "medium",
            "category": "security",
            "rule": "CWE-601",
            "title": "Open redirect vulnerability",
            "message": "Unvalidated redirect allows phishing attacks by redirecting to malicious sites.",
            "suggestion": "Validate URL against allowlist of trusted domains, or use relative paths only."
        }],
        "language": "python"
    },
    # Mass assignment
    {
        "code": """@app.route('/user/update', methods=['POST'])
def update_user():
    user = User.query.get(current_user.id)
    user.update(**request.form)
    db.session.commit()
    return 'Updated'""",
        "findings": [{
            "line": 4,
            "severity": "high",
            "category": "security",
            "rule": "CWE-915",
            "title": "Mass assignment vulnerability",
            "message": "Directly passing request.form to update() allows attackers to modify any field including is_admin, role, etc.",
            "suggestion": "Explicitly specify allowed fields: user.name = request.form.get('name')"
        }],
        "language": "python"
    },
]

MORE_VULNERABLE_GO = [
    # Nil pointer without check
    {
        "code": '''func GetUserName(u *User) string {
    return u.Name
}''',
        "findings": [{
            "line": 2,
            "severity": "medium",
            "category": "bug",
            "rule": "CWE-476",
            "title": "Potential nil pointer dereference",
            "message": "No nil check before accessing u.Name. Will panic if u is nil.",
            "suggestion": "Add nil check: if u == nil { return \"\" }"
        }],
        "language": "go"
    },
    # Goroutine leak
    {
        "code": '''func startWorker(jobs <-chan Job) {
    go func() {
        for job := range jobs {
            process(job)
        }
    }()
}''',
        "findings": [{
            "line": 2,
            "severity": "medium",
            "category": "quality",
            "rule": None,
            "title": "Potential goroutine leak",
            "message": "Goroutine will block forever if jobs channel is never closed.",
            "suggestion": "Ensure channel is closed when done, or use context for cancellation."
        }],
        "language": "go"
    },
    # Insecure TLS
    {
        "code": '''func createClient() *http.Client {
    tr := &http.Transport{
        TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
    }
    return &http.Client{Transport: tr}
}''',
        "findings": [{
            "line": 3,
            "severity": "high",
            "category": "security",
            "rule": "CWE-295",
            "title": "TLS certificate validation disabled",
            "message": "InsecureSkipVerify: true disables certificate verification, enabling man-in-the-middle attacks.",
            "suggestion": "Remove InsecureSkipVerify or set to false in production."
        }],
        "language": "go"
    },
]

MORE_VULNERABLE_RUST = [
    # Transmute misuse
    {
        "code": '''fn bytes_to_string(bytes: &[u8]) -> &str {
    unsafe {
        std::mem::transmute(bytes)
    }
}''',
        "findings": [{
            "line": 3,
            "severity": "critical",
            "category": "security",
            "rule": "CWE-704",
            "title": "Unsafe transmute of bytes to str",
            "message": "transmute doesn't validate UTF-8. Invalid bytes will cause undefined behavior when used as &str.",
            "suggestion": "Use std::str::from_utf8(bytes) or from_utf8_unchecked with validation."
        }],
        "language": "rust"
    },
    # Send + Sync violation
    {
        "code": '''struct UnsafeWrapper(*mut i32);

unsafe impl Send for UnsafeWrapper {}
unsafe impl Sync for UnsafeWrapper {}''',
        "findings": [{
            "line": 3,
            "severity": "high",
            "category": "security",
            "rule": "CWE-362",
            "title": "Potentially unsound Send/Sync implementation",
            "message": "Manually implementing Send/Sync for raw pointers can cause data races if not carefully managed.",
            "suggestion": "Ensure all accesses to the inner pointer are properly synchronized."
        }],
        "language": "rust"
    },
]

# Clean/Safe code examples for balance
SAFE_EXAMPLES = [
    {
        "code": '''void safe_copy(char *dest, size_t dest_size, const char *src) {
    if (dest == NULL || src == NULL || dest_size == 0) {
        return;
    }
    size_t src_len = strlen(src);
    size_t copy_len = (src_len < dest_size - 1) ? src_len : dest_size - 1;
    memcpy(dest, src, copy_len);
    dest[copy_len] = '\\0';
}''',
        "findings": [],
        "language": "c"
    },
    {
        "code": '''def get_user_safely(user_id: int) -> Optional[User]:
    """Fetch user with parameterized query and proper error handling."""
    try:
        cursor.execute(
            "SELECT * FROM users WHERE id = %s",
            (user_id,)
        )
        row = cursor.fetchone()
        return User.from_row(row) if row else None
    except DatabaseError as e:
        logger.error(f"Database error: {e}")
        return None''',
        "findings": [],
        "language": "python"
    },
    {
        "code": '''func SafeOpenFile(basePath, filename string) (*os.File, error) {
    // Clean the filename and ensure it's within basePath
    cleanName := filepath.Clean(filename)
    if strings.HasPrefix(cleanName, "..") {
        return nil, fmt.Errorf("path traversal attempt detected")
    }
    fullPath := filepath.Join(basePath, cleanName)
    
    // Verify the resolved path is still within basePath
    if !strings.HasPrefix(fullPath, basePath) {
        return nil, fmt.Errorf("path outside allowed directory")
    }
    
    return os.Open(fullPath)
}''',
        "findings": [],
        "language": "go"
    },
    {
        "code": '''fn parse_config(input: &str) -> Result<Config, ConfigError> {
    let value: i32 = input
        .trim()
        .parse()
        .map_err(|e| ConfigError::ParseError(e))?;
    
    if value < 0 || value > 65535 {
        return Err(ConfigError::OutOfRange);
    }
    
    Ok(Config { port: value as u16 })
}''',
        "findings": [],
        "language": "rust"
    },
    {
        "code": '''import subprocess
import shlex

def safe_run_command(user_input: str) -> str:
    """Run a command safely without shell injection."""
    # Validate input contains only allowed characters
    if not user_input.replace("-", "").replace(".", "").isalnum():
        raise ValueError("Invalid input")
    
    # Use argument list, not shell
    result = subprocess.run(
        ["ping", "-c", "1", user_input],
        capture_output=True,
        text=True,
        timeout=10
    )
    return result.stdout''',
        "findings": [],
        "language": "python"
    },
    {
        "code": '''#include <stdio.h>
#include <string.h>
#include <stdarg.h>

void safe_log(const char *fmt, ...) {
    char buffer[1024];
    va_list args;
    va_start(args, fmt);
    int len = vsnprintf(buffer, sizeof(buffer), fmt, args);
    va_end(args);
    
    if (len > 0 && len < (int)sizeof(buffer)) {
        fprintf(stderr, "[LOG] %s\\n", buffer);
    }
}''',
        "findings": [],
        "language": "c"
    },
]


def format_sample(sample: dict) -> dict:
    """Format a sample for training."""
    code = sample["code"]
    language = sample.get("language", "")
    findings = sample.get("findings", [])
    
    lines = code.strip().split("\n")
    numbered = "\n".join(f"{i+1:3} | {line}" for i, line in enumerate(lines))
    
    instruction = f"""Review the following {language} code for security vulnerabilities, bugs, and quality issues:

```{language}
{numbered}
```

Analyze carefully and report any issues. For each issue provide JSON with: line, severity, category, rule (if applicable), title, message, suggestion."""

    if findings:
        response = "\n".join(json.dumps(f) for f in findings)
    else:
        response = '{"no_issues": true, "message": "Code follows security best practices."}'
    
    return {"instruction": instruction, "response": response}


def main():
    data_dir = Path(__file__).parent.parent / "data"
    train_path = data_dir / "train.jsonl"
    
    # Load existing
    with open(train_path) as f:
        existing = [json.loads(line) for line in f]
    
    # Add new patterns
    all_new = (
        MORE_VULNERABLE_C + 
        MORE_VULNERABLE_PYTHON + 
        MORE_VULNERABLE_GO + 
        MORE_VULNERABLE_RUST +
        SAFE_EXAMPLES
    )
    
    for sample in all_new:
        existing.append(format_sample(sample))
    
    # Shuffle
    random.seed(42)
    random.shuffle(existing)
    
    # Write back
    with open(train_path, "w") as f:
        for sample in existing:
            f.write(json.dumps(sample) + "\n")
    
    print(f"Total training samples: {len(existing)}")
    
    # Also update eval with some safe examples
    eval_path = data_dir / "eval.jsonl"
    with open(eval_path, "a") as f:
        for sample in SAFE_EXAMPLES[:2]:
            f.write(json.dumps(format_sample(sample)) + "\n")


if __name__ == "__main__":
    main()
