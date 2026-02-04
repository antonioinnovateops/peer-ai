#!/usr/bin/env python3
"""Augment training data with variations."""

import json
import random
import re
from pathlib import Path

# Variable name variations
VAR_NAMES = {
    "buffer": ["buf", "data", "temp", "arr", "str_buf", "output", "result"],
    "input": ["user_input", "str", "text", "value", "param", "arg"],
    "username": ["user", "name", "login", "uname", "user_name", "uid"],
    "password": ["passwd", "pwd", "pass", "secret", "credential"],
    "filename": ["file", "path", "fname", "filepath", "name"],
    "query": ["sql", "stmt", "q", "sql_query", "command"],
    "cmd": ["command", "shell_cmd", "exec_cmd", "run_cmd"],
    "conn": ["connection", "db_conn", "link", "socket"],
    "data": ["payload", "content", "body", "msg", "message"],
    "config": ["cfg", "conf", "settings", "opts", "options"],
    "url": ["uri", "link", "endpoint", "address", "target"],
    "token": ["key", "api_key", "secret", "auth_token", "access_token"],
}

# Function name variations
FUNC_NAMES = {
    "process": ["handle", "parse", "execute", "run", "do"],
    "get": ["fetch", "retrieve", "load", "read", "obtain"],
    "save": ["store", "write", "persist", "dump", "export"],
    "send": ["transmit", "dispatch", "deliver", "post", "emit"],
    "validate": ["check", "verify", "ensure", "confirm", "test"],
}

# Size variations
SIZES = ["32", "64", "128", "256", "512", "1024", "2048", "4096"]

# Additional vulnerable patterns to expand dataset
EXTRA_C_PATTERNS = [
    # More buffer overflows
    '''void {func}({type} *{input}) {{
    char {buffer}[{size}];
    strcpy({buffer}, {input});
    log_message({buffer});
}}''',
    '''int {func}(char *{input}, int len) {{
    char {buffer}[{size}];
    memcpy({buffer}, {input}, len);  // len not validated
    return process({buffer});
}}''',
    '''void {func}(FILE *fp) {{
    char {buffer}[{size}];
    fscanf(fp, "%s", {buffer});  // No width specifier
}}''',
    # Format strings
    '''void {func}(char *{input}) {{
    syslog(LOG_INFO, {input});
}}''',
    '''void {func}(char *{input}) {{
    fprintf(stderr, {input});
}}''',
]

EXTRA_PYTHON_PATTERNS = [
    # More SQL injection
    '''def {func}({param}):
    query = "SELECT * FROM {table} WHERE id = " + str({param})
    return db.execute(query).fetchone()''',
    '''def {func}({param}, {param2}):
    sql = f"UPDATE {table} SET status = '{{{param2}}}' WHERE user = '{{{param}}}'"
    cursor.execute(sql)''',
    # More command injection
    '''def {func}({param}):
    os.popen(f"grep {{{param}}} /var/log/app.log")''',
    '''def {func}({param}):
    subprocess.Popen(f"convert {{{param}}} output.png", shell=True)''',
    # Path traversal variations
    '''def {func}({param}):
    return open(os.path.join(UPLOAD_DIR, {param})).read()''',
    '''def {func}({param}):
    shutil.copy({param}, "/backup/")''',
]

EXTRA_GO_PATTERNS = [
    # SQL injection
    '''func {func}(db *sql.DB, {param} string) error {{
    _, err := db.Exec("DELETE FROM {table} WHERE id = " + {param})
    return err
}}''',
    # Path traversal
    '''func {func}(w http.ResponseWriter, {param} string) {{
    http.ServeFile(w, r, filepath.Join(baseDir, {param}))
}}''',
    # Unchecked errors
    '''func {func}({param} string) {{
    f, _ := os.Open({param})
    defer f.Close()
    io.Copy(os.Stdout, f)
}}''',
]

def substitute_vars(template: str, rng: random.Random) -> str:
    """Substitute variable names with random alternatives."""
    result = template
    
    # Replace {type} placeholders
    result = result.replace("{type}", rng.choice(["char", "const char", "unsigned char"]))
    result = result.replace("{size}", rng.choice(SIZES))
    result = result.replace("{table}", rng.choice(["users", "products", "orders", "sessions", "logs"]))
    
    # Replace variable names
    for var, alternatives in VAR_NAMES.items():
        pattern = f"{{{var}}}"
        if pattern in result:
            # Sometimes keep original, sometimes use alternative
            replacement = rng.choice([var] + alternatives)
            result = result.replace(pattern, replacement)
    
    # Replace function names
    for func, alternatives in FUNC_NAMES.items():
        pattern = f"{{{func}}}"
        if pattern in result:
            replacement = rng.choice([func] + alternatives)
            result = result.replace(pattern, replacement)
    
    # Generic placeholders
    result = result.replace("{func}", rng.choice(["process", "handle", "run", "execute", "do_action"]))
    result = result.replace("{param}", rng.choice(["input", "value", "data", "arg", "param"]))
    result = result.replace("{param2}", rng.choice(["status", "value", "flag", "mode"]))
    
    return result


def generate_finding_for_pattern(code: str, lang: str) -> list:
    """Generate appropriate findings based on code patterns."""
    findings = []
    
    # Detect issues by pattern
    if lang == "c":
        if "strcpy" in code:
            findings.append({
                "line": code.count("\n", 0, code.find("strcpy")) + 1,
                "severity": "critical",
                "category": "security",
                "rule": "CWE-120",
                "title": "Buffer overflow via strcpy",
                "message": "strcpy() has no bounds checking and can overflow the destination buffer.",
                "suggestion": "Use strncpy() with explicit size limit."
            })
        if "sprintf" in code and "snprintf" not in code:
            findings.append({
                "line": code.count("\n", 0, code.find("sprintf")) + 1,
                "severity": "high",
                "category": "security",
                "rule": "CWE-120",
                "title": "Potential buffer overflow via sprintf",
                "message": "sprintf() does not check buffer bounds.",
                "suggestion": "Use snprintf() with explicit size."
            })
        if "gets(" in code:
            findings.append({
                "line": code.count("\n", 0, code.find("gets(")) + 1,
                "severity": "critical",
                "category": "security",
                "rule": "CWE-120",
                "title": "Use of gets() is always unsafe",
                "message": "gets() cannot limit input and was removed from C11.",
                "suggestion": "Use fgets() with size limit."
            })
        if re.search(r'printf\s*\(\s*\w+\s*\)', code) or "syslog" in code and "%s" not in code:
            findings.append({
                "line": 2,
                "severity": "critical",
                "category": "security",
                "rule": "CWE-134",
                "title": "Format string vulnerability",
                "message": "User input used as format string.",
                "suggestion": "Use printf(\"%s\", input) to treat as data."
            })
        if "fscanf" in code and '"%s"' in code:
            findings.append({
                "line": code.count("\n", 0, code.find("fscanf")) + 1,
                "severity": "high",
                "category": "security",
                "rule": "CWE-120",
                "title": "Buffer overflow via fscanf %s",
                "message": "fscanf %s has no width limit.",
                "suggestion": "Use width specifier: fscanf(fp, \"%255s\", buffer)"
            })
        if re.search(r'memcpy.*len[^;]*;.*//.*not validated', code, re.IGNORECASE):
            findings.append({
                "line": 3,
                "severity": "critical",
                "category": "security",
                "rule": "CWE-120",
                "title": "Buffer overflow via unchecked memcpy",
                "message": "memcpy length not validated against buffer size.",
                "suggestion": "Check: if (len <= sizeof(buffer)) memcpy(...);"
            })
            
    elif lang == "python":
        if re.search(r'f"[^"]*SELECT|f"[^"]*INSERT|f"[^"]*UPDATE|f"[^"]*DELETE', code, re.IGNORECASE):
            findings.append({
                "line": 2,
                "severity": "critical",
                "category": "security",
                "rule": "CWE-89",
                "title": "SQL injection vulnerability",
                "message": "User input interpolated into SQL query.",
                "suggestion": "Use parameterized queries with placeholders."
            })
        if "os.system" in code or "os.popen" in code:
            findings.append({
                "line": 2,
                "severity": "critical",
                "category": "security",
                "rule": "CWE-78",
                "title": "Command injection vulnerability",
                "message": "User input passed to shell command.",
                "suggestion": "Use subprocess with shell=False and argument list."
            })
        if "subprocess" in code and "shell=True" in code:
            findings.append({
                "line": 2,
                "severity": "critical",
                "category": "security",
                "rule": "CWE-78",
                "title": "Command injection via shell=True",
                "message": "shell=True with user input allows command injection.",
                "suggestion": "Use shell=False with argument list."
            })
        if "open(" in code and "path.join" not in code.lower() and "os.path" not in code:
            if re.search(r'open\([^)]*\+', code):
                findings.append({
                    "line": 2,
                    "severity": "high",
                    "category": "security",
                    "rule": "CWE-22",
                    "title": "Potential path traversal",
                    "message": "File path constructed from user input without validation.",
                    "suggestion": "Validate path is within allowed directory."
                })
        if "shutil.copy" in code:
            findings.append({
                "line": 2,
                "severity": "high",
                "category": "security",
                "rule": "CWE-22",
                "title": "Potential path traversal in file copy",
                "message": "File operation with user-controlled path.",
                "suggestion": "Validate and sanitize the path."
            })
            
    elif lang == "go":
        if re.search(r'fmt\.Sprintf.*SELECT|"SELECT[^"]*"\s*\+', code, re.IGNORECASE):
            findings.append({
                "line": 2,
                "severity": "critical",
                "category": "security",
                "rule": "CWE-89",
                "title": "SQL injection vulnerability",
                "message": "String concatenation used to build SQL query.",
                "suggestion": "Use parameterized query with $1, $2 placeholders."
            })
        if "db.Exec" in code and '+ ' in code:
            findings.append({
                "line": 2,
                "severity": "critical",
                "category": "security",
                "rule": "CWE-89",
                "title": "SQL injection in Exec",
                "message": "User input concatenated into SQL.",
                "suggestion": "Use parameterized query."
            })
        if "filepath.Join" in code and "Clean" not in code:
            findings.append({
                "line": 2,
                "severity": "high",
                "category": "security",
                "rule": "CWE-22",
                "title": "Potential path traversal",
                "message": "filepath.Join doesn't prevent ../ traversal.",
                "suggestion": "Use filepath.Clean and verify path is within baseDir."
            })
        if re.search(r'\w+\s*,\s*_\s*:?=\s*os\.', code):
            findings.append({
                "line": 2,
                "severity": "medium",
                "category": "bug",
                "rule": None,
                "title": "Unchecked error",
                "message": "Error from os operation is ignored.",
                "suggestion": "Always check errors in Go."
            })
    
    return findings


def augment_dataset(input_path: Path, output_path: Path, multiplier: int = 10):
    """Augment the dataset with variations."""
    rng = random.Random(42)
    
    # Load original samples
    with open(input_path) as f:
        samples = [json.loads(line) for line in f]
    
    augmented = list(samples)  # Keep originals
    
    # Generate variations from templates
    for _ in range(multiplier):
        # C patterns
        for template in EXTRA_C_PATTERNS:
            code = substitute_vars(template, rng)
            findings = generate_finding_for_pattern(code, "c")
            if findings:
                augmented.append(format_sample(code, "c", findings))
        
        # Python patterns
        for template in EXTRA_PYTHON_PATTERNS:
            code = substitute_vars(template, rng)
            findings = generate_finding_for_pattern(code, "python")
            if findings:
                augmented.append(format_sample(code, "python", findings))
        
        # Go patterns
        for template in EXTRA_GO_PATTERNS:
            code = substitute_vars(template, rng)
            findings = generate_finding_for_pattern(code, "go")
            if findings:
                augmented.append(format_sample(code, "go", findings))
    
    # Shuffle
    rng.shuffle(augmented)
    
    # Write output
    with open(output_path, "w") as f:
        for sample in augmented:
            f.write(json.dumps(sample) + "\n")
    
    return len(augmented)


def format_sample(code: str, language: str, findings: list) -> dict:
    """Format code sample for training."""
    lines = code.strip().split("\n")
    numbered = "\n".join(f"{i+1:3} | {line}" for i, line in enumerate(lines))
    
    instruction = f"""Review the following {language} code for security vulnerabilities, bugs, and quality issues:

```{language}
{numbered}
```

Analyze carefully and report any issues found."""

    if findings:
        response = "\n".join(json.dumps(f) for f in findings)
    else:
        response = '{"no_issues": true}'
    
    return {"instruction": instruction, "response": response}


def main():
    data_dir = Path(__file__).parent.parent / "data"
    
    train_in = data_dir / "train.jsonl"
    train_out = data_dir / "train_augmented.jsonl"
    
    count = augment_dataset(train_in, train_out, multiplier=15)
    print(f"Generated {count} augmented training samples -> {train_out}")
    
    # Copy augmented to main train file
    import shutil
    shutil.copy(train_out, train_in)
    print(f"Updated {train_in}")


if __name__ == "__main__":
    main()
