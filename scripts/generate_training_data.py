#!/usr/bin/env python3
"""Generate comprehensive training data for Peer-AI."""

import json
import random
from pathlib import Path

# ============================================================================
# C/C++ Vulnerable Patterns
# ============================================================================

C_VULNERABLE = [
    # Buffer overflows
    {
        "code": '''void process_name(char *input) {
    char buffer[64];
    strcpy(buffer, input);
    printf("Hello, %s!\\n", buffer);
}''',
        "findings": [{
            "line": 3,
            "severity": "critical",
            "category": "security",
            "rule": "CWE-120",
            "title": "Buffer overflow via strcpy",
            "message": "strcpy() has no bounds checking. If input exceeds 64 bytes, it will overflow buffer and corrupt the stack, potentially allowing code execution.",
            "suggestion": "Use strncpy with size limit: strncpy(buffer, input, sizeof(buffer)-1); buffer[sizeof(buffer)-1]='\\0';"
        }],
        "language": "c"
    },
    {
        "code": '''char* read_input() {
    char buf[256];
    gets(buf);
    return strdup(buf);
}''',
        "findings": [{
            "line": 3,
            "severity": "critical",
            "category": "security",
            "rule": "CWE-120",
            "title": "Use of gets() - always vulnerable",
            "message": "gets() cannot limit input length and was removed from C11 due to being inherently unsafe. Any input longer than 255 bytes causes buffer overflow.",
            "suggestion": "Use fgets(buf, sizeof(buf), stdin) instead."
        }],
        "language": "c"
    },
    {
        "code": '''void log_message(const char *user, const char *action) {
    char log_entry[128];
    sprintf(log_entry, "[%s] User %s performed: %s", timestamp(), user, action);
    write_log(log_entry);
}''',
        "findings": [{
            "line": 3,
            "severity": "high",
            "category": "security",
            "rule": "CWE-120",
            "title": "Potential buffer overflow via sprintf",
            "message": "sprintf() doesn't check bounds. Combined length of timestamp, user, and action could exceed 128 bytes.",
            "suggestion": "Use snprintf(log_entry, sizeof(log_entry), ...) to prevent overflow."
        }],
        "language": "c"
    },
    {
        "code": '''void copy_data(char *dest, size_t dest_size, char *src) {
    memcpy(dest, src, strlen(src));
}''',
        "findings": [{
            "line": 3,
            "severity": "critical",
            "category": "security",
            "rule": "CWE-120",
            "title": "Buffer overflow - memcpy without bounds check",
            "message": "memcpy copies strlen(src) bytes without checking if dest_size is sufficient. This ignores the dest_size parameter entirely.",
            "suggestion": "Check size before copy: size_t len = strlen(src); if (len < dest_size) memcpy(dest, src, len+1);"
        }],
        "language": "c"
    },
    
    # Format string vulnerabilities
    {
        "code": '''void print_error(char *user_message) {
    printf(user_message);
}''',
        "findings": [{
            "line": 2,
            "severity": "critical",
            "category": "security",
            "rule": "CWE-134",
            "title": "Format string vulnerability",
            "message": "User-controlled string passed directly to printf(). Attacker can use %x to leak stack data or %n to write to arbitrary memory.",
            "suggestion": "Use printf(\"%s\", user_message) to treat input as data, not format string."
        }],
        "language": "c"
    },
    {
        "code": '''void log_error(char *fmt, ...) {
    char buf[512];
    va_list args;
    va_start(args, fmt);
    vsprintf(buf, fmt, args);
    va_end(args);
    syslog(LOG_ERR, buf);
}''',
        "findings": [
            {
                "line": 5,
                "severity": "high",
                "category": "security",
                "rule": "CWE-120",
                "title": "Buffer overflow via vsprintf",
                "message": "vsprintf has no bounds checking. Formatted output could exceed 512 bytes.",
                "suggestion": "Use vsnprintf(buf, sizeof(buf), fmt, args) instead."
            },
            {
                "line": 7,
                "severity": "high",
                "category": "security", 
                "rule": "CWE-134",
                "title": "Format string passed to syslog",
                "message": "buf is used as format string in syslog(). If buf contains format specifiers, this is exploitable.",
                "suggestion": "Use syslog(LOG_ERR, \"%s\", buf) to prevent format string attacks."
            }
        ],
        "language": "c"
    },
    
    # Use after free
    {
        "code": '''void process_request(Request *req) {
    char *data = req->data;
    free(req);
    
    // Process the data
    parse_data(data);  // UAF: data was part of req
}''',
        "findings": [{
            "line": 6,
            "severity": "critical",
            "category": "security",
            "rule": "CWE-416",
            "title": "Use after free",
            "message": "data points into the freed req structure. Accessing it after free() is undefined behavior and can lead to code execution.",
            "suggestion": "Copy data before freeing req, or restructure to free req after processing."
        }],
        "language": "c"
    },
    {
        "code": '''char* get_cached_value(const char *key) {
    static char *cache = NULL;
    if (cache) free(cache);
    cache = strdup(lookup(key));
    return cache;
}''',
        "findings": [{
            "line": 3,
            "severity": "high",
            "category": "security",
            "rule": "CWE-416",
            "title": "Potential use after free in concurrent access",
            "message": "If called concurrently, one thread may free cache while another is using the returned pointer. The static variable creates a race condition.",
            "suggestion": "Return a copy instead of the cached pointer, or use thread-local storage."
        }],
        "language": "c"
    },
    
    # Double free
    {
        "code": '''void cleanup(Connection *conn) {
    if (conn->buffer) {
        free(conn->buffer);
    }
    free(conn->buffer);  // Double free!
    free(conn);
}''',
        "findings": [{
            "line": 5,
            "severity": "critical",
            "category": "security",
            "rule": "CWE-415",
            "title": "Double free vulnerability",
            "message": "conn->buffer is freed twice. Double free corrupts heap metadata and can be exploited for code execution.",
            "suggestion": "Set pointer to NULL after free: free(conn->buffer); conn->buffer = NULL;"
        }],
        "language": "c"
    },
    
    # Null pointer dereference
    {
        "code": '''void process_config(Config *cfg) {
    char *name = cfg->username;
    int len = strlen(name);
    
    if (cfg == NULL) {
        return;
    }
    // ... rest of function
}''',
        "findings": [{
            "line": 2,
            "severity": "high",
            "category": "security",
            "rule": "CWE-476",
            "title": "Null pointer dereference before check",
            "message": "cfg is dereferenced on line 2, but null check is on line 5. If cfg is NULL, this crashes before the check.",
            "suggestion": "Move the null check to the beginning of the function, before any dereference."
        }],
        "language": "c"
    },
    
    # Integer overflow
    {
        "code": '''void *allocate_array(int count, int elem_size) {
    int total = count * elem_size;
    return malloc(total);
}''',
        "findings": [{
            "line": 2,
            "severity": "high",
            "category": "security",
            "rule": "CWE-190",
            "title": "Integer overflow in size calculation",
            "message": "count * elem_size can overflow if both are large, resulting in a small allocation. Subsequent writes will overflow the undersized buffer.",
            "suggestion": "Check for overflow: if (count > SIZE_MAX / elem_size) return NULL; or use calloc(count, elem_size)."
        }],
        "language": "c"
    },
    
    # Uninitialized variable
    {
        "code": '''int authenticate(const char *password) {
    int authenticated;
    
    if (strcmp(password, get_stored_hash()) == 0) {
        authenticated = 1;
    }
    
    return authenticated;
}''',
        "findings": [{
            "line": 8,
            "severity": "high",
            "category": "security",
            "rule": "CWE-457",
            "title": "Uninitialized variable in security check",
            "message": "authenticated is only set when password matches. If it doesn't match, the uninitialized value (random stack data) is returned, potentially granting access.",
            "suggestion": "Initialize: int authenticated = 0;"
        }],
        "language": "c"
    },
    
    # Command injection
    {
        "code": '''void send_email(const char *to, const char *subject) {
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "mail -s '%s' %s", subject, to);
    system(cmd);
}''',
        "findings": [{
            "line": 4,
            "severity": "critical",
            "category": "security",
            "rule": "CWE-78",
            "title": "Command injection vulnerability",
            "message": "User input (to, subject) is passed to system(). An attacker can inject: subject=\"'; rm -rf /; '\" to execute arbitrary commands.",
            "suggestion": "Use execve() with separate arguments, or sanitize inputs rigorously. Better: use a mail library instead of shell."
        }],
        "language": "c"
    },
]

# ============================================================================
# Python Vulnerable Patterns
# ============================================================================

PYTHON_VULNERABLE = [
    # SQL injection
    {
        "code": '''def get_user(username):
    query = f"SELECT * FROM users WHERE username = '{username}'"
    cursor.execute(query)
    return cursor.fetchone()''',
        "findings": [{
            "line": 2,
            "severity": "critical",
            "category": "security",
            "rule": "CWE-89",
            "title": "SQL injection vulnerability",
            "message": "User input directly interpolated into SQL. Attacker can input: ' OR '1'='1 to bypass auth, or '; DROP TABLE users;-- to destroy data.",
            "suggestion": "Use parameterized query: cursor.execute('SELECT * FROM users WHERE username = ?', (username,))"
        }],
        "language": "python"
    },
    {
        "code": '''def search_products(category, min_price):
    query = "SELECT * FROM products WHERE category = '%s' AND price > %s" % (category, min_price)
    return db.execute(query).fetchall()''',
        "findings": [{
            "line": 2,
            "severity": "critical",
            "category": "security",
            "rule": "CWE-89",
            "title": "SQL injection via string formatting",
            "message": "Using % formatting to build SQL queries allows injection attacks.",
            "suggestion": "Use parameterized queries: db.execute('SELECT * FROM products WHERE category = ? AND price > ?', (category, min_price))"
        }],
        "language": "python"
    },
    
    # Command injection
    {
        "code": '''import os

def ping_server(hostname):
    os.system(f"ping -c 3 {hostname}")''',
        "findings": [{
            "line": 4,
            "severity": "critical",
            "category": "security",
            "rule": "CWE-78",
            "title": "Command injection via os.system",
            "message": "User input in os.system() allows command injection. Input: 'localhost; cat /etc/passwd' executes arbitrary commands.",
            "suggestion": "Use subprocess.run(['ping', '-c', '3', hostname], check=True) with shell=False."
        }],
        "language": "python"
    },
    {
        "code": '''import subprocess

def run_script(script_name, args):
    cmd = f"python {script_name} {args}"
    subprocess.call(cmd, shell=True)''',
        "findings": [{
            "line": 5,
            "severity": "critical",
            "category": "security",
            "rule": "CWE-78",
            "title": "Command injection via shell=True",
            "message": "Using shell=True with user input allows shell metacharacter injection.",
            "suggestion": "subprocess.run(['python', script_name] + args.split(), shell=False)"
        }],
        "language": "python"
    },
    
    # Code injection
    {
        "code": '''def calculate(expression):
    return eval(expression)''',
        "findings": [{
            "line": 2,
            "severity": "critical",
            "category": "security",
            "rule": "CWE-94",
            "title": "Code injection via eval()",
            "message": "eval() executes arbitrary Python code. Input: __import__('os').system('rm -rf /') destroys the system.",
            "suggestion": "Use ast.literal_eval() for safe literal parsing, or a math expression library like numexpr."
        }],
        "language": "python"
    },
    {
        "code": '''def load_config(config_str):
    exec(config_str)
    return globals()''',
        "findings": [{
            "line": 2,
            "severity": "critical",
            "category": "security",
            "rule": "CWE-94",
            "title": "Code injection via exec()",
            "message": "exec() runs arbitrary code. Never use on untrusted input.",
            "suggestion": "Use a safe config format like JSON or YAML with safe_load()."
        }],
        "language": "python"
    },
    
    # Path traversal
    {
        "code": '''def read_file(filename):
    path = f"/var/www/uploads/{filename}"
    with open(path, 'r') as f:
        return f.read()''',
        "findings": [{
            "line": 2,
            "severity": "high",
            "category": "security",
            "rule": "CWE-22",
            "title": "Path traversal vulnerability",
            "message": "filename can contain ../../../etc/passwd to read arbitrary files outside the uploads directory.",
            "suggestion": "Validate filename: os.path.basename(filename) or check resolved path starts with allowed directory."
        }],
        "language": "python"
    },
    
    # Insecure deserialization
    {
        "code": '''import pickle

def load_session(data):
    return pickle.loads(data)''',
        "findings": [{
            "line": 4,
            "severity": "critical",
            "category": "security",
            "rule": "CWE-502",
            "title": "Insecure deserialization with pickle",
            "message": "pickle.loads() can execute arbitrary code during deserialization. Never unpickle untrusted data.",
            "suggestion": "Use JSON or a safe serialization format. If pickle is required, use hmac to verify data integrity."
        }],
        "language": "python"
    },
    
    # Hardcoded credentials
    {
        "code": '''DATABASE_PASSWORD = "admin123"
API_KEY = "sk-1234567890abcdef"

def connect():
    return psycopg2.connect(password=DATABASE_PASSWORD)''',
        "findings": [
            {
                "line": 1,
                "severity": "critical",
                "category": "security",
                "rule": "CWE-798",
                "title": "Hardcoded database password",
                "message": "Credentials in source code are exposed in version control and logs.",
                "suggestion": "Use environment variables: os.environ.get('DATABASE_PASSWORD')"
            },
            {
                "line": 2,
                "severity": "critical",
                "category": "security",
                "rule": "CWE-798",
                "title": "Hardcoded API key",
                "message": "API keys in source code can be extracted and abused.",
                "suggestion": "Load from environment or secrets manager."
            }
        ],
        "language": "python"
    },
    
    # Weak cryptography
    {
        "code": '''import hashlib

def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()''',
        "findings": [{
            "line": 4,
            "severity": "high",
            "category": "security",
            "rule": "CWE-327",
            "title": "Weak password hashing (MD5)",
            "message": "MD5 is cryptographically broken and too fast for password hashing. Rainbow tables can crack MD5 hashes instantly.",
            "suggestion": "Use bcrypt, argon2, or scrypt: import bcrypt; bcrypt.hashpw(password.encode(), bcrypt.gensalt())"
        }],
        "language": "python"
    },
    {
        "code": '''import random

def generate_token():
    return ''.join(random.choices('abcdef0123456789', k=32))''',
        "findings": [{
            "line": 4,
            "severity": "high",
            "category": "security",
            "rule": "CWE-330",
            "title": "Insecure random number generator",
            "message": "random module is not cryptographically secure. Tokens can be predicted if seed is known.",
            "suggestion": "Use secrets module: import secrets; secrets.token_hex(16)"
        }],
        "language": "python"
    },
    
    # SSRF
    {
        "code": '''import requests

def fetch_url(url):
    return requests.get(url).text''',
        "findings": [{
            "line": 4,
            "severity": "high",
            "category": "security",
            "rule": "CWE-918",
            "title": "Server-Side Request Forgery (SSRF)",
            "message": "Unrestricted URL fetching allows attackers to access internal services (http://169.254.169.254 for cloud metadata, internal APIs).",
            "suggestion": "Validate URL against allowlist of domains. Block private IP ranges and cloud metadata endpoints."
        }],
        "language": "python"
    },
]

# ============================================================================
# Go Vulnerable Patterns
# ============================================================================

GO_VULNERABLE = [
    # SQL injection
    {
        "code": '''func GetUser(db *sql.DB, username string) (*User, error) {
    query := fmt.Sprintf("SELECT * FROM users WHERE username = '%s'", username)
    row := db.QueryRow(query)
    var user User
    err := row.Scan(&user.ID, &user.Username, &user.Email)
    return &user, err
}''',
        "findings": [{
            "line": 2,
            "severity": "critical",
            "category": "security",
            "rule": "CWE-89",
            "title": "SQL injection vulnerability",
            "message": "String formatting used to build SQL query. Vulnerable to injection attacks.",
            "suggestion": "Use parameterized query: db.QueryRow(\"SELECT * FROM users WHERE username = $1\", username)"
        }],
        "language": "go"
    },
    
    # Command injection
    {
        "code": '''func RunCommand(userInput string) error {
    cmd := exec.Command("sh", "-c", "echo " + userInput)
    return cmd.Run()
}''',
        "findings": [{
            "line": 2,
            "severity": "critical",
            "category": "security",
            "rule": "CWE-78",
            "title": "Command injection",
            "message": "User input concatenated into shell command. Attacker can inject: \"; rm -rf /\"",
            "suggestion": "Pass arguments separately: exec.Command(\"echo\", userInput) without shell."
        }],
        "language": "go"
    },
    
    # Path traversal
    {
        "code": '''func ServeFile(w http.ResponseWriter, r *http.Request) {
    filename := r.URL.Query().Get("file")
    data, _ := ioutil.ReadFile("/var/www/files/" + filename)
    w.Write(data)
}''',
        "findings": [{
            "line": 3,
            "severity": "high",
            "category": "security",
            "rule": "CWE-22",
            "title": "Path traversal vulnerability",
            "message": "filename can contain ../../../etc/passwd to read arbitrary files.",
            "suggestion": "Use filepath.Clean and verify the path is within allowed directory."
        }],
        "language": "go"
    },
    
    # Unchecked error
    {
        "code": '''func SaveConfig(data []byte) {
    f, _ := os.Create("/etc/app/config.json")
    f.Write(data)
    f.Close()
}''',
        "findings": [
            {
                "line": 2,
                "severity": "medium",
                "category": "bug",
                "rule": None,
                "title": "Unchecked error from os.Create",
                "message": "Error from os.Create is ignored. If file creation fails, f will be nil causing panic on Write.",
                "suggestion": "Always check errors: f, err := os.Create(...); if err != nil { return err }"
            },
            {
                "line": 4,
                "severity": "low",
                "category": "quality",
                "rule": None,
                "title": "File not closed with defer",
                "message": "Using Close() directly may skip cleanup if Write() panics.",
                "suggestion": "Use defer f.Close() immediately after successful open."
            }
        ],
        "language": "go"
    },
    
    # Race condition
    {
        "code": '''var counter int

func Increment() {
    counter++
}

func GetCount() int {
    return counter
}''',
        "findings": [{
            "line": 4,
            "severity": "high",
            "category": "security",
            "rule": "CWE-362",
            "title": "Data race on shared variable",
            "message": "counter is accessed from multiple goroutines without synchronization. This causes undefined behavior.",
            "suggestion": "Use sync/atomic: atomic.AddInt64(&counter, 1), or protect with sync.Mutex."
        }],
        "language": "go"
    },
]

# ============================================================================
# Rust Vulnerable Patterns  
# ============================================================================

RUST_VULNERABLE = [
    # Unwrap on user input
    {
        "code": '''fn parse_port(input: &str) -> u16 {
    input.parse().unwrap()
}''',
        "findings": [{
            "line": 2,
            "severity": "medium",
            "category": "bug",
            "rule": None,
            "title": "Panic on invalid input",
            "message": "unwrap() will panic if input is not a valid u16. In a server, this causes denial of service.",
            "suggestion": "Handle the error: input.parse().unwrap_or(8080) or return Result."
        }],
        "language": "rust"
    },
    
    # Unsafe block misuse
    {
        "code": '''fn get_element(slice: &[i32], index: usize) -> i32 {
    unsafe {
        *slice.as_ptr().add(index)
    }
}''',
        "findings": [{
            "line": 3,
            "severity": "high",
            "category": "security",
            "rule": "CWE-125",
            "title": "Unsafe out-of-bounds access",
            "message": "No bounds checking before pointer arithmetic. If index >= slice.len(), this reads invalid memory.",
            "suggestion": "Use safe indexing: slice.get(index).copied() or check bounds before unsafe block."
        }],
        "language": "rust"
    },
    
    # SQL injection (with sqlx)
    {
        "code": '''async fn get_user(pool: &PgPool, username: &str) -> Result<User, Error> {
    let query = format!("SELECT * FROM users WHERE username = '{}'", username);
    sqlx::query_as::<_, User>(&query).fetch_one(pool).await
}''',
        "findings": [{
            "line": 2,
            "severity": "critical",
            "category": "security",
            "rule": "CWE-89",
            "title": "SQL injection vulnerability",
            "message": "String formatting used to build query. Rust's type safety doesn't prevent SQL injection!",
            "suggestion": "Use query parameters: sqlx::query_as!(User, \"SELECT * FROM users WHERE username = $1\", username)"
        }],
        "language": "rust"
    },
]

# ============================================================================
# C++ Vulnerable Patterns
# ============================================================================

CPP_VULNERABLE = [
    # Buffer overflow
    {
        "code": '''void processInput(const char* input) {
    char buffer[100];
    std::strcpy(buffer, input);
    std::cout << buffer << std::endl;
}''',
        "findings": [{
            "line": 3,
            "severity": "critical",
            "category": "security",
            "rule": "CWE-120",
            "title": "Buffer overflow via strcpy",
            "message": "C-style strcpy in C++ code has no bounds checking.",
            "suggestion": "Use std::string instead: std::string buffer(input);"
        }],
        "language": "cpp"
    },
    
    # Use after move
    {
        "code": '''void process(std::unique_ptr<Data> data) {
    auto moved = std::move(data);
    moved->process();
    data->validate();  // Use after move!
}''',
        "findings": [{
            "line": 4,
            "severity": "high",
            "category": "bug",
            "rule": "CWE-416",
            "title": "Use after move",
            "message": "data was moved to 'moved' on line 2. Accessing data->validate() is undefined behavior.",
            "suggestion": "Don't use moved-from objects. Restructure logic or use shared_ptr if shared ownership needed."
        }],
        "language": "cpp"
    },
    
    # Exception safety
    {
        "code": '''void updateData(Data* d) {
    delete d->buffer;
    d->buffer = new char[1024];  // May throw!
    d->size = 1024;
}''',
        "findings": [{
            "line": 3,
            "severity": "medium",
            "category": "bug",
            "rule": None,
            "title": "Exception safety issue",
            "message": "If new throws, d->buffer is deleted but d->size keeps old value. Object left in invalid state.",
            "suggestion": "Allocate first, then delete: auto newBuf = new char[1024]; delete d->buffer; d->buffer = newBuf;"
        }],
        "language": "cpp"
    },
]

# ============================================================================
# Safe/Clean Code Examples (for balance)
# ============================================================================

SAFE_EXAMPLES = [
    {
        "code": '''void process_name(const char *input, size_t max_len) {
    char buffer[64];
    size_t len = strnlen(input, max_len);
    if (len >= sizeof(buffer)) {
        len = sizeof(buffer) - 1;
    }
    memcpy(buffer, input, len);
    buffer[len] = '\\0';
    printf("Hello, %s!\\n", buffer);
}''',
        "findings": [],
        "language": "c"
    },
    {
        "code": '''def get_user(username: str) -> Optional[User]:
    """Safely fetch user with parameterized query."""
    cursor.execute(
        "SELECT * FROM users WHERE username = ?",
        (username,)
    )
    return cursor.fetchone()''',
        "findings": [],
        "language": "python"
    },
    {
        "code": '''func GetUser(db *sql.DB, username string) (*User, error) {
    var user User
    err := db.QueryRow(
        "SELECT id, username, email FROM users WHERE username = $1",
        username,
    ).Scan(&user.ID, &user.Username, &user.Email)
    if err != nil {
        return nil, fmt.Errorf("get user: %w", err)
    }
    return &user, nil
}''',
        "findings": [],
        "language": "go"
    },
    {
        "code": '''fn parse_port(input: &str) -> Result<u16, ParseIntError> {
    input.parse()
}''',
        "findings": [],
        "language": "rust"
    },
    {
        "code": '''import secrets
import bcrypt

def hash_password(password: str) -> str:
    """Securely hash a password using bcrypt."""
    salt = bcrypt.gensalt(rounds=12)
    return bcrypt.hashpw(password.encode(), salt).decode()

def generate_token() -> str:
    """Generate a cryptographically secure token."""
    return secrets.token_urlsafe(32)''',
        "findings": [],
        "language": "python"
    },
]


def format_sample(sample: dict) -> dict:
    """Format a sample for training."""
    code = sample["code"]
    language = sample.get("language", "")
    findings = sample.get("findings", [])
    
    # Add line numbers
    lines = code.split("\n")
    numbered = "\n".join(f"{i+1:3} | {line}" for i, line in enumerate(lines))
    
    instruction = f"""Review the following {language} code for security vulnerabilities, bugs, and quality issues:

```{language}
{numbered}
```

Analyze carefully and report any issues found. For each issue, provide a JSON object with: line, severity (low/medium/high/critical), category (security/bug/quality/performance), rule (CWE-XXX if applicable), title, message, and suggestion."""

    if findings:
        response = "\n".join(json.dumps(f) for f in findings)
    else:
        response = '{"no_issues": true, "message": "Code looks secure and well-written."}'
    
    return {
        "instruction": instruction,
        "response": response,
    }


def main():
    output_dir = Path(__file__).parent.parent / "data"
    output_dir.mkdir(exist_ok=True)
    
    # Combine all samples
    all_samples = (
        C_VULNERABLE + 
        PYTHON_VULNERABLE + 
        GO_VULNERABLE + 
        RUST_VULNERABLE + 
        CPP_VULNERABLE +
        SAFE_EXAMPLES
    )
    
    # Shuffle
    random.seed(42)
    random.shuffle(all_samples)
    
    # Split train/eval (90/10)
    split = int(len(all_samples) * 0.9)
    train_samples = all_samples[:split]
    eval_samples = all_samples[split:]
    
    # Format and write
    train_path = output_dir / "train.jsonl"
    eval_path = output_dir / "eval.jsonl"
    
    with open(train_path, "w") as f:
        for sample in train_samples:
            formatted = format_sample(sample)
            f.write(json.dumps(formatted) + "\n")
    
    with open(eval_path, "w") as f:
        for sample in eval_samples:
            formatted = format_sample(sample)
            f.write(json.dumps(formatted) + "\n")
    
    print(f"Generated {len(train_samples)} training samples -> {train_path}")
    print(f"Generated {len(eval_samples)} eval samples -> {eval_path}")
    
    # Also create a raw version for inspection
    raw_path = output_dir / "raw_patterns.json"
    with open(raw_path, "w") as f:
        json.dump(all_samples, f, indent=2)
    print(f"Saved raw patterns -> {raw_path}")


if __name__ == "__main__":
    main()
