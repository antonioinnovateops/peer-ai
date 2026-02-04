# Peer-AI 🤖

**AI-powered code review that integrates with your git workflow.**

An open-source, self-hosted code reviewer powered by a fine-tuned language model. Reviews PRs/MRs automatically and posts inline comments like a human reviewer.

## Features

- 🔍 **Smart Diff Analysis** - Reviews only changed code, not entire files
- 💬 **Inline Comments** - Posts on specific lines with context
- 🛡️ **Security First** - Detects CVE patterns, unsafe code, vulnerabilities
- 🌐 **Multi-Language** - C, C++, Rust, Python, Go
- 🔌 **Git Integrations** - GitHub, GitLab, Gitea, Forgejo
- 🏠 **Self-Hosted** - Your code never leaves your infrastructure
- ⚡ **Fast** - Small model runs on consumer GPUs (6GB+ VRAM)

## Architecture

```
┌─────────────┐     Webhook      ┌─────────────┐     Analysis    ┌─────────────┐
│   GitHub    │ ───────────────► │   Server    │ ───────────────► │  Peer-AI    │
│   GitLab    │ ◄─────────────── │  (FastAPI)  │ ◄─────────────── │   Model     │
│   Gitea     │   PR Comments    └─────────────┘    Findings      │  (1-3B)     │
└─────────────┘                                                   └─────────────┘
```

## Quick Start

### 1. Install

```bash
pip install peer-ai
# or
pip install -e .
```

### 2. Run locally (CLI mode)

```bash
# Review a diff
git diff main..feature | peer-ai review

# Review staged changes
git diff --cached | peer-ai review

# Review a file
peer-ai review src/main.c
```

### 3. Run as server (webhook mode)

```bash
# Start server
peer-ai serve --port 8080

# Configure webhook in GitHub/GitLab to point to:
# https://your-server.com/webhook
```

## Configuration

```yaml
# peer-ai.yaml
model:
  name: peer-ai/reviewer-1.5b
  device: cuda  # or cpu
  
server:
  port: 8080
  secret: ${WEBHOOK_SECRET}

integrations:
  github:
    app_id: 12345
    private_key_path: ./github-app.pem
  gitlab:
    token: ${GITLAB_TOKEN}

review:
  languages: [c, cpp, rust, python, go]
  severity_threshold: medium  # low, medium, high, critical
  auto_approve: false
  max_comments_per_pr: 20
```

## Review Output

```json
{
  "file": "src/auth.c",
  "line": 42,
  "severity": "critical",
  "category": "security",
  "rule": "CWE-120",
  "title": "Buffer overflow vulnerability",
  "message": "strcpy() copies user input without bounds checking. This can lead to buffer overflow attacks.",
  "suggestion": "Use strncpy() or snprintf() with explicit size limits:\n```c\nstrncpy(buffer, input, sizeof(buffer) - 1);\nbuffer[sizeof(buffer) - 1] = '\\0';\n```"
}
```

## Supported Languages & Checks

| Language | Security | Quality | Style | Performance |
|----------|----------|---------|-------|-------------|
| C        | ✅       | ✅      | ✅    | ✅          |
| C++      | ✅       | ✅      | ✅    | ✅          |
| Rust     | ✅       | ✅      | ✅    | ✅          |
| Python   | ✅       | ✅      | ✅    | ✅          |
| Go       | ✅       | ✅      | ✅    | ✅          |

### Security Checks
- Buffer overflows (CWE-120, CWE-787)
- SQL injection (CWE-89)
- Command injection (CWE-78)
- Path traversal (CWE-22)
- Use after free (CWE-416)
- Null pointer dereference (CWE-476)
- Integer overflow (CWE-190)
- Hardcoded credentials (CWE-798)
- Insecure random (CWE-330)

## Training Your Own Model

```bash
# Generate training data from CVE databases
peer-ai data generate --output data/train.jsonl

# Fine-tune the model
peer-ai train --config configs/training.yaml

# Evaluate
peer-ai eval --model models/reviewer-1.5b
```

## License

Apache 2.0
