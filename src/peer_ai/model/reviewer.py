"""Code review model interface."""

import json
import logging
import re
from pathlib import Path
from typing import Optional

from peer_ai.models import Finding, Severity, Category


logger = logging.getLogger(__name__)

# Language detection by file extension
LANGUAGE_MAP = {
    ".c": "c",
    ".h": "c",
    ".cpp": "cpp",
    ".cxx": "cpp",
    ".cc": "cpp",
    ".hpp": "cpp",
    ".hxx": "cpp",
    ".rs": "rust",
    ".py": "python",
    ".pyi": "python",
    ".go": "go",
}

# System prompt for the review model
REVIEW_SYSTEM_PROMPT = """You are an expert code reviewer specializing in security analysis and code quality.

Your task is to review the provided code and identify:
1. Security vulnerabilities (buffer overflows, injection, authentication issues, etc.)
2. Bugs and logic errors
3. Code quality issues (error handling, resource leaks, etc.)
4. Performance problems

For each issue found, respond with a JSON object on a single line:
{"line": <line_number>, "severity": "<low|medium|high|critical>", "category": "<security|bug|quality|performance>", "rule": "<CWE-XXX or null>", "title": "<short title>", "message": "<detailed explanation>", "suggestion": "<how to fix>"}

If no issues are found, respond with: {"no_issues": true}

Be precise and concise. Focus on real issues, not style preferences unless they impact readability significantly."""

# Language-specific guidance
LANGUAGE_PROMPTS = {
    "c": """
Additional C-specific checks:
- Buffer overflows (strcpy, sprintf, gets)
- Format string vulnerabilities
- Integer overflow/underflow
- Null pointer dereferences
- Use after free
- Double free
- Memory leaks
- Uninitialized variables
""",
    "cpp": """
Additional C++-specific checks:
- All C vulnerabilities plus:
- Exception safety
- RAII violations
- Smart pointer misuse
- Move semantics issues
- Undefined behavior from object lifetime
""",
    "rust": """
Additional Rust-specific checks:
- Unsafe block misuse
- Panic in library code
- Unwrap/expect on Option/Result
- Memory safety in unsafe code
- Incorrect lifetime annotations
- Data races in unsafe code
""",
    "python": """
Additional Python-specific checks:
- SQL injection
- Command injection (subprocess, os.system)
- Path traversal
- Pickle/eval/exec usage
- Hardcoded secrets
- Insecure deserialization
- SSRF vulnerabilities
""",
    "go": """
Additional Go-specific checks:
- Goroutine leaks
- Race conditions
- Deferred function issues
- Nil pointer panics
- Unchecked errors
- SQL injection
- Command injection
""",
}


class CodeReviewer:
    """AI-powered code reviewer."""
    
    def __init__(
        self,
        model_name: str = "peer-ai/reviewer-1.5b",
        device: str = "cuda",
        quantization: Optional[str] = None,
    ):
        self.model_name = model_name
        self.device = device
        self.quantization = quantization
        
        self._model = None
        self._tokenizer = None
        self._pipeline = None
        
    def _load_model(self):
        """Lazy load the model."""
        if self._pipeline is not None:
            return
        
        logger.info(f"Loading model: {self.model_name}")
        
        try:
            import torch
            from transformers import pipeline, AutoModelForCausalLM, AutoTokenizer
            
            # Determine quantization config
            model_kwargs = {}
            if self.quantization == "4bit":
                from transformers import BitsAndBytesConfig
                model_kwargs["quantization_config"] = BitsAndBytesConfig(
                    load_in_4bit=True,
                    bnb_4bit_compute_dtype=torch.float16,
                )
            elif self.quantization == "8bit":
                from transformers import BitsAndBytesConfig
                model_kwargs["quantization_config"] = BitsAndBytesConfig(
                    load_in_8bit=True,
                )
            
            # Load model and tokenizer
            self._tokenizer = AutoTokenizer.from_pretrained(self.model_name)
            self._model = AutoModelForCausalLM.from_pretrained(
                self.model_name,
                device_map=self.device if self.device != "cpu" else None,
                torch_dtype=torch.float16 if self.device != "cpu" else torch.float32,
                **model_kwargs,
            )
            
            self._pipeline = pipeline(
                "text-generation",
                model=self._model,
                tokenizer=self._tokenizer,
                device_map=self.device if self.device != "cpu" else None,
            )
            
            logger.info("Model loaded successfully")
            
        except Exception as e:
            logger.error(f"Failed to load model: {e}")
            raise
    
    def review(
        self,
        code: str,
        file_path: str = "unknown",
        language: Optional[str] = None,
        line_offset: int = 1,
    ) -> list[Finding]:
        """Review code and return findings.
        
        Args:
            code: Source code to review
            file_path: Path to the file (for context and language detection)
            language: Override language detection
            line_offset: Line number offset for findings
            
        Returns:
            List of findings
        """
        self._load_model()
        
        # Detect language
        if language is None:
            ext = Path(file_path).suffix.lower()
            language = LANGUAGE_MAP.get(ext)
        
        # Build prompt
        system_prompt = REVIEW_SYSTEM_PROMPT
        if language and language in LANGUAGE_PROMPTS:
            system_prompt += LANGUAGE_PROMPTS[language]
        
        # Add line numbers to code
        numbered_code = self._add_line_numbers(code, start=line_offset)
        
        user_prompt = f"""Review the following {language or 'code'} from file `{file_path}`:

```{language or ''}
{numbered_code}
```

Identify any security vulnerabilities, bugs, or quality issues. Respond with one JSON object per line for each issue found."""
        
        # Generate review
        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ]
        
        try:
            response = self._pipeline(
                messages,
                max_new_tokens=2048,
                do_sample=True,
                temperature=0.3,
                top_p=0.95,
                return_full_text=False,
            )[0]["generated_text"]
            
            # Handle both string and dict responses
            if isinstance(response, dict):
                response = response.get("content", "")
            
            findings = self._parse_response(response, file_path)
            return findings
            
        except Exception as e:
            logger.error(f"Review failed: {e}")
            return []
    
    def _add_line_numbers(self, code: str, start: int = 1) -> str:
        """Add line numbers to code."""
        lines = code.split("\n")
        width = len(str(start + len(lines)))
        numbered = []
        for i, line in enumerate(lines, start=start):
            numbered.append(f"{i:>{width}} | {line}")
        return "\n".join(numbered)
    
    def _parse_response(self, response: str, file_path: str) -> list[Finding]:
        """Parse model response into findings."""
        findings = []
        
        # Try to extract JSON objects from response
        for line in response.split("\n"):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            
            # Skip "no issues" response
            if "no_issues" in line.lower():
                continue
            
            # Try to parse JSON
            try:
                # Find JSON in the line
                match = re.search(r'\{[^{}]+\}', line)
                if match:
                    data = json.loads(match.group())
                    
                    # Map to Finding
                    finding = Finding(
                        file=file_path,
                        line=data.get("line", 1),
                        severity=Severity(data.get("severity", "low")),
                        category=Category(data.get("category", "quality")),
                        rule=data.get("rule"),
                        title=data.get("title", "Issue found"),
                        message=data.get("message", ""),
                        suggestion=data.get("suggestion"),
                    )
                    findings.append(finding)
                    
            except (json.JSONDecodeError, ValueError) as e:
                logger.debug(f"Failed to parse line: {line} ({e})")
                continue
        
        return findings
