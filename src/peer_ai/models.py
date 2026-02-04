"""Data models for Peer-AI."""

from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


class Severity(str, Enum):
    """Issue severity levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Category(str, Enum):
    """Issue categories."""
    SECURITY = "security"
    BUG = "bug"
    QUALITY = "quality"
    PERFORMANCE = "performance"
    STYLE = "style"


class Finding(BaseModel):
    """A code review finding."""
    
    file: str = Field(description="File path")
    line: int = Field(description="Line number")
    end_line: Optional[int] = Field(default=None, description="End line for multi-line issues")
    column: Optional[int] = Field(default=None, description="Column number")
    
    severity: Severity = Field(description="Issue severity")
    category: Category = Field(description="Issue category")
    rule: Optional[str] = Field(default=None, description="Rule ID (e.g., CWE-120)")
    
    title: str = Field(description="Short issue title")
    message: str = Field(description="Detailed explanation")
    suggestion: Optional[str] = Field(default=None, description="Suggested fix")
    code_suggestion: Optional[str] = Field(default=None, description="Code snippet for fix")
    
    confidence: float = Field(default=1.0, ge=0.0, le=1.0, description="Model confidence")


class DiffHunk(BaseModel):
    """A hunk from a diff."""
    
    file: str
    start_line: int
    end_line: int
    content: str
    language: Optional[str] = None


class ReviewRequest(BaseModel):
    """A code review request."""
    
    files: list[DiffHunk] = Field(description="Files/hunks to review")
    context: Optional[str] = Field(default=None, description="Additional context")
    languages: list[str] = Field(default_factory=list, description="Languages to focus on")
    severity_threshold: Severity = Field(default=Severity.LOW)


class ReviewResponse(BaseModel):
    """Code review response."""
    
    findings: list[Finding] = Field(default_factory=list)
    summary: Optional[str] = Field(default=None, description="Review summary")
    approved: bool = Field(default=False)
    
    @property
    def has_critical(self) -> bool:
        return any(f.severity == Severity.CRITICAL for f in self.findings)
    
    @property
    def has_high(self) -> bool:
        return any(f.severity == Severity.HIGH for f in self.findings)


class PRInfo(BaseModel):
    """Pull/Merge Request information."""
    
    id: int
    number: int
    title: str
    author: str
    base_branch: str
    head_branch: str
    url: str
    
    # Provider info
    provider: str = Field(description="github, gitlab, gitea")
    repo_owner: str
    repo_name: str
