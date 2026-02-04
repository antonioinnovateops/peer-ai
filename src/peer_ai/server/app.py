"""FastAPI webhook server for Peer-AI."""

import hashlib
import hmac
import logging
from contextlib import asynccontextmanager
from typing import Optional

from fastapi import FastAPI, Request, HTTPException, BackgroundTasks
from pydantic_settings import BaseSettings

from peer_ai.model.reviewer import CodeReviewer
from peer_ai.integrations.github import GitHubIntegration
from peer_ai.integrations.gitlab import GitLabIntegration


logger = logging.getLogger(__name__)


class Settings(BaseSettings):
    """Server settings."""
    
    model_name: str = "peer-ai/reviewer-1.5b"
    model_device: str = "cuda"
    
    github_app_id: Optional[int] = None
    github_private_key: Optional[str] = None
    github_webhook_secret: Optional[str] = None
    
    gitlab_token: Optional[str] = None
    gitlab_webhook_secret: Optional[str] = None
    gitlab_url: str = "https://gitlab.com"
    
    auto_approve: bool = False
    severity_threshold: str = "low"
    max_comments_per_pr: int = 20
    
    class Config:
        env_prefix = "PEER_AI_"


# Global state
_reviewer: Optional[CodeReviewer] = None
_github: Optional[GitHubIntegration] = None
_gitlab: Optional[GitLabIntegration] = None
_settings: Optional[Settings] = None


def create_app(config_path: Optional[str] = None) -> FastAPI:
    """Create the FastAPI application."""
    
    @asynccontextmanager
    async def lifespan(app: FastAPI):
        """Initialize resources on startup."""
        global _reviewer, _github, _gitlab, _settings
        
        _settings = Settings()
        
        # Load model
        logger.info(f"Loading model: {_settings.model_name}")
        _reviewer = CodeReviewer(
            model_name=_settings.model_name,
            device=_settings.model_device,
        )
        
        # Initialize integrations
        if _settings.github_app_id and _settings.github_private_key:
            _github = GitHubIntegration(
                app_id=_settings.github_app_id,
                private_key=_settings.github_private_key,
            )
            logger.info("GitHub integration enabled")
        
        if _settings.gitlab_token:
            _gitlab = GitLabIntegration(
                token=_settings.gitlab_token,
                url=_settings.gitlab_url,
            )
            logger.info("GitLab integration enabled")
        
        yield
        
        # Cleanup
        logger.info("Shutting down...")
    
    app = FastAPI(
        title="Peer-AI",
        description="AI-powered code review webhook server",
        version="0.1.0",
        lifespan=lifespan,
    )
    
    @app.get("/health")
    async def health():
        """Health check endpoint."""
        return {
            "status": "healthy",
            "model_loaded": _reviewer is not None,
            "github_enabled": _github is not None,
            "gitlab_enabled": _gitlab is not None,
        }
    
    @app.post("/webhook/github")
    async def github_webhook(request: Request, background_tasks: BackgroundTasks):
        """Handle GitHub webhook events."""
        if not _github:
            raise HTTPException(status_code=503, detail="GitHub integration not configured")
        
        # Verify signature
        signature = request.headers.get("X-Hub-Signature-256")
        if _settings.github_webhook_secret and signature:
            body = await request.body()
            expected = "sha256=" + hmac.new(
                _settings.github_webhook_secret.encode(),
                body,
                hashlib.sha256
            ).hexdigest()
            if not hmac.compare_digest(signature, expected):
                raise HTTPException(status_code=401, detail="Invalid signature")
        
        event = request.headers.get("X-GitHub-Event")
        payload = await request.json()
        
        if event == "pull_request":
            action = payload.get("action")
            if action in ("opened", "synchronize", "reopened"):
                pr_number = payload["pull_request"]["number"]
                repo = payload["repository"]["full_name"]
                
                logger.info(f"Processing PR #{pr_number} on {repo}")
                background_tasks.add_task(
                    _review_github_pr,
                    repo=repo,
                    pr_number=pr_number,
                )
                return {"status": "processing", "pr": pr_number}
        
        return {"status": "ignored", "event": event}
    
    @app.post("/webhook/gitlab")
    async def gitlab_webhook(request: Request, background_tasks: BackgroundTasks):
        """Handle GitLab webhook events."""
        if not _gitlab:
            raise HTTPException(status_code=503, detail="GitLab integration not configured")
        
        # Verify token
        token = request.headers.get("X-Gitlab-Token")
        if _settings.gitlab_webhook_secret:
            if token != _settings.gitlab_webhook_secret:
                raise HTTPException(status_code=401, detail="Invalid token")
        
        payload = await request.json()
        event = payload.get("object_kind")
        
        if event == "merge_request":
            action = payload.get("object_attributes", {}).get("action")
            if action in ("open", "update", "reopen"):
                mr_iid = payload["object_attributes"]["iid"]
                project_id = payload["project"]["id"]
                
                logger.info(f"Processing MR !{mr_iid} on project {project_id}")
                background_tasks.add_task(
                    _review_gitlab_mr,
                    project_id=project_id,
                    mr_iid=mr_iid,
                )
                return {"status": "processing", "mr": mr_iid}
        
        return {"status": "ignored", "event": event}
    
    @app.post("/api/review")
    async def api_review(request: Request):
        """Direct API endpoint for code review."""
        if not _reviewer:
            raise HTTPException(status_code=503, detail="Model not loaded")
        
        payload = await request.json()
        code = payload.get("code", "")
        file_path = payload.get("file", "unknown")
        language = payload.get("language")
        
        findings = _reviewer.review(code, file_path=file_path, language=language)
        
        return {
            "findings": [f.model_dump() for f in findings],
            "count": len(findings),
        }
    
    return app


async def _review_github_pr(repo: str, pr_number: int):
    """Review a GitHub pull request."""
    try:
        # Get PR diff
        diff = await _github.get_pr_diff(repo, pr_number)
        
        # Parse and review
        from peer_ai.analyzers.diff import parse_diff
        files = parse_diff(diff)
        
        all_findings = []
        for file_path, hunks in files.items():
            for hunk in hunks:
                findings = _reviewer.review(
                    hunk["content"],
                    file_path=file_path,
                    line_offset=hunk["start_line"],
                )
                all_findings.extend(findings)
        
        # Post comments
        if all_findings:
            await _github.post_review(
                repo=repo,
                pr_number=pr_number,
                findings=all_findings[:_settings.max_comments_per_pr],
            )
            logger.info(f"Posted {len(all_findings)} comments to PR #{pr_number}")
        else:
            logger.info(f"No issues found in PR #{pr_number}")
            
    except Exception as e:
        logger.error(f"Error reviewing PR #{pr_number}: {e}")


async def _review_gitlab_mr(project_id: int, mr_iid: int):
    """Review a GitLab merge request."""
    try:
        # Get MR diff
        diff = await _gitlab.get_mr_diff(project_id, mr_iid)
        
        # Parse and review
        from peer_ai.analyzers.diff import parse_diff
        files = parse_diff(diff)
        
        all_findings = []
        for file_path, hunks in files.items():
            for hunk in hunks:
                findings = _reviewer.review(
                    hunk["content"],
                    file_path=file_path,
                    line_offset=hunk["start_line"],
                )
                all_findings.extend(findings)
        
        # Post comments
        if all_findings:
            await _gitlab.post_review(
                project_id=project_id,
                mr_iid=mr_iid,
                findings=all_findings[:_settings.max_comments_per_pr],
            )
            logger.info(f"Posted {len(all_findings)} comments to MR !{mr_iid}")
        else:
            logger.info(f"No issues found in MR !{mr_iid}")
            
    except Exception as e:
        logger.error(f"Error reviewing MR !{mr_iid}: {e}")
