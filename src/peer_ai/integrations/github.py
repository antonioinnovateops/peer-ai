"""GitHub integration for Peer-AI."""

import logging
import time
from typing import Optional

import httpx
import jwt

from peer_ai.models import Finding


logger = logging.getLogger(__name__)


class GitHubIntegration:
    """GitHub App integration for PR reviews."""
    
    def __init__(
        self,
        app_id: int,
        private_key: str,
        base_url: str = "https://api.github.com",
    ):
        self.app_id = app_id
        self.private_key = private_key
        self.base_url = base_url
        
        self._installation_tokens: dict[int, tuple[str, float]] = {}
    
    def _get_jwt(self) -> str:
        """Generate a JWT for GitHub App authentication."""
        now = int(time.time())
        payload = {
            "iat": now - 60,  # Issued 60 seconds ago
            "exp": now + 600,  # Expires in 10 minutes
            "iss": self.app_id,
        }
        return jwt.encode(payload, self.private_key, algorithm="RS256")
    
    async def _get_installation_token(self, installation_id: int) -> str:
        """Get an installation access token."""
        # Check cache
        if installation_id in self._installation_tokens:
            token, expires = self._installation_tokens[installation_id]
            if time.time() < expires - 60:  # Refresh 1 minute early
                return token
        
        # Request new token
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{self.base_url}/app/installations/{installation_id}/access_tokens",
                headers={
                    "Authorization": f"Bearer {self._get_jwt()}",
                    "Accept": "application/vnd.github+json",
                },
            )
            response.raise_for_status()
            data = response.json()
            
            token = data["token"]
            # Parse expiry (ISO format)
            from datetime import datetime
            expires_at = datetime.fromisoformat(data["expires_at"].replace("Z", "+00:00"))
            expires = expires_at.timestamp()
            
            self._installation_tokens[installation_id] = (token, expires)
            return token
    
    async def _get_installation_id(self, owner: str, repo: str) -> int:
        """Get the installation ID for a repository."""
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{self.base_url}/repos/{owner}/{repo}/installation",
                headers={
                    "Authorization": f"Bearer {self._get_jwt()}",
                    "Accept": "application/vnd.github+json",
                },
            )
            response.raise_for_status()
            return response.json()["id"]
    
    async def get_pr_diff(self, repo: str, pr_number: int) -> str:
        """Get the diff for a pull request.
        
        Args:
            repo: Repository in "owner/repo" format
            pr_number: Pull request number
            
        Returns:
            Unified diff text
        """
        owner, repo_name = repo.split("/", 1)
        installation_id = await self._get_installation_id(owner, repo_name)
        token = await self._get_installation_token(installation_id)
        
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{self.base_url}/repos/{repo}/pulls/{pr_number}",
                headers={
                    "Authorization": f"Bearer {token}",
                    "Accept": "application/vnd.github.diff",
                },
            )
            response.raise_for_status()
            return response.text
    
    async def post_review(
        self,
        repo: str,
        pr_number: int,
        findings: list[Finding],
        body: Optional[str] = None,
        event: str = "COMMENT",
    ):
        """Post a review with inline comments.
        
        Args:
            repo: Repository in "owner/repo" format
            pr_number: Pull request number
            findings: List of findings to post as comments
            body: Overall review body
            event: Review event (APPROVE, REQUEST_CHANGES, COMMENT)
        """
        owner, repo_name = repo.split("/", 1)
        installation_id = await self._get_installation_id(owner, repo_name)
        token = await self._get_installation_token(installation_id)
        
        # Get the PR to find the latest commit SHA
        async with httpx.AsyncClient() as client:
            pr_response = await client.get(
                f"{self.base_url}/repos/{repo}/pulls/{pr_number}",
                headers={
                    "Authorization": f"Bearer {token}",
                    "Accept": "application/vnd.github+json",
                },
            )
            pr_response.raise_for_status()
            commit_sha = pr_response.json()["head"]["sha"]
        
        # Build review comments
        comments = []
        for finding in findings:
            comment = {
                "path": finding.file,
                "line": finding.line,
                "body": self._format_comment(finding),
            }
            comments.append(comment)
        
        # Determine review event based on findings
        if not body:
            severity_counts = {}
            for f in findings:
                severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1
            
            body = f"## 🤖 Peer-AI Review\n\n"
            body += f"Found **{len(findings)}** issue(s):\n"
            for sev in ["critical", "high", "medium", "low"]:
                if sev in severity_counts:
                    emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵"}[sev]
                    body += f"- {emoji} {severity_counts[sev]} {sev}\n"
        
        if any(f.severity in ("critical", "high") for f in findings):
            event = "REQUEST_CHANGES"
        
        # Post review
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{self.base_url}/repos/{repo}/pulls/{pr_number}/reviews",
                headers={
                    "Authorization": f"Bearer {token}",
                    "Accept": "application/vnd.github+json",
                },
                json={
                    "commit_id": commit_sha,
                    "body": body,
                    "event": event,
                    "comments": comments,
                },
            )
            response.raise_for_status()
            logger.info(f"Posted review to PR #{pr_number}")
    
    def _format_comment(self, finding: Finding) -> str:
        """Format a finding as a GitHub comment."""
        severity_emoji = {
            "critical": "🔴",
            "high": "🟠",
            "medium": "🟡",
            "low": "🔵",
        }
        
        lines = [
            f"### {severity_emoji.get(finding.severity, '⚪')} {finding.title}",
            "",
            f"**Severity:** {finding.severity.upper()}",
        ]
        
        if finding.rule:
            lines.append(f"**Rule:** [{finding.rule}](https://cwe.mitre.org/data/definitions/{finding.rule.replace('CWE-', '')}.html)")
        
        lines.extend([
            "",
            finding.message,
        ])
        
        if finding.suggestion:
            lines.extend([
                "",
                "**Suggestion:**",
                finding.suggestion,
            ])
        
        if finding.code_suggestion:
            lines.extend([
                "",
                "```suggestion",
                finding.code_suggestion,
                "```",
            ])
        
        return "\n".join(lines)
