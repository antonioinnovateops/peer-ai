"""GitLab integration for Peer-AI."""

import logging
from typing import Optional

import httpx

from peer_ai.models import Finding


logger = logging.getLogger(__name__)


class GitLabIntegration:
    """GitLab integration for MR reviews."""
    
    def __init__(
        self,
        token: str,
        url: str = "https://gitlab.com",
    ):
        self.token = token
        self.url = url.rstrip("/")
        self.api_url = f"{self.url}/api/v4"
    
    async def get_mr_diff(self, project_id: int, mr_iid: int) -> str:
        """Get the diff for a merge request.
        
        Args:
            project_id: GitLab project ID
            mr_iid: Merge request IID (internal ID)
            
        Returns:
            Unified diff text
        """
        async with httpx.AsyncClient() as client:
            # Get MR changes
            response = await client.get(
                f"{self.api_url}/projects/{project_id}/merge_requests/{mr_iid}/changes",
                headers={"PRIVATE-TOKEN": self.token},
            )
            response.raise_for_status()
            data = response.json()
            
            # Build unified diff from changes
            diff_parts = []
            for change in data.get("changes", []):
                diff_parts.append(change.get("diff", ""))
            
            return "\n".join(diff_parts)
    
    async def post_review(
        self,
        project_id: int,
        mr_iid: int,
        findings: list[Finding],
        summary: Optional[str] = None,
    ):
        """Post review comments on a merge request.
        
        Args:
            project_id: GitLab project ID
            mr_iid: Merge request IID
            findings: List of findings to post as comments
            summary: Optional summary comment
        """
        async with httpx.AsyncClient() as client:
            # Get MR info for head SHA
            mr_response = await client.get(
                f"{self.api_url}/projects/{project_id}/merge_requests/{mr_iid}",
                headers={"PRIVATE-TOKEN": self.token},
            )
            mr_response.raise_for_status()
            mr_data = mr_response.json()
            
            head_sha = mr_data["sha"]
            base_sha = mr_data["diff_refs"]["base_sha"]
            
            # Post summary comment if provided
            if summary:
                await client.post(
                    f"{self.api_url}/projects/{project_id}/merge_requests/{mr_iid}/notes",
                    headers={"PRIVATE-TOKEN": self.token},
                    json={"body": summary},
                )
            
            # Post inline comments for each finding
            for finding in findings:
                comment_body = self._format_comment(finding)
                
                # Create a discussion with position
                await client.post(
                    f"{self.api_url}/projects/{project_id}/merge_requests/{mr_iid}/discussions",
                    headers={"PRIVATE-TOKEN": self.token},
                    json={
                        "body": comment_body,
                        "position": {
                            "position_type": "text",
                            "base_sha": base_sha,
                            "head_sha": head_sha,
                            "start_sha": base_sha,
                            "new_path": finding.file,
                            "new_line": finding.line,
                        },
                    },
                )
            
            logger.info(f"Posted {len(findings)} comments to MR !{mr_iid}")
    
    async def approve_mr(self, project_id: int, mr_iid: int):
        """Approve a merge request."""
        async with httpx.AsyncClient() as client:
            await client.post(
                f"{self.api_url}/projects/{project_id}/merge_requests/{mr_iid}/approve",
                headers={"PRIVATE-TOKEN": self.token},
            )
            logger.info(f"Approved MR !{mr_iid}")
    
    async def unapprove_mr(self, project_id: int, mr_iid: int):
        """Remove approval from a merge request."""
        async with httpx.AsyncClient() as client:
            await client.post(
                f"{self.api_url}/projects/{project_id}/merge_requests/{mr_iid}/unapprove",
                headers={"PRIVATE-TOKEN": self.token},
            )
    
    def _format_comment(self, finding: Finding) -> str:
        """Format a finding as a GitLab comment."""
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
                "```suggestion:-0+0",
                finding.code_suggestion,
                "```",
            ])
        
        return "\n".join(lines)
