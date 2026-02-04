"""Diff parser for code review."""

import re
from typing import TypedDict


class Hunk(TypedDict):
    """A diff hunk."""
    start_line: int
    end_line: int
    content: str


def parse_diff(diff_text: str) -> dict[str, list[Hunk]]:
    """Parse a unified diff into files and hunks.
    
    Args:
        diff_text: Unified diff text
        
    Returns:
        Dict mapping file paths to list of hunks
    """
    files: dict[str, list[Hunk]] = {}
    
    current_file = None
    current_hunk_lines = []
    current_start_line = 0
    current_line = 0
    
    for line in diff_text.split("\n"):
        # New file
        if line.startswith("diff --git"):
            # Save previous hunk
            if current_file and current_hunk_lines:
                _save_hunk(files, current_file, current_start_line, current_line, current_hunk_lines)
                current_hunk_lines = []
            
            # Extract file path from diff header
            match = re.search(r'b/(.+)$', line)
            if match:
                current_file = match.group(1)
                if current_file not in files:
                    files[current_file] = []
            continue
        
        # File path from +++ line (more reliable)
        if line.startswith("+++"):
            match = re.search(r'\+\+\+ b/(.+)$', line) or re.search(r'\+\+\+ (.+)$', line)
            if match:
                path = match.group(1)
                if not path.startswith("/dev/null"):
                    current_file = path
                    if current_file not in files:
                        files[current_file] = []
            continue
        
        # Hunk header
        if line.startswith("@@"):
            # Save previous hunk
            if current_file and current_hunk_lines:
                _save_hunk(files, current_file, current_start_line, current_line, current_hunk_lines)
                current_hunk_lines = []
            
            # Parse hunk header: @@ -old_start,old_count +new_start,new_count @@
            match = re.search(r'\+(\d+)(?:,(\d+))?', line)
            if match:
                current_start_line = int(match.group(1))
                current_line = current_start_line
            continue
        
        # Skip diff metadata
        if line.startswith("---") or line.startswith("index ") or line.startswith("Binary"):
            continue
        
        # Actual diff content
        if current_file:
            if line.startswith("+") and not line.startswith("+++"):
                # Added line - include in review
                current_hunk_lines.append(line[1:])  # Remove + prefix
                current_line += 1
            elif line.startswith("-") and not line.startswith("---"):
                # Removed line - skip but don't increment line number
                pass
            elif line.startswith(" "):
                # Context line
                current_hunk_lines.append(line[1:])  # Remove space prefix
                current_line += 1
            elif line == "":
                # Empty line in diff
                pass
    
    # Save final hunk
    if current_file and current_hunk_lines:
        _save_hunk(files, current_file, current_start_line, current_line, current_hunk_lines)
    
    return files


def _save_hunk(
    files: dict[str, list[Hunk]],
    file_path: str,
    start_line: int,
    end_line: int,
    lines: list[str],
):
    """Save a hunk to the files dict."""
    if not lines:
        return
    
    content = "\n".join(lines)
    hunk: Hunk = {
        "start_line": start_line,
        "end_line": end_line,
        "content": content,
    }
    files[file_path].append(hunk)


def parse_patch_file(patch_path: str) -> dict[str, list[Hunk]]:
    """Parse a patch file."""
    with open(patch_path, "r") as f:
        return parse_diff(f.read())
