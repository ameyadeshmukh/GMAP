"""
Utility functions for incremental report generation across phases.
Each phase node can call these functions to append their section to the report.
"""
from datetime import datetime
import re


def append_to_report(state, new_section: str) -> str:
    """
    Append a new section to the existing report.
    """
    existing_report = state.get("report", "")
    if existing_report:
        return existing_report + "\n" + new_section
    return new_section


def update_or_append_section(state, section_header: str, new_section_content: str) -> str:
    """
    Update an existing section if it exists, or append a new one.
    If the section appears multiple times (retries), it will be numbered.

    Args:
        state: The current state
        section_header: The section header to look for (e.g., "## Discovery Phase Results")
        new_section_content: The full section content including header

    Returns:
        Updated report string
    """
    existing_report = state.get("report", "")

    if not existing_report:
        return new_section_content

    # Check if this section already exists
    # Escape special regex characters in the header
    escaped_header = re.escape(section_header)

    # Pattern to match the section with optional attempt number
    # Matches: "## Discovery Phase Results" or "## Discovery Phase Results (Attempt 2)"
    pattern = rf"({escaped_header}(?:\s*\(Attempt \d+\))?)"

    matches = list(re.finditer(pattern, existing_report))

    if not matches:
        # Section doesn't exist yet, append it
        return existing_report + "\n" + new_section_content

    # Section exists, add attempt number
    attempt_number = len(matches) + 1

    # Add attempt number to the new section header
    numbered_section = new_section_content.replace(
        section_header,
        f"{section_header} (Attempt {attempt_number})",
        1  # Only replace first occurrence
    )

    return existing_report + "\n" + numbered_section


def generate_report_header(state) -> str:
    """
    Generate the report header with metadata (called at start of first phase).
    """
    sections = []
    sections.append("# Penetration Testing Report")
    sections.append(f"\n**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    sections.append(f"**Target:** {state.get('target_host', 'N/A')}\n")

    # Target Information
    sections.append("## Target Information")
    sections.append(f"**Host:** {state.get('target_host', 'N/A')}")

    scope = state.get("scope", [])
    sections.append(f"**Scope:** {', '.join(scope) if scope else 'None specified'}")

    exclusions = state.get("exclusions", [])
    sections.append(f"**Exclusions:** {', '.join(exclusions) if exclusions else 'None specified'}")

    engagement_rules = state.get("engagement_rules", "")
    sections.append(f"**Engagement Rules:** {engagement_rules if engagement_rules else 'None specified'}\n")

    return "\n".join(sections)
