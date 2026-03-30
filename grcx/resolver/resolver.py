# Copyright (c) 2026 Neil Lowden | GRCX | MIT License
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import anthropic
import yaml
from rich.console import Console

from grcx.sentinel.regulatory.rss import RegulatoryItem
from grcx.audit.log import AuditLog

console = Console()

_FRAMEWORKS_DIR = Path(__file__).parent.parent / "controls" / "frameworks"

RESOLVER_PROMPT = """You are GRCX, a compliance operations agent for a regulated financial services firm.

A new regulatory publication has been detected. Assess it and respond in the JSON format below.

Severity guide:
- critical: requires urgent action (new mandatory rule, enforcement action, deadline < 3 months)
- warning:  requires planned response (consultation closing, guidance update, upcoming change)
- info:     awareness only (speech, data release, minor clarification with no direct obligation)

Control framework: {framework_name}

{controls_summary}

Publication details:
Title:        {title}
Jurisdiction: {jurisdiction}
Published:    {published}
Summary:      {summary}
URL:          {url}

Write every field specifically through the lens of {framework_name}. Focus only on the aspects of this publication that are relevant to the controls and obligations in this framework. Do not produce a generic summary — if the publication has no bearing on this framework's controls, say so and set has_implications to false.

Respond with ONLY valid JSON — no markdown fences, no commentary:
{{
  "has_implications": true or false,
  "severity": "info" | "warning" | "critical",
  "affected_controls": ["{control_id_example}"],
  "summary": "One sentence — what this publication means for the firm specifically from a {framework_name} perspective",
  "recommended_action": "One concrete sentence — what the compliance team should do next in the context of {framework_name}",
  "rationale": "Two or three sentences explaining your reasoning in terms of {framework_name} controls and obligations"
}}"""


def _load_framework(framework_id: str) -> dict:
    """Load a framework YAML file by ID. Returns empty dict if not found."""
    path = _FRAMEWORKS_DIR / f"{framework_id}.yaml"
    if not path.exists():
        return {}
    with open(path) as f:
        return yaml.safe_load(f)


def _build_controls_summary(framework: dict) -> tuple[str, str]:
    """
    Return (controls_summary, example_control_id) for use in the prompt.
    Groups controls by category for readability.
    """
    if not framework:
        return "", "control-id"

    controls = framework.get("controls", [])
    by_category: dict[str, list] = {}
    for c in controls:
        cat = c.get("category", "General")
        by_category.setdefault(cat, []).append(c)

    lines = [f"Available controls ({framework.get('name', '')}):\n"]
    for cat, items in by_category.items():
        lines.append(f"  {cat}:")
        for c in items:
            lines.append(f"    {c['id']} — {c['description'].strip()}")
        lines.append("")

    example_id = controls[0]["id"] if controls else "control-id"
    return "\n".join(lines), example_id


@dataclass
class ResolverResult:
    has_implications: bool
    severity: str
    affected_controls: list[str]
    summary: str
    recommended_action: str
    rationale: str
    raw_item: RegulatoryItem


class Resolver:
    """
    LLM-powered reasoning layer. Takes a regulatory item and assesses
    its compliance implications against all configured control frameworks.
    Framework definitions are loaded from grcx/controls/frameworks/*.yaml.

    Supports multiple frameworks simultaneously — one LLM call and one audit
    entry is produced per framework per item.
    """

    def __init__(self, config: dict, audit: AuditLog):
        self.config = config
        self.audit = audit
        self.mode = config.get("resolver", {}).get("auto_remediate", "notify_only")
        self.llm = config.get("resolver", {}).get("llm", "claude-sonnet-4-6")
        self.client = anthropic.Anthropic(api_key=os.environ.get("ANTHROPIC_API_KEY"))

        # Support both `framework: id` (single) and `frameworks: [id, id]` (multi)
        controls_cfg = config.get("controls", {})
        raw = controls_cfg.get("frameworks") or controls_cfg.get("framework") or "iso27001"
        framework_ids = raw if isinstance(raw, list) else [raw]

        self._frameworks: list[dict] = []
        for fid in framework_ids:
            fw = _load_framework(fid)
            if fw:
                self._frameworks.append(fw)
            else:
                console.print(
                    f"[yellow]Framework '{fid}' not found in {_FRAMEWORKS_DIR} "
                    f"— skipping[/yellow]"
                )

    def analyse(self, item: RegulatoryItem) -> list[ResolverResult]:
        """
        Analyse a regulatory item against all configured frameworks.
        Returns one ResolverResult per framework.
        """
        console.print(f"[dim]Analysing: {item.title[:60]}...[/dim]")
        results = []
        for framework in self._frameworks:
            result = self._analyse_one(item, framework)
            if result is not None:
                results.append(result)
        return results

    def _analyse_one(
        self, item: RegulatoryItem, framework: dict
    ) -> Optional[ResolverResult]:
        """Run a single LLM analysis pass for one framework."""
        framework_id = framework.get("id", "unknown")
        framework_name = framework.get("name", framework_id)
        controls_summary, example_id = _build_controls_summary(framework)

        prompt = RESOLVER_PROMPT.format(
            framework_name=framework_name,
            controls_summary=controls_summary,
            control_id_example=example_id,
            title=item.title,
            jurisdiction=item.jurisdiction,
            published=item.published or "Unknown",
            summary=item.summary or "No summary available",
            url=item.url,
        )

        try:
            message = self.client.messages.create(
                model=self.llm,
                max_tokens=1024,
                messages=[{"role": "user", "content": prompt}],
            )

            raw = message.content[0].text.strip()
            if raw.startswith("```"):
                raw = raw.split("```")[1]
                if raw.startswith("json"):
                    raw = raw[4:]
            raw = raw.strip()

            data = json.loads(raw)

            result = ResolverResult(
                has_implications=data.get("has_implications", False),
                severity=data.get("severity", "info"),
                affected_controls=data.get("affected_controls", []),
                summary=data.get("summary", ""),
                recommended_action=data.get("recommended_action", ""),
                rationale=data.get("rationale", ""),
                raw_item=item,
            )

            if result.has_implications:
                self.audit.write(
                    event_type="resolver.assessment",
                    summary=result.summary,
                    severity=result.severity,
                    jurisdiction=item.jurisdiction,
                    source=item.url,
                    detail={
                        "framework": framework_id,
                        "affected_controls": result.affected_controls,
                        "recommended_action": result.recommended_action,
                        "rationale": result.rationale,
                        "publication_title": item.title,
                        "fingerprint": item.fingerprint,
                    },
                )

                colour = {"info": "green", "warning": "yellow", "critical": "red"}.get(
                    result.severity, "white"
                )
                console.print(
                    f"  [{colour}][{framework_id}] ⚠ {result.severity.upper()}[/{colour}] "
                    f"{result.summary}"
                )
                if result.affected_controls:
                    console.print(
                        f"  [cyan]Controls affected \\[{framework_id}]:[/cyan] "
                        f"{', '.join(result.affected_controls)}"
                    )
                console.print(f"  [dim]→ {result.recommended_action}[/dim]")
            else:
                console.print(
                    f"  [dim]✓ No compliance implications \\[{framework_id}][/dim]"
                )

            return result

        except Exception as e:
            console.print(
                f"[red]Resolver error [{framework_id}] for '{item.title[:40]}': {e}[/red]"
            )
            self.audit.write(
                event_type="resolver.error",
                summary=f"Resolver failed for: {item.title[:60]}",
                severity="warning",
                jurisdiction=item.jurisdiction,
                detail={
                    "framework": framework_id,
                    "error": str(e),
                    "fingerprint": item.fingerprint,
                },
            )
            return None
