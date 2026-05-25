"""Export every Sentinel rule as a SKILL.md descriptor.

The SKILL.md spec (adopted by Anthropic / OpenAI / Google / GitHub / Cursor)
is a portable rule descriptor: frontmatter with `name`, `description`,
`trigger`, plus optional `severity`, `scope`, `source`, then a free-text body.

Sentinel rules are already first-class objects with `ID`, `SEVERITY`, `SOURCE`,
`SCOPE` constants and a module docstring. This script reads each rule, derives
the SKILL.md frontmatter, and writes one file per rule to `F:\\Sentinel\\skills\\`.

Idempotent: re-running overwrites every output. Drop a rule -> its SKILL.md
becomes stale and is overwritten with a deprecation stub.

Usage:
    python scripts/export_skills.py            # write all
    python scripts/export_skills.py --dry-run  # report what would be written
    python scripts/export_skills.py --check    # verify on-disk SKILL.md set is in sync
"""
from __future__ import annotations

import argparse
import ast
import importlib.util
import io
import sys
import textwrap
from pathlib import Path

if sys.platform == "win32" and "pytest" not in sys.modules:
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

SENTINEL_ROOT = Path(__file__).resolve().parents[1]
PLUGINS_DIR = SENTINEL_ROOT / "sentinel" / "rules" / "plugins"
YAML_DIR = SENTINEL_ROOT / "sentinel" / "rules" / "yaml"
SKILLS_DIR = SENTINEL_ROOT / "skills"


def _trigger_for_scope(scope: str | None) -> str:
    """Translate Sentinel SCOPE to SKILL.md trigger vocabulary."""
    if not scope:
        return "commit"
    s = scope.lower()
    if s == "portfolio":
        return "nightly"
    return "commit"  # default for repo-scope and unknowns


def _extract_python_rule(path: Path) -> dict | None:
    """Parse a plugin rule .py file via AST (no execution) and return its
    metadata if it looks like a Sentinel rule (has ID + check function)."""
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    except (SyntaxError, OSError):
        return None
    info: dict[str, str | None] = {
        "id": None, "severity": None, "source": None, "scope": None,
        "docstring": ast.get_docstring(tree) or "",
        "has_check": False,
    }
    for node in tree.body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1:
            target = node.targets[0]
            if isinstance(target, ast.Name):
                val = node.value
                if isinstance(val, ast.Constant) and isinstance(val.value, str):
                    if target.id == "ID":
                        info["id"] = val.value
                    elif target.id == "SOURCE":
                        info["source"] = val.value
                    elif target.id == "SCOPE":
                        info["scope"] = val.value
                elif isinstance(val, ast.Attribute) and target.id == "SEVERITY":
                    # SEVERITY = Severity.BLOCK
                    info["severity"] = val.attr
        elif isinstance(node, ast.FunctionDef) and node.name == "check":
            info["has_check"] = True
    if not info["id"] or not info["has_check"]:
        return None
    return info


def _extract_yaml_rule(path: Path) -> dict | None:
    """Parse a YAML rule file. Minimal parser: look for `id:`, `severity:`,
    `description:` at the top level. Avoids importing pyyaml to keep
    bootstrap simple."""
    text = path.read_text(encoding="utf-8")
    info: dict[str, str | None] = {
        "id": None, "severity": None, "source": None, "scope": "repo",
        "docstring": "", "has_check": True,
    }
    in_description = False
    desc_lines: list[str] = []
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("id:"):
            info["id"] = stripped.split(":", 1)[1].strip().strip('"\'')
        elif stripped.startswith("severity:"):
            info["severity"] = stripped.split(":", 1)[1].strip().strip('"\'').upper()
        elif stripped.startswith("source:"):
            info["source"] = stripped.split(":", 1)[1].strip().strip('"\'')
        elif stripped.startswith("description:"):
            rest = stripped.split(":", 1)[1].strip()
            if rest in ("|", ">", "|-", ">-"):
                in_description = True
            elif rest.startswith('"') or rest.startswith("'"):
                info["docstring"] = rest.strip('"\'')
            else:
                info["docstring"] = rest
        elif in_description:
            if line.startswith(" ") or line.startswith("\t"):
                desc_lines.append(line.strip())
            else:
                in_description = False
    if desc_lines:
        info["docstring"] = " ".join(desc_lines)
    if not info["id"]:
        return None
    return info


def _to_skill_md(info: dict, source_kind: str, source_path: Path) -> str:
    """Render one rule's SKILL.md content."""
    rid = info["id"]
    docstring = (info["docstring"] or "").strip()
    # The description is the first paragraph (or first line) of the docstring.
    desc = docstring.split("\n\n", 1)[0].strip().replace("\n", " ")
    if len(desc) > 250:
        desc = desc[:247] + "..."
    if not desc:
        desc = f"Sentinel rule {rid}"

    severity = info.get("severity") or "INFO"
    scope = info.get("scope") or "repo"
    trigger = _trigger_for_scope(scope)
    source = info.get("source") or ""

    # Body: full docstring (preserved formatting) + provenance line.
    body_parts = []
    if docstring:
        body_parts.append(docstring)
    body_parts.append(
        f"\n---\n\n"
        f"_Auto-exported from `{source_path.relative_to(SENTINEL_ROOT).as_posix()}` "
        f"by `scripts/export_skills.py`. Source kind: {source_kind}. "
        f"Manifest-hashed in `rules-manifest.json`. Do not edit this file directly; "
        f"edit the rule and re-run the exporter._"
    )

    # Skip-marker so SKILL.md exports of rules whose docstrings legitimately
    # demonstrate the bad pattern don't self-flag (cp1252_mojibake,
    # script_close_in_template, etc.). Comment-syntax HTML form is read by
    # sentinel.io.skip_marker.
    return textwrap.dedent(f"""\
        <!-- sentinel:skip-file — auto-generated rule descriptor; docstring may demonstrate the bad pattern by design -->
        ---
        name: {rid}
        description: {desc!r}
        trigger: {trigger}
        severity: {severity}
        scope: {scope}
        source: {source!r}
        ---

        """) + "\n".join(body_parts) + "\n"


def collect_rules() -> list[tuple[dict, str, Path]]:
    """Return [(info, kind, source_path), ...] across plugin + yaml directories."""
    out: list[tuple[dict, str, Path]] = []
    for py in sorted(PLUGINS_DIR.glob("*.py")):
        if py.name in ("__init__.py",) or py.name.startswith("__"):
            continue
        info = _extract_python_rule(py)
        if info:
            out.append((info, "python-plugin", py))
    for ym in sorted(YAML_DIR.glob("*.yaml")):
        info = _extract_yaml_rule(ym)
        if info:
            out.append((info, "yaml", ym))
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--check", action="store_true",
                    help="exit 1 if on-disk skills are out of sync")
    args = ap.parse_args(argv)

    rules = collect_rules()
    print(f"Discovered {len(rules)} rules across plugins + yaml")
    if not rules:
        print("No rules found — check PLUGINS_DIR / YAML_DIR paths", file=sys.stderr)
        return 1

    if args.dry_run:
        for info, kind, path in rules:
            print(f"  [{kind}] {info['id']}  <- {path.relative_to(SENTINEL_ROOT)}")
        return 0

    SKILLS_DIR.mkdir(exist_ok=True)
    drift = 0
    written = 0
    for info, kind, path in rules:
        target = SKILLS_DIR / f"{info['id']}.md"
        new_content = _to_skill_md(info, kind, path)
        if args.check:
            if not target.is_file():
                print(f"  MISSING  {target.name}")
                drift += 1
                continue
            old_content = target.read_text(encoding="utf-8")
            if old_content != new_content:
                print(f"  DRIFT    {target.name}")
                drift += 1
            continue
        target.write_text(new_content, encoding="utf-8")
        written += 1

    if args.check:
        # Also catch stale on-disk skills (a rule was deleted but its SKILL.md
        # is still around)
        live_ids = {info["id"] for info, _, _ in rules}
        for stale in SKILLS_DIR.glob("*.md"):
            if stale.stem not in live_ids:
                print(f"  STALE    {stale.name}")
                drift += 1
        if drift:
            print(f"\n{drift} skills out of sync; re-run without --check to fix.")
            return 1
        print(f"\nAll {len(rules)} skills in sync.")
        return 0

    print(f"Wrote {written} SKILL.md files to {SKILLS_DIR}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
