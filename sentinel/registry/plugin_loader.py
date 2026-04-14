"""Plugin rule loader. Imports a Python module and wraps it as a rule."""
from __future__ import annotations
import importlib.util
import traceback
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, List, Sequence

from sentinel.core import RepoContext, Severity, Verdict


REQUIRED_ATTRS = ("ID", "SEVERITY", "SOURCE", "check")


class PluginRuleLoadError(Exception):
    """Raised when a plugin module is missing required attributes."""


@dataclass
class PluginRule:
    id: str
    severity: Severity
    source: str
    scope: str
    _check: Callable[[RepoContext], Sequence[Verdict]]

    def check(self, ctx: RepoContext) -> Sequence[Verdict]:
        if self.scope == "portfolio" and ctx.is_repo_scan():
            return []
        if self.scope == "repo" and ctx.is_portfolio_scan():
            return []

        try:
            result = self._check(ctx)
        except Exception as e:
            return [
                Verdict(
                    rule_id=self.id,
                    severity=Severity.BLOCK,
                    repo=str(ctx.repo_root),
                    file=None,
                    line=None,
                    detail=f"{type(e).__name__}: {e}\n{traceback.format_exc()}",
                    fix_hint=f"rule {self.id} raised; fix the plugin or bypass the rule",
                    source=self.source,
                    timestamp=datetime.now(timezone.utc),
                )
            ]
        return list(result)


def load_plugin_rule(path: Path) -> PluginRule:
    spec = importlib.util.spec_from_file_location(f"sentinel_plugin_{path.stem}", path)
    if spec is None or spec.loader is None:
        raise PluginRuleLoadError(f"{path}: cannot import")
    module = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)
    except Exception as e:
        raise PluginRuleLoadError(f"{path}: import failed: {e}") from e

    for attr in REQUIRED_ATTRS:
        if not hasattr(module, attr):
            raise PluginRuleLoadError(
                f"{path}: missing required attribute: {attr}"
            )

    sev = module.SEVERITY
    if not isinstance(sev, Severity):
        raise PluginRuleLoadError(
            f"{path}: SEVERITY must be sentinel.core.Severity, got {type(sev).__name__}"
        )

    scope = getattr(module, "SCOPE", "repo")
    if scope not in ("repo", "portfolio"):
        raise PluginRuleLoadError(
            f"{path}: SCOPE must be 'repo' or 'portfolio', got {scope!r}"
        )

    return PluginRule(
        id=str(module.ID),
        severity=sev,
        source=str(module.SOURCE),
        scope=scope,
        _check=module.check,
    )
