"""Sources, scenarios and docs must not contain invisible/bidi characters.

Test inputs spell them as escapes (\\u200b) so reviewers see what is tested.
"""

import tomllib
import unicodedata

import pytest

from conftest import ROOT
from toolguard import Policy
from toolguard.approvals import ApprovalConfig

SUFFIXES = {".py", ".json", ".toml", ".yml", ".yaml", ".md"}
FILES = [
    *sorted(
        p
        for folder in ("src", "tests", "examples", ".github")
        for p in (ROOT / folder).rglob("*")
        if p.is_file() and p.suffix in SUFFIXES
    ),
    *(
        p
        for p in (ROOT / "README.md", ROOT / "pyproject.toml", ROOT / ".gitlab-ci.yml")
        if p.exists()
    ),
]


def _hidden(ch: str) -> bool:
    return ch not in "\n\t\r" and unicodedata.category(ch) in {"Cc", "Cf", "Co", "Zl", "Zp"}


@pytest.mark.parametrize("path", FILES, ids=lambda p: p.relative_to(ROOT).as_posix())
def test_no_hidden_characters(path):
    text = path.read_text(encoding="utf-8")
    hidden = [
        (n, f"U+{ord(ch):04X}")
        for n, line in enumerate(text.splitlines(), 1)
        for ch in line
        if _hidden(ch)
    ]
    assert hidden == []


def test_example_policy_is_valid():
    path = ROOT / "examples" / "team-policy.toml"
    tomllib.loads(path.read_text(encoding="utf-8"))
    policy = Policy.load(str(path))
    assert policy.sink_for("mcp__deployer__rollout", {}).category == "deploy"
    assert policy.taint_ttl == 28800


def test_example_approvals_config_is_valid():
    config = ApprovalConfig.load(ROOT / "examples" / "approvals.toml")
    assert [n.name for n in config.notifiers] == ["telegram", "webhook", "desktop", "file"]
    assert config.settings.length == 12 and config.settings.max_attempts == 5
