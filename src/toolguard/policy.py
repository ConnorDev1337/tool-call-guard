"""Policy: sources of untrusted or private data, sensitive sinks and the actions to take.

Policies are TOML files. A user policy usually ``extends`` a bundled preset: its
list entries take precedence over the preset's and tables are merged key by key.
"""

from __future__ import annotations

import dataclasses
import fnmatch
import hashlib
import tomllib
from collections.abc import Iterator
from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path
from typing import Any

from .model import Action, canonical_json

PRESETS = ("balanced", "strict")
MODES = ("enforce", "monitor")
_TOP_KEYS = {
    "version",
    "extends",
    "mode",
    "taint_ttl",
    "endorse_user_input",
    "max_observation_chars",
    "source",
    "sink",
    "actions",
    "protect",
}
_RULE_FIELDS = ("tainted", "untrusted_flow", "directed_flow", "private_flow", "trifecta")


class PolicyError(ValueError):
    """The policy is invalid or cannot be read."""


def _strings(value: Any, where: str) -> tuple[str, ...]:
    if isinstance(value, str):
        return (value,)
    if isinstance(value, list) and all(isinstance(v, str) for v in value):
        return tuple(value)
    raise PolicyError(f"{where}: expected a string or a list of strings")


def _patterns(value: Any, where: str) -> dict[str, tuple[str, ...]]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise PolicyError(f"{where}: expected a table of argument -> patterns")
    return {str(k): _strings(v, f"{where}.{k}") for k, v in value.items()}


def iter_strings(value: Any, path: str = "") -> Iterator[tuple[str, str]]:
    """Yield ``(dotted_path, text)`` for every string or number leaf of ``value``."""
    if isinstance(value, str):
        yield path or "$", value
    elif isinstance(value, bool) or value is None:
        return
    elif isinstance(value, int | float):
        yield path or "$", str(value)
    elif isinstance(value, dict):
        for key, item in value.items():
            yield from iter_strings(item, f"{path}.{key}" if path else str(key))
    elif isinstance(value, list | tuple):
        for index, item in enumerate(value):
            yield from iter_strings(item, f"{path}[{index}]" if path else f"[{index}]")


def select_args(args: Any, names: tuple[str, ...]) -> list[tuple[str, str]]:
    """Return the string leaves whose top-level key or full path is in ``names``.

    Matching is case-insensitive; ``"*"`` selects every leaf.
    """
    leaves = list(iter_strings(args))
    if "*" in names:
        return leaves
    wanted = {n.lower() for n in names}
    selected = []
    for path, value in leaves:
        head = path.split(".")[0].split("[")[0].lower()
        if head in wanted or path.lower() in wanted:
            selected.append((path, value))
    return selected


def _glob(value: str, patterns: tuple[str, ...]) -> bool:
    """Match case-insensitively, treating Windows path separators as ``/``."""
    norm = value.replace("\\", "/").lower()
    return any(fnmatch.fnmatchcase(norm, p.replace("\\", "/").lower()) for p in patterns)


def _tool_matches(tool: str, patterns: tuple[str, ...]) -> bool:
    return any(fnmatch.fnmatchcase(tool, p) for p in patterns)


def _when_matches(args: Any, when: dict[str, tuple[str, ...]]) -> bool:
    """Return whether every condition matches at least one selected argument value."""
    for name, patterns in when.items():
        values = [v for _, v in select_args(args, (name,))]
        if not any(_glob(v, patterns) for v in values):
            return False
    return True


@dataclass(frozen=True)
class SourceRule:
    """Tools whose results bring untrusted and/or private data into the context."""

    tools: tuple[str, ...]
    kind: str = "external"
    untrusted: bool = False
    private: bool = False
    when: dict[str, tuple[str, ...]] = field(default_factory=dict)

    def matches(self, tool: str, args: Any) -> bool:
        return _tool_matches(tool, self.tools) and _when_matches(args, self.when)


@dataclass(frozen=True)
class SinkRule:
    """A sensitive action; ``critical`` names the arguments checked for untrusted flows."""

    tools: tuple[str, ...]
    category: str
    critical: tuple[str, ...] = ("*",)
    egress: bool = False
    when: dict[str, tuple[str, ...]] = field(default_factory=dict)

    def matches(self, tool: str, args: Any) -> bool:
        return _tool_matches(tool, self.tools) and _when_matches(args, self.when)


@dataclass(frozen=True)
class ProtectRule:
    """Argument patterns that must never reach the given tools (self-protection)."""

    tools: tuple[str, ...]
    args: dict[str, tuple[str, ...]]
    message: str
    action: Action = Action.BLOCK

    def hits(self, tool: str, args: Any) -> list[str]:
        """Return the paths of the arguments that match a protected pattern."""
        if not _tool_matches(tool, self.tools):
            return []
        found = []
        for name, patterns in self.args.items():
            for path, value in select_args(args, (name,)):
                if _glob(value, patterns):
                    found.append(path)
        return found


@dataclass(frozen=True)
class ActionTable:
    """Action demanded by each rule for one sink category.

    ``directed_flow`` is ``untrusted_flow`` restricted to sources the user named in
    the prompt; when it is ``None`` it falls back to ``untrusted_flow``, so a policy
    that does not set it behaves exactly as before.
    """

    tainted: Action = Action.CONFIRM
    untrusted_flow: Action = Action.BLOCK
    private_flow: Action = Action.BLOCK
    trifecta: Action = Action.BLOCK
    directed_flow: Action | None = None

    @property
    def directed(self) -> Action:
        """Return the action for a directed untrusted flow (defaults to ``untrusted_flow``)."""
        return self.directed_flow if self.directed_flow is not None else self.untrusted_flow


@dataclass(frozen=True)
class SourceMatch:
    """Combined classification of a tool result by its matching source rules."""

    kind: str
    untrusted: bool
    private: bool


@dataclass
class Policy:
    """A validated policy; build it with :meth:`load`, :meth:`preset` or :meth:`from_dict`."""

    name: str = "custom"
    mode: str = "enforce"
    taint_ttl: float = 0.0
    endorse_user_input: bool = True
    max_observation_chars: int = 262_144
    sources: tuple[SourceRule, ...] = ()
    sinks: tuple[SinkRule, ...] = ()
    actions: dict[str, ActionTable] = field(default_factory=dict)
    protect: tuple[ProtectRule, ...] = ()
    digest: str = ""

    # ------------------------------------------------------------------ loading

    @classmethod
    def from_dict(cls, data: dict[str, Any], name: str = "custom") -> Policy:
        """Validate ``data``, resolving ``extends``; raise :class:`PolicyError` if invalid."""
        raw = _resolve(data)
        unknown = set(raw) - _TOP_KEYS
        if unknown:
            raise PolicyError(f"unknown top-level key(s): {', '.join(sorted(unknown))}")
        mode = raw.get("mode", "enforce")
        if mode not in MODES:
            raise PolicyError(f"mode must be one of {', '.join(MODES)}")
        sources = tuple(_source(i, s) for i, s in enumerate(raw.get("source", [])))
        sinks = tuple(_sink(i, s) for i, s in enumerate(raw.get("sink", [])))
        actions = {str(k): _table(k, v) for k, v in raw.get("actions", {}).items()}
        protect = tuple(_protect(i, p) for i, p in enumerate(raw.get("protect", [])))
        ttl = raw.get("taint_ttl", 0)
        if not isinstance(ttl, int | float) or ttl < 0:
            raise PolicyError("taint_ttl must be a non-negative number of seconds")
        max_chars = raw.get("max_observation_chars", 262_144)
        if not isinstance(max_chars, int) or max_chars < 1024:
            raise PolicyError("max_observation_chars must be an integer >= 1024")
        return cls(
            name=name,
            mode=mode,
            taint_ttl=float(ttl),
            endorse_user_input=bool(raw.get("endorse_user_input", True)),
            max_observation_chars=max_chars,
            sources=sources,
            sinks=sinks,
            actions=actions,
            protect=protect,
            digest=hashlib.sha256(canonical_json(raw).encode()).hexdigest(),
        )

    @classmethod
    def from_toml(cls, path: str | Path) -> Policy:
        """Load a TOML file; raise :class:`PolicyError` if it is unreadable or invalid."""
        file_path = Path(path)
        try:
            data = tomllib.loads(file_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
            raise PolicyError(f"cannot read policy {file_path}: {exc}") from exc
        return cls.from_dict(data, name=str(file_path))

    @classmethod
    def preset(cls, name: str) -> Policy:
        if name not in PRESETS:
            raise PolicyError(f"unknown preset {name!r} ({', '.join(PRESETS)})")
        return cls.from_dict(_preset_dict(name), name=name)

    @classmethod
    def load(cls, spec: str | Path | None) -> Policy:
        """Load a preset by name, a TOML file by path, or ``balanced`` for ``None``."""
        if spec is None:
            return cls.preset("balanced")
        if str(spec) in PRESETS:
            return cls.preset(str(spec))
        if not Path(spec).exists():
            raise PolicyError(
                f"unknown policy {str(spec)!r}: not a preset ({', '.join(PRESETS)}) "
                "nor an existing file"
            )
        return cls.from_toml(spec)

    def with_mode(self, mode: str) -> Policy:
        if mode not in MODES:
            raise PolicyError(f"mode must be one of {', '.join(MODES)}")
        return dataclasses.replace(self, mode=mode)

    # ------------------------------------------------------------------ queries

    def source_for(self, tool: str, args: Any) -> SourceMatch | None:
        """Return the union of all matching source rules (the most cautious combination)."""
        matched = [rule for rule in self.sources if rule.matches(tool, args)]
        if not matched:
            return None
        return SourceMatch(
            kind=matched[0].kind,
            untrusted=any(r.untrusted for r in matched),
            private=any(r.private for r in matched),
        )

    def sink_for(self, tool: str, args: Any) -> SinkRule | None:
        """Return the first matching sink rule; user rules precede the preset's."""
        return next((rule for rule in self.sinks if rule.matches(tool, args)), None)

    def actions_for(self, category: str) -> ActionTable:
        """Return the table for ``category``, else ``default``, else the built-in defaults."""
        return self.actions.get(category) or self.actions.get("default") or ActionTable()

    def protect_hits(self, tool: str, args: Any) -> list[tuple[ProtectRule, list[str]]]:
        return [(rule, hits) for rule in self.protect if (hits := rule.hits(tool, args))]


# ---------------------------------------------------------------------- parsing helpers


def _preset_dict(name: str) -> dict[str, Any]:
    text = resources.files("toolguard.presets").joinpath(f"{name}.toml").read_text("utf-8")
    return tomllib.loads(text)


def _resolve(data: dict[str, Any], chain: tuple[str, ...] = ()) -> dict[str, Any]:
    """Return ``data`` merged over the full chain of presets it ``extends``.

    A preset may itself extend another preset, so the chain is resolved
    recursively; ``chain`` holds the presets already visited to detect cycles.
    """
    if "extends" not in data:
        return data
    base_name = data["extends"]
    if base_name not in PRESETS:
        raise PolicyError(f"extends: unknown preset {base_name!r} ({', '.join(PRESETS)})")
    if base_name in chain:
        cycle = " -> ".join((*chain, base_name))
        raise PolicyError(f"extends: cycle between presets ({cycle})")
    base = _resolve(_preset_dict(base_name), (*chain, base_name))
    return _merge(base, data)


def _merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    """Merge ``override`` into ``base``: lists are prepended, tables merged recursively."""
    merged = {key: value for key, value in base.items() if key != "extends"}
    for key, value in override.items():
        if key == "extends":
            continue
        current = base.get(key)
        if isinstance(value, list) and isinstance(current, list):
            merged[key] = value + current
        elif isinstance(value, dict) and isinstance(current, dict):
            merged[key] = _merge(current, value)
        else:
            merged[key] = value
    return merged


def _check_keys(entry: Any, allowed: set[str], where: str) -> dict[str, Any]:
    if not isinstance(entry, dict):
        raise PolicyError(f"{where}: expected a table")
    unknown = set(entry) - allowed
    if unknown:
        raise PolicyError(f"{where}: unknown key(s) {', '.join(sorted(unknown))}")
    if "tools" not in entry:
        raise PolicyError(f"{where}: 'tools' is required")
    return entry


def _source(index: int, entry: Any) -> SourceRule:
    where = f"source[{index}]"
    entry = _check_keys(entry, {"tools", "kind", "untrusted", "private", "when"}, where)
    rule = SourceRule(
        tools=_strings(entry["tools"], f"{where}.tools"),
        kind=str(entry.get("kind", "external")),
        untrusted=bool(entry.get("untrusted", False)),
        private=bool(entry.get("private", False)),
        when=_patterns(entry.get("when"), f"{where}.when"),
    )
    if not (rule.untrusted or rule.private):
        raise PolicyError(f"{where}: a source must be untrusted, private or both")
    return rule


def _sink(index: int, entry: Any) -> SinkRule:
    where = f"sink[{index}]"
    entry = _check_keys(entry, {"tools", "category", "critical", "egress", "when"}, where)
    if "category" not in entry:
        raise PolicyError(f"{where}: 'category' is required")
    return SinkRule(
        tools=_strings(entry["tools"], f"{where}.tools"),
        category=str(entry["category"]),
        critical=_strings(entry.get("critical", ["*"]), f"{where}.critical"),
        egress=bool(entry.get("egress", False)),
        when=_patterns(entry.get("when"), f"{where}.when"),
    )


def _table(category: Any, entry: Any) -> ActionTable:
    where = f"actions.{category}"
    if not isinstance(entry, dict):
        raise PolicyError(f"{where}: expected a table")
    unknown = set(entry) - set(_RULE_FIELDS)
    if unknown:
        raise PolicyError(f"{where}: unknown key(s) {', '.join(sorted(unknown))}")
    try:
        return ActionTable(**{k: Action.parse(v) for k, v in entry.items()})
    except ValueError as exc:
        raise PolicyError(f"{where}: {exc}") from None


def _protect(index: int, entry: Any) -> ProtectRule:
    where = f"protect[{index}]"
    entry = _check_keys(entry, {"tools", "args", "message", "action"}, where)
    try:
        action = Action.parse(entry.get("action", "block"))
    except ValueError as exc:
        raise PolicyError(f"{where}: {exc}") from None
    return ProtectRule(
        tools=_strings(entry["tools"], f"{where}.tools"),
        args=_patterns(entry.get("args"), f"{where}.args"),
        message=str(entry.get("message", "protected resource")),
        action=action,
    )
