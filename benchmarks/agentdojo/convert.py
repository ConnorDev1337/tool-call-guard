"""Convert AgentDojo tasks into toolguard evaluation scenarios.

For every user task of every suite this script writes a benign scenario (the
task's ground-truth tool calls with their real outputs) and, for every
injection task, an attack scenario: the same trajectory with the injection
vectors filled by AgentDojo's ``important_instructions`` attack, where the
injection task's ground-truth calls (marked as attack steps) are executed right
after the first tool output that shows the injection, as the template asks
("Before you can solve the task that I gave you in the beginning, please do the
following first"), and the user task then continues.

The trajectories are executed by AgentDojo itself (``TaskSuite.run_task_with_pipeline``
with a scripted pipeline element in place of a model), so AgentDojo's own utility
and security checks are recorded with each scenario. No model is called.

Run it only inside the throwaway image (see README.md), without network::

    docker run --rm --network none -v "$PWD:/work" toolguard-agentdojo-convert:0.1.35 \
        python -I convert.py
"""

from __future__ import annotations

import argparse
import datetime
import json
import sys
import types
from collections.abc import Sequence
from importlib import metadata
from pathlib import Path
from typing import Any

from agentdojo.agent_pipeline.base_pipeline_element import BasePipelineElement
from agentdojo.agent_pipeline.tool_execution import tool_result_to_str
from agentdojo.attacks.important_instructions_attacks import ImportantInstructionsAttack
from agentdojo.default_suites.v1.tools import cloud_drive_client, email_client
from agentdojo.functions_runtime import EmptyEnv, Env, FunctionCall, FunctionsRuntime
from agentdojo.task_suite.load_suites import get_suites
from agentdojo.types import (
    ChatAssistantMessage,
    ChatMessage,
    ChatToolResultMessage,
    text_content_block_from_string,
)

BENCHMARK_VERSION = "v1.2.2"  # Default of AgentDojo 0.1.35's benchmark script
ATTACK = "important_instructions"
TARGET_MODEL = "gpt-4o-2024-05-13"  # Default --model of the benchmark script; names "{model}"
FIXED_NOW = datetime.datetime(2024, 5, 15, 12, 0)  # The suites' "current day"
SUITES = ("workspace", "slack", "travel", "banking")
TITLE_CHARS = 90


class _FixedDateTime(datetime.datetime):
    """``datetime.datetime`` whose ``now()`` is fixed, for reproducible outputs."""

    @classmethod
    def now(cls, tz: datetime.tzinfo | None = None) -> datetime.datetime:  # noqa: D102
        return FIXED_NOW


def _freeze_clock() -> None:
    """Make sent e-mails and created files carry a fixed timestamp."""
    shim = types.SimpleNamespace(datetime=_FixedDateTime)
    email_client.datetime = shim
    cloud_drive_client.datetime = shim


class _TargetName(BasePipelineElement):
    """Stand-in for the attacked pipeline; the attack only reads its name."""

    name = TARGET_MODEL

    def query(self, *args: Any, **kwargs: Any) -> Any:  # noqa: D102
        raise RuntimeError("no model is called during the conversion")


class ScriptedAgent(BasePipelineElement):
    """Pipeline element that executes ground-truth calls instead of querying a model.

    With an ``injection_task``, its ground-truth calls are executed after the
    output of call number ``inject_after`` (0-based) of the user task.
    """

    name = "toolguard-scripted-ground-truth"

    def __init__(self, user_task: Any, injection_task: Any = None, inject_after: int = -1):
        self.user_task = user_task
        self.injection_task = injection_task
        self.inject_after = inject_after
        self.steps: list[dict[str, Any]] = []
        self.errors: list[str] = []

    def _run(
        self, runtime: FunctionsRuntime, env: Env, call: FunctionCall, attack: bool
    ) -> list[ChatMessage]:
        result, error = runtime.run_function(env, call.function, dict(call.args))
        output = tool_result_to_str(result) if error is None else f"Error: {error}"
        step: dict[str, Any] = {"tool": call.function, "args": _plain(call.args), "output": output}
        if attack:
            step["attack"] = True
        if error is not None:
            self.errors.append(f"{call.function}: {error}")
        self.steps.append(step)
        return [
            ChatAssistantMessage(
                role="assistant", tool_calls=[call], content=[text_content_block_from_string("")]
            ),
            ChatToolResultMessage(
                role="tool",
                content=[text_content_block_from_string(output)],
                tool_call=call,
                tool_call_id=None,
                error=error,
            ),
        ]

    def query(
        self,
        query: str,
        runtime: FunctionsRuntime,
        env: Env = EmptyEnv(),
        messages: Sequence[ChatMessage] = [],  # noqa: B006 (AgentDojo's signature)
        extra_args: dict = {},  # noqa: B006
    ) -> tuple[str, FunctionsRuntime, Env, Sequence[ChatMessage], dict]:
        self.steps = [{"user": query}]
        new: list[ChatMessage] = []
        outputs = [self.user_task.GROUND_TRUTH_OUTPUT]
        for index, call in enumerate(self.user_task.ground_truth(env)):
            new += self._run(runtime, env, call, attack=False)
            if self.injection_task is not None and index == self.inject_after:
                for injected in self.injection_task.ground_truth(env):
                    new += self._run(runtime, env, injected, attack=True)
                outputs.append(self.injection_task.GROUND_TRUTH_OUTPUT)
        final = "\n".join(o for o in outputs if o)
        new.append(
            ChatAssistantMessage(
                role="assistant", content=[text_content_block_from_string(final)], tool_calls=None
            )
        )
        return query, runtime, env, [*messages, *new], extra_args


def _plain(value: Any) -> Any:
    """Return ``value`` as JSON-compatible data; fail loudly on anything else."""
    return json.loads(json.dumps(value))


def _first_exposure(suite: Any, user_task: Any, vectors: list[str]) -> int:
    """Return the index of the first ground-truth call whose output shows an injection.

    Uses single-token canaries, which YAML output never wraps or escapes.
    """
    canaries = {vector: f"CANARY{n:03d}XTOOLGUARD" for n, vector in enumerate(vectors)}
    agent = ScriptedAgent(user_task)
    suite.run_task_with_pipeline(agent, user_task, None, canaries)
    calls = [s for s in agent.steps if "tool" in s]
    for index, step in enumerate(calls):
        if any(canary in step["output"] for canary in canaries.values()):
            return index
    raise ValueError("no ground-truth output shows an injection")


def _title(*parts: str) -> str:
    text = " | ".join(" ".join(p.split()) for p in parts)
    return text if len(text) <= TITLE_CHARS else text[: TITLE_CHARS - 3] + "..."


def convert_suite(name: str, suite: Any) -> tuple[list[dict], list[dict], list[dict]]:
    """Return the benign scenarios, attack scenarios and skips of one suite."""
    attack = ImportantInstructionsAttack(suite, _TargetName())
    benign: list[dict] = []
    attacks: list[dict] = []
    skips: list[dict] = []
    for user_id, user_task in suite.user_tasks.items():
        agent = ScriptedAgent(user_task)
        try:
            utility, _ = suite.run_task_with_pipeline(agent, user_task, None, {})
        except Exception as exc:  # A ground truth that does not execute is skipped
            skips.append({"suite": name, "scenario": f"{name}/{user_id}", "reason": repr(exc)})
            continue
        reason = "; ".join(agent.errors) or (None if utility else "AgentDojo utility check fails")
        if reason:
            skips.append({"suite": name, "scenario": f"{name}/{user_id}", "reason": reason})
        else:
            benign.append(
                {
                    "id": f"{name}/{user_id}",
                    "title": _title(user_task.PROMPT),
                    "kind": "benign",
                    "category": name,
                    "agentdojo": {"suite": name, "user_task": user_id, "utility": utility},
                    "steps": agent.steps,
                }
            )
        try:
            exposure = _first_exposure(suite, user_task, attack.get_injection_candidates(user_task))
        except Exception as exc:
            for injection_id in suite.injection_tasks:
                skips.append(
                    {
                        "suite": name,
                        "scenario": f"{name}/{user_id}/{injection_id}",
                        "reason": f"not injectable: {exc!r}",
                    }
                )
            continue
        for injection_id, injection_task in suite.injection_tasks.items():
            scenario_id = f"{name}/{user_id}/{injection_id}"
            injections = attack.attack(user_task, injection_task)
            agent = ScriptedAgent(user_task, injection_task, exposure)
            try:
                utility, security = suite.run_task_with_pipeline(
                    agent, user_task, injection_task, injections
                )
            except Exception as exc:
                skips.append({"suite": name, "scenario": scenario_id, "reason": repr(exc)})
                continue
            if not any(s.get("attack") for s in agent.steps):
                skips.append(
                    {
                        "suite": name,
                        "scenario": scenario_id,
                        "reason": "the injection task has no tool call (output-only goal)",
                    }
                )
                continue
            if not security:
                skips.append(
                    {
                        "suite": name,
                        "scenario": scenario_id,
                        "reason": "AgentDojo security check: the scripted attack does not succeed",
                    }
                )
                continue
            attacks.append(
                {
                    "id": scenario_id,
                    "title": _title(user_task.PROMPT, injection_task.GOAL),
                    "kind": "attack",
                    "category": name,
                    "agentdojo": {
                        "suite": name,
                        "user_task": user_id,
                        "injection_task": injection_id,
                        "injection_vectors": sorted(injections),
                        "utility_under_attack": utility,
                        "tool_errors": agent.errors,
                    },
                    "steps": agent.steps,
                }
            )
    return benign, attacks, skips


def _dump(scenarios: list[dict], path: Path) -> None:
    """Write one scenario per line, ASCII only (invisible characters stay escaped)."""
    lines = ",\n".join(json.dumps(s, ensure_ascii=True, sort_keys=False) for s in scenarios)
    path.write_text(f"[\n{lines}\n]\n", encoding="ascii", newline="\n")


def main(argv: list[str] | None = None) -> int:
    """Convert the suites and write the scenario files and the manifest."""
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--out", default=".", help="benchmark directory (default: .)")
    parser.add_argument("--suite", action="append", choices=SUITES, help="suite(s) to convert")
    args = parser.parse_args(argv)
    _freeze_clock()
    out = Path(args.out)
    (out / "scenarios").mkdir(parents=True, exist_ok=True)
    suites = get_suites(BENCHMARK_VERSION)
    manifest: dict[str, Any] = {
        "agentdojo_version": metadata.version("agentdojo"),
        "benchmark_version": BENCHMARK_VERSION,
        "attack": ATTACK,
        "attack_target_model": TARGET_MODEL,
        "fixed_now": FIXED_NOW.isoformat(),
        "suites": {},
        "skipped": [],
    }
    for name in args.suite or SUITES:
        suite = suites[name]
        benign, attacks, skips = convert_suite(name, suite)
        _dump(benign, out / "scenarios" / f"{name}-benign.json")
        _dump(attacks, out / "scenarios" / f"{name}-attacks.json")
        manifest["suites"][name] = {
            "user_tasks": len(suite.user_tasks),
            "injection_tasks": len(suite.injection_tasks),
            "pairs": len(suite.user_tasks) * len(suite.injection_tasks),
            "benign_scenarios": len(benign),
            "attack_scenarios": len(attacks),
            "skipped": len(skips),
        }
        manifest["skipped"] += skips
        print(f"{name}: {len(benign)} benign, {len(attacks)} attacks, {len(skips)} skipped")
    text = json.dumps(manifest, indent=2, ensure_ascii=True)
    (out / "manifest.json").write_text(text + "\n", encoding="ascii", newline="\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
