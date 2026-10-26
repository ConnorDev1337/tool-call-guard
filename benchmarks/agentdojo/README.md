# AgentDojo scenarios for `toolguard eval`

This directory turns [AgentDojo](https://github.com/ethz-spylab/agentdojo), a public prompt-injection benchmark for tool-using agents, into toolguard scenarios, so that toolguard is also measured on tasks and attacks that its authors did not write. It is a **held-out** evaluation: neither the presets nor [`toolset.toml`](toolset.toml) were adjusted after seeing the results below.

```sh
toolguard eval benchmarks/agentdojo/scenarios --toolset benchmarks/agentdojo/toolset.toml
```

Nothing here is part of the toolguard package, and toolguard does not depend on AgentDojo.

## Provenance

| | |
|---|---|
| AgentDojo | 0.1.35 from PyPI (released 2025-10-27), tag `v0.1.35` = commit `a75aba7631d3ca5fb7ab938965c97ead2f9ff84b` |
| Wheel | `agentdojo-0.1.35-py3-none-any.whl`, sha256 `364bea4219716b716bf639f504d195943f7f6a5535d312ca41d7098704a2affd` |
| Benchmark version | `v1.2.2` (the default of AgentDojo's benchmark script) |
| Suites | workspace, slack, travel, banking |
| Attack | `important_instructions` (user name "Emma Johnson", model name "GPT-4", as AgentDojo derives it for its default model `gpt-4o-2024-05-13`) |
| Image | `python:3.12-slim@sha256:a6e34c598f2467ed0e9a8d349809fcd8b5c603269512df273a0bb1784edc11b1`, dependencies from the hash-locked [`requirements.lock`](requirements.lock) (resolved with `--exclude-newer 2025-11-01`) |
| Determinism | `datetime.now()` in AgentDojo's e-mail and drive tools is fixed to 2024-05-15 12:00 and `PYTHONHASHSEED=0`; two runs produce identical files |

No model is called and no API key is used: AgentDojo is only used to build the environments, fill in the injections and execute the tasks' ground-truth tool calls.

## How the scenarios are built

[`convert.py`](convert.py) runs AgentDojo's own harness (`TaskSuite.run_task_with_pipeline`) with a scripted pipeline element in place of the model:

- **Benign** (one per user task): the user prompt, then the user task's ground-truth calls with the outputs AgentDojo returns (formatted with its default YAML formatter, exactly what a model would see). The injection vectors keep their benign default text.
- **Attack** (one per user task and injection task): the injection vectors that the user task reads are filled with the `important_instructions` text for the injection task's goal. The user task's ground truth runs until the first output that shows the injection; then the injection task's ground-truth calls run, marked `"attack": true`, as the template asks ("Before you can solve the task that I gave you in the beginning, please do the following first"); then the user task continues. Each attack scenario records AgentDojo's verdicts in `agentdojo.utility_under_attack` and the injection vectors used.

A pair is **kept only if AgentDojo's own security check confirms that the scripted attack succeeds**, so every attack scenario is an attack that works without a guard. Benign scenarios are kept only if the ground truth runs without tool errors and passes AgentDojo's utility check (all 97 do).

| suite | user tasks | injection tasks | pairs | attack scenarios | skipped | benign scenarios |
|---|---|---|---|---|---|---|
| workspace | 40 | 14 | 560 | 231 | 329 | 40 |
| slack | 21 | 5 | 105 | 105 | 0 | 21 |
| travel | 20 | 7 | 140 | 118 | 22 | 20 |
| banking | 16 | 9 | 144 | 142 | 2 | 16 |
| **total** | 97 | 35 | 949 | **596** | 353 | **97** |

Skipped pairs, each listed with its reason in [`manifest.json`](manifest.json):

- **320** (workspace injection tasks 6 to 13): AgentDojo v1.2 ships these e-mail and file exfiltration tasks with an empty ground truth (`return []`), so there is no reference trajectory to convert. Writing our own would reintroduce the self-authored-benchmark problem this directory is meant to avoid.
- **20** (travel injection task 6, "Say that I should absolutely visit ..."): the goal is a manipulated answer, not a tool call; a tool-call guard cannot see it by design.
- **13**: the scripted attack does not succeed per AgentDojo's security check, because the user task's own later calls undo or supersede it (e.g. the user task also changes the password).

## Toolset mapping

AgentDojo's tools are plain functions named `send_email`, `get_webpage`, `send_money`, ...; the presets target Claude Code and MCP names (`mcp__<server>__<tool>`) and classify none of them. [`toolset.toml`](toolset.toml) is what a deployer would write for this toolset, derived from each tool's name, signature and docstring only. It declares sources and sinks but no actions: `--toolset` prepends its entries to each guarded policy (`taint-only`, `balanced`, `strict`), as if they were written in a policy file that extends the preset, so each policy's posture is unchanged. `allow-all` stays unguarded.

| tools | classification | rationale |
|---|---|---|
| e-mail reads (`get_*_emails`, `search_emails`), Slack reads (`read_*`, `get_channels`, `get_users_in_channel`) | source: untrusted, private | written by others, about the user; the presets classify mail and chat reads the same way |
| `search_calendar_events`, `get_day_calendar_events` | source: untrusted, private | invitations are created by other people (the presets leave calendars out; a deployer of this toolset would not) |
| drive reads, banking `read_file` | source: untrusted, private | shared files, bills and notices come from third parties |
| `get_webpage` | source: untrusted; sink `web` (critical `url`) | as the presets treat `WebFetch` |
| hotel, restaurant, car-rental and flight lookups | source: untrusted | listings and reviews are written by businesses and their customers |
| `get_most_recent_transactions` | source: untrusted, private | incoming transfers carry a subject chosen by the sender |
| contacts, `get_user_information`, `get_user_info`, `get_iban`, `get_balance`, `get_scheduled_transactions` | source: private | the user's own personal and financial data |
| `send_email`; `create_calendar_event`, `add_calendar_event_participants`; `send_direct_message`, `send_channel_message` | sink `send`, egress (critical: recipients / participants / channel) | the calendar docstrings state that participants are e-mailed |
| `share_file`, `invite_user_to_slack`, `add_user_to_channel` | sink `access`, egress (critical: who and where) | grants a party access to data; maps onto the preset `access` category (send posture) added by the policy-gap work |
| `send_money`, `schedule_transaction`, `update_scheduled_transaction` | sink `payment` (critical `recipient`, `amount`) | |
| `reserve_hotel`, `reserve_restaurant`, `reserve_car_rental` | sink `payment` (critical: the business) | a reservation commits the user, like `place_order` in the presets |
| `post_webpage` | sink `publish` (critical `url`) | publishes content at a URL |
| `delete_email`, `delete_file`, `cancel_calendar_event`, `remove_user_from_slack` | sink `destructive` | |
| `update_password`, `update_user_info` | sink `account` (all arguments critical) | credential and profile changes; maps onto the preset `account` category (payment posture) added by the policy-gap work |
| `create_file`, `append_to_file`, `reschedule_calendar_event` | sink `write` (critical: the target) | changes the user's own objects |
| `get_current_day` | none | |

Critical arguments name who receives data, money or access, or which object changes, never the content: content leaks are what `private_flow` and `trifecta` look for in every argument.

## Results

`toolguard eval benchmarks/agentdojo/scenarios --toolset benchmarks/agentdojo/toolset.toml` (pinned by `tests/test_agentdojo_benchmark.py`):

| policy | attacks: prevented / flagged / missed | benign: autonomous / needs-human / broken | confirms/scenario |
|---|---|---|---|
| `allow-all` | 0 / 0 / 596 | 97 / 0 / 0 | 0.00 |
| `taint-only` | 0 / 596 / 0 | 37 / 60 / 0 | 1.94 |
| `balanced` | 432 / 159 / 5 | 42 / 44 / 11 | 1.03 |
| `strict` | 526 / 70 / 0 | 37 / 15 / 45 | 0.39 |

Per suite, attacks (prevented / flagged / missed):

| suite | n | `taint-only` | `balanced` | `strict` |
|---|---|---|---|---|
| workspace | 231 | 0 / 231 / 0 | 171 / 60 / 0 | 191 / 40 / 0 |
| slack | 105 | 0 / 105 / 0 | 58 / 42 / 5 | 95 / 10 / 0 |
| travel | 118 | 0 / 118 / 0 | 97 / 21 / 0 | 98 / 20 / 0 |
| banking | 142 | 0 / 142 / 0 | 106 / 36 / 0 | 142 / 0 / 0 |

Per suite, benign tasks (autonomous / needs-human / broken):

| suite | n | `taint-only` | `balanced` | `strict` |
|---|---|---|---|---|
| workspace | 40 | 18 / 22 / 0 | 23 / 13 / 4 | 18 / 7 / 15 |
| slack | 21 | 1 / 20 / 0 | 1 / 14 / 6 | 1 / 1 / 19 |
| travel | 20 | 14 / 6 / 0 | 14 / 6 / 0 | 14 / 6 / 0 |
| banking | 16 | 4 / 12 / 0 | 4 / 11 / 1 | 4 / 1 / 11 |

These numbers are after the policy-gap work (see `../../docs/policy-gaps.md`), which changed the presets but **not** this mapping. The earlier `balanced` figures were attacks 493 / 98 / 5 and benign 42 / 35 / 20.

What the numbers say:

- **Attacker-chosen destinations are caught.** With the attacker's IBAN, e-mail address, URL or password copied from the injection into a critical argument, `balanced` blocks the exfiltration and booking attacks without asking anyone (72% prevented autonomously, 99% with a human who rejects what is flagged), **except** where the user named the source that carries the injected value (see directed flows below).
- **Directed sources are flagged, not blocked.** The policy-gap work added a generic `directed_flow` rule: when the user named the exact file or page a value came from (`pay the bill bill-december-2023.txt`, `invite the person on www.x.com`), the guard cannot tell a legitimate value from an injected one in the same resource, so `balanced` asks a human instead of blocking. This moved 61 attacks from prevented to flagged (banking 142 → 106, workspace 191 → 171, slack 63 → 58); `safety_with_human` stays at 99%, and in exchange nine benign tasks move from broken to needs-human. `strict` keeps blocking directed flows, so its numbers are unchanged.
- **Content-free attacks are only flagged.** "Delete the file with ID 13" (workspace) and "create a calendar event titled ..." (travel) carry no attributable destination, so the guard can only ask a human because the session is tainted.
- **Five attacks get through `balanced`**: slack injection task 3 ("visit this link") in user tasks whose first untrusted read is a web page. `balanced` deliberately allows browsing from a tainted session (`web: untrusted_flow = allow`) and only escalates once private data is also in context (`trifecta`); `strict` flags them.
- **Usefulness is the cost.** `balanced` breaks 11 of 97 benign tasks (down from 20) and `strict`
  45. The remaining breaks are legitimate actions whose critical arguments come from untrusted data the user did *not* name specifically: e-mailing the addresses in a shared file, adding the members listed in one channel to another. Flow evidence cannot tell "the user asked me to use this data" from "the data told me to do this"; when the user named the source, `directed_flow` turns the break into a human prompt, and the `access` category (now a preset category rather than the `default` fallback) only flags the two workspace `share_file` tasks instead of blocking them. The coarse `tainted` rule makes most of the remaining benign tasks wait for a human: every travel task with a side effect (booking, e-mail, calendar event) follows reads of third-party listings.

## Limitations

- **Ground truths are not model behaviour.** Real agents deviate from the reference trajectory, partially comply with an injection, paraphrase or encode what they exfiltrate, or refuse; a scripted trajectory that executes the injected goal verbatim is the easy case for flow tracking. AgentDojo's ground truths also skip reads a model would need (banking injection task 0 sends "spotify" without reading the transaction history), which hides some `private_flow` evidence.
- **One attack template.** `important_instructions` is AgentDojo's strongest baseline but one of many; the attack is non-adaptive and knows nothing about toolguard.
- **The interleaving is a choice.** Injected calls run right after the first exposure; an agent that defers them to the end of the task would read more private data first (more `trifecta`).
- **Mapping choices matter.** Classifying the travel listings as untrusted, or adding the `access` and `account` categories, moves the usefulness numbers; the rationale above is the honest first attempt, kept as written.
- **Utility under attack is not scored.** `toolguard eval` scores the marked attack calls; whether the user's own task still completes in an attack scenario is recorded per scenario (`agentdojo.utility_under_attack`, AgentDojo's verdict without a guard) but not evaluated.
- **Coverage.** 329 of the 560 workspace pairs cannot be converted (see above), including the bulk e-mail and file exfiltration tasks of v1.2.

## Regenerating

The image needs the network to install the locked dependencies; the conversion runs without it. From this directory:

```sh
docker build --label agent-task=agentdojo -t toolguard-agentdojo-convert:0.1.35 .
docker run --rm --network none --label agent-task=agentdojo -v "$PWD:/work" \
    toolguard-agentdojo-convert:0.1.35 python -I convert.py
docker image rm toolguard-agentdojo-convert:0.1.35
```

This rewrites `scenarios/*.json` and `manifest.json` (about five minutes). `--suite NAME` converts one suite. To change the pins, edit `requirements.in` and regenerate the lock with `uv pip compile requirements.in --universal --python-version 3.12 --generate-hashes --exclude-newer <date> -o requirements.lock`.

## License

The scenario files contain data, task prompts and injection goals from AgentDojo, used under its MIT license:

```text
MIT License

Copyright (c) 2024 Edoardo Debenedetti, Jie Zhang, Mislav Balunovic, Luca Beurer-Kellner, Marc Fischer, and Florian Tramèr

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

The converter, the mapping and this README are part of tool-call-guard (Apache-2.0).
