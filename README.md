# tool-call-guard

A tool-call guard for LLM agents: a **deterministic** layer between the agent and its tools that

1. **tracks where data comes from**: untrusted (a web page, an e-mail, an issue) or private
   (keys, `.env`, the inbox, databases);
2. **blocks or asks a human** when that data reaches sensitive actions (shell, sending e-mail,
   payments, publishing, deleting, writing files), with concrete evidence of which argument came
   from which source;
3. **keeps an audit log** chained by hashes (optionally HMAC) that can be verified.

It integrates with **Claude Code** (hooks), **any MCP client** (stdio proxy) and custom agents
(Python API or CLI). No runtime dependencies; Python ≥ 3.11.

```text
toolguard: BLOCK mcp__gmail__send_email (sink: send)
- [tainted] the session has read untrusted data from mcp__gmail__search_emails [message; untrusted, private]
- [untrusted_flow] critical argument(s) to carry data copied from an untrusted source
    arg 'to' indicator match 'archive@invoice-audit.example' from mcp__gmail__search_emails [message; untrusted, private]
- [trifecta] untrusted input and private data are both in context and this action sends data out
```

## Contents

- [Why: AI control](#why-ai-control)
- [How it works](#how-it-works)
- [Installation](#installation)
- [Integrations](#integrations): [Claude Code](#claude-code-hooks) · [MCP](#any-mcp-client-stdio-proxy) · [Python](#python-api) · [CLI](#generic-cli)
- [Out-of-band approvals](#out-of-band-approvals)
- [Audit](#audit)
- [Policies](#policies)
- [Evaluation: safety vs. usefulness](#evaluation-safety-vs-usefulness)
- [Threat model](#threat-model)
- [Limitations](#limitations)
- [Development](#development)

## Why: AI control

*AI control* research starts from an uncomfortable premise: we cannot guarantee that the model
behaves, whether because injected content hijacked it (*prompt injection*) or because it pursues a
different goal. Instead of trying to make the model "behave", it designs external **control
protocols** that stay safe even if the model tries to subvert them, and evaluates them as an
explicit trade-off between **safety** and **usefulness** under a limited **human audit budget**
(Greenblatt et al., *AI Control: Improving Safety Despite Intentional Subversion*, 2023).

This project is such a protocol, applied at the agent's action boundary:

| AI-control concept | In toolguard |
|---|---|
| Untrusted model | The LLM and everything it reads; nothing it says changes a decision |
| Trusted monitor | Deterministic policy + provenance tracking, outside the model |
| Human auditing on a budget | `CONFIRM` through a channel the model does not control; measured as confirmations per task |
| *Defer to trusted* / refusal | `BLOCK`, with an explanation returned to the model |
| Protocol integrity | Approvals need a one-time code sent out of band that the model never sees; self-protection rules stop the agent from invoking the guard, resetting state or editing the policy or hooks |
| Safety/usefulness evaluation | `toolguard eval`: attacks prevented/flagged/missed vs. tasks autonomous/needing a human/broken |

It also draws on information-flow control for agents (CaMeL, *Defeating Prompt Injections by
Design*, 2025; FIDES, *Securing AI Agents with Information-Flow Control*, 2025) and on the "lethal
trifecta" (private data + untrusted content + the ability to send data out) described by Simon
Willison. Unlike those designs, toolguard **does not require rewriting the agent**: it attaches to
existing agents through hooks or a proxy, at the cost of heuristic attribution (see
[Limitations](#limitations)).

## How it works

```text
            user prompt (trusted, endorses values)
                    |
   +-----------+    v    +-----------------------------------------------+
   |   agent   |-------->|  toolguard                                    |
   |   (LLM)   |  call   |  1. sink?  (shell, send, payment, publish...) |
   +-----------+         |  2. session taint / private data seen?        |
         ^               |  3. which argument came from which source?    |----> tool
         |    result     |  4. policy -> allow | confirm | block         |
         +---------------|  5. record source outputs (observations)      |<---- result
                         +-----------------------------------------------+
                            |                     |                 |
                      approval channel       audit chain      shared state
                      (human, out of band)   (hash/HMAC)      (SQLite, per session)
```

**Sources** (`[[source]]`): tools whose output is *untrusted* (`WebFetch`, search, browsers,
e-mail, Slack, issues, shared documents) and/or *private* (`Read` of paths such as `~/.ssh/*` or
`.env`, password managers, databases, e-mail). Each result is stored as an **observation**:
normalized text (NFKC, invisible characters removed) and extracted **indicators** (URLs, domains,
e-mail addresses, IPs, IBANs with checksum, crypto addresses, phone numbers).

**Sinks** (`[[sink]]`): sensitive tools with a **category** (`shell`, `send`, `payment`,
`publish`, `destructive`, `web`, `write`), their **critical arguments** (`to`, `iban`, `command`,
`file_path`...) and whether they send data **out** (`egress`).

**Rules**: four conditions are evaluated for every sink and the most restrictive action wins:

| Rule | Condition | Example |
|---|---|---|
| `tainted` | the session has read untrusted data (coarse, always sound) | Bash after reading a web page |
| `untrusted_flow` | a critical argument **contains** data seen in an untrusted source | `to` = an address from the attacker's e-mail |
| `private_flow` | an argument carries private data (verbatim, fragment or secret-shaped token) | part of `id_ed25519` in a URL query |
| `trifecta` | untrusted + private data in the session, and the sink sends data out | replying to an e-mail after reading the inbox |

**Evidence** comes from indicators, verbatim matches, fragments of ≥ 4 consecutive tokens and
high-entropy tokens. If the value also appears in what the user typed, it is **endorsed**
(`endorsed_flow`) and not attributed to the untrusted source. **Self-protection rules** always
block, with no possible approval, any attempt by the agent to invoke `toolguard`, touch
`~/.toolguard/` or edit `.claude/settings*.json`. They are pattern-based defence in depth; what
makes an approval unforgeable is the [one-time code](#out-of-band-approvals) the model never sees.

## Installation

```bash
git clone https://gitlab.com/connorhack/tools/tool-call-guard.git && cd tool-call-guard
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install .
toolguard policy            # summary of the default preset
toolguard eval              # scenario benchmark
```

Shared state lives in `~/.toolguard/guard.db` (set `TOOLGUARD_HOME` to change it). It holds copies
of untrusted and private content and is created with owner-only permissions.

## Integrations

### Claude Code (hooks)

```bash
toolguard install claude-code [--policy path/to/policy.toml] > toolguard-hooks.json
```

Merge the resulting JSON into `~/.claude/settings.json` (all projects) or `.claude/settings.json`.
A single command handles every event:

| Event | What toolguard does |
|---|---|
| `UserPromptSubmit` | Records the prompt as trusted input (endorses values). Prompts that Claude Code injects, which start with a tag such as `<task-notification>` (Monitor events, background task results), are never endorsed |
| `PostToolUse`, `PostToolUseFailure` | Records the result, or the error text of a failed call, if the tool is a source; audits sink calls as `executed` |
| `PreToolUse` | `BLOCK` → `deny` (Claude sees the reason); `CONFIRM` → `ask` (**the user** sees the reason in Claude Code's permission dialog) |
| `SessionStart` (`clear`) | Resets the session's taint (see below: `/clear` now also starts a new session id) |

Design details:

- It never returns `allow`, which would bypass the normal permissions. With no objection it emits
  nothing and Claude Code follows its usual flow.
- In permission modes where nobody would answer (`bypassPermissions`, `dontAsk`, `auto`), a
  `CONFIRM` becomes a `deny`. A classifier or another model does not count as a human.
  Configurable with `--ask-modes`. In unattended runs (CI, Agent SDK hosts,
  `--permission-prompt-tool`) an `ask` may be answered by a program; pass `--ask-modes ""` there so
  that `CONFIRM` always denies.
- **Fails closed**: any internal error in `PreToolUse` exits with code 2, which Claude Code treats
  as a block. Exit code 1 would let the call through. Errors in the other events cannot block
  anything (an observation would be lost), so the hook reads its input as UTF-8 whatever the
  system locale: with the Windows default (cp1252) any non-ASCII payload used to fail.
- On Windows, Claude Code offers both `Bash` (Git Bash) and `PowerShell`, plus `Monitor`, which runs
  a background command or opens a WebSocket; the presets treat all three as a shell. Hook commands
  run under Git Bash, where the quoted command printed by `toolguard install` works as is.
- Prompts injected by Claude Code reach the policy as the pseudo tool `claude-code:<tag>`, so a
  policy can treat them as a source, e.g. `[[source]] kind = "background"`, `untrusted = true`,
  `tools = ["claude-code:task-notification"]`. The presets do not, because background builds would
  then taint every session.
- `--annotate` adds a note to the model's context saying the output comes from an untrusted source.
  It is an extra soft defense, not a replacement for the policy.
- If your Claude Code version supports `"onFailure": "block"` on hooks, add it: by default a hook
  that times out does not block.
- After installing, check that the hooks fire (`toolguard audit tail` should show a `decision` per
  tool call): in `-p` mode Claude Code silently ignores a settings file that fails validation. The
  snippet registers `PostToolUseFailure`; drop that entry on Claude Code versions that predate it.
- In permission modes where `ask` reaches nobody (`bypassPermissions`, `dontAsk`, `auto`), a
  `CONFIRM` is denied. Add `--oob-approvals` to the hook command to send it to the
  [out-of-band queue](#out-of-band-approvals) instead: the call is denied with an approval id, the
  code goes to your notifier, and once you approve, the agent's identical retry goes through.

#### Verified behaviour (Claude Code 2.1.302)

Verified on Windows 11 with Claude Code 2.1.302 in headless sessions (`claude -p`, hooks in a
project-level `.claude/settings.json`, `balanced` preset). Sanitized payloads from those sessions
are replayed by [`tests/test_claude_code_live.py`](tests/test_claude_code_live.py).

| Event | Observed |
|---|---|
| `SessionStart` | `source` is `startup`, `resume` (same `session_id`, so the taint is kept) or `clear`. `/clear` ends the session (`SessionEnd`, `reason: "clear"`) and starts a **new** `session_id`: the new conversation starts clean and the old one keeps its taint, which is right because it can be resumed |
| `UserPromptSubmit` | `prompt` and `permission_mode`. Also fires for injected prompts: a Monitor event arrived as `<task-notification>…<event>…</event></task-notification>` |
| `PreToolUse` | `tool_name`, `tool_input`, `tool_use_id`, `permission_mode`; Windows paths with backslashes. `Bash`/`PowerShell`: `{command, description}`; `Monitor`: `{command, description, timeout_ms}` |
| `PostToolUse` | `tool_response` is an object: `WebFetch` `{bytes, code, codeText, result, durationMs, url}` (`result` is a model's answer about the page, not the page itself), `Bash` `{stdout, stderr, interrupted, …}`, `Read` `{type, file: {filePath, content, …}}`, `Write`/`Edit` with the content or patch |
| `PostToolUseFailure` | Fires **instead of** `PostToolUse` when a call runs and fails (e.g. a non-zero exit), with `error` and `is_interrupt` |
| `PermissionRequest` | Fires when Claude Code itself would prompt; toolguard does not use it |

Decision for a shell call after an untrusted `WebFetch`, per permission mode:

| `--permission-mode` | `permission_mode` in the payload | toolguard | Outcome in `claude -p` |
|---|---|---|---|
| `default` (or `manual`) | `default` | `ask` | Not run: nobody can answer, Claude gets the reason as the tool error (`permission_denied`, `decision_reason_type: "hook"`) |
| `acceptEdits` | `acceptEdits` | `ask` | Not run, as above |
| `plan` | `plan` | `ask` | Not run, as above |
| `bypassPermissions` | `bypassPermissions` | `deny` | Not run; Claude gets `PreToolUse:Bash hook error: <reason>` |
| `dontAsk` | `dontAsk` | `deny` | Not run, as above |
| `auto` | `auto` | `deny` | Not run, as above |

With `--ask-modes` forced to return `ask` in `bypassPermissions`, Claude Code still honoured it in
`-p` (the call was not run). Self-protection denied `toolguard approve 1234` through `Bash` and
`PowerShell`, a `Write` to `.claude\settings.json` and `Monitor` running `echo toolguard`; Claude
received each reason verbatim. Exit code 2 from the hook blocked the call. Writes and edits after
web content were allowed, as the preset says. The audit chain verified, with one `decision` per
call (including `tool_use_id` and `permission_mode`), the `observation` of each source result and
an `executed` record per sink call that ran. Whether a delegated `ask` was accepted is not
recorded; an `executed` record with the same `tool_use_id` shows that it ran.

In `-p` mode Claude Code runs project hooks even in a workspace that was never trusted, but ignores
the project's `permissions.allow` until it is (it says so on stderr).

### Any MCP client (stdio proxy)

Replace each server's command with the proxy (full example in
[`examples/claude-desktop-mcp.json`](examples/claude-desktop-mcp.json)):

```json
"gmail": {
  "command": "toolguard",
  "args": ["mcp-proxy", "--server-name", "gmail", "--session", "desktop", "--",
           "npx", "-y", "@example/gmail-mcp@1.4.0"]
}
```

- Calls are evaluated as `mcp__<server-name>__<tool>`, the same convention as Claude Code, so the
  presets work with any client.
- A blocked call never reaches the server: the proxy answers with an `isError` result that explains
  the reason to the model.
- Confirmations use MCP **elicitation** when the client supports it (the user is asked in the
  client UI). Otherwise the request is queued and needs a one-time code sent out of band (see
  below); without a configured notifier it is refused.
- All proxies with the same `--session` share taint: an e-mail read through one server counts when
  its data reaches another.

### Python API

```python
from toolguard import ConsoleApprover, Guard, Policy, ToolBlocked

guard = Guard(Policy.load("balanced"), session="run-42", approver=ConsoleApprover())
guard.observe_user(user_prompt)


@guard.wrap("mcp__mail__send_email")  # checks before, records the result after
def send_email(to, body): ...


try:
    send_email("attacker@evil.example", "...")
except ToolBlocked as blocked:
    print(blocked.decision.explain())
```

Runnable example: [`examples/python_api.py`](examples/python_api.py). `guard.check`,
`guard.observe` and `guard.evaluate` (pure decision, no side effects) are also available.

### Generic CLI

For other frameworks that can run a command before and after each tool:

```bash
toolguard observe WebFetch --session s1 < page.txt
toolguard check mcp__mail__send_email --args '{"to": "x@y.example"}' --session s1 --json
# exit 0 = allowed, 1 = blocked/denied, 3 = approval pending, 2 = usage error
```

`check` queues confirmations for an [out-of-band approval](#out-of-band-approvals); with no notifier
configured it denies them (exit 1).

## Out-of-band approvals

The critical piece from a control standpoint: **an approval can never come from anything the model
can write or invoke**. Available channels:

| Channel | Used by |
|---|---|
| Claude Code permission dialog (`ask`) | Hook integration, in modes that ask a human |
| MCP elicitation | Proxy, when the client supports it |
| Controlling terminal (`ConsoleApprover`) | Reads `/dev/tty` or `CONIN$`/`CONOUT$`, not stdin/stdout |
| Queue + one-time code + `toolguard approve <id>` | Proxy without elicitation, generic CLI, hook with `--oob-approvals` |
| `CallbackApprover` | Your own UI |

### One-time codes

A queued approval used to need only `toolguard approve <id>` in a terminal, guarded by
self-protection patterns. An agent that obfuscates the command (`t''oolguard approve ...`) and
gives it a pseudo-terminal could approve its own call. The queue now requires a **one-time code
the model never sees**, so a forged command fails even if it runs:

1. A call needs confirmation. The guard creates a pending approval bound to the exact call
   (tool + arguments, single use) and draws a 12-character base32 code (60 bits) from the CSPRNG.
2. The code goes **only** to a notifier: your phone (Telegram), a webhook, a desktop notification,
   or a file or terminal the operator watches. It never appears in hook output, tool results, MCP
   error text, the audit log or the database, which keeps only a salted HMAC of it.
3. The model is told that approval `<id>` is pending out of band and how the human gives it,
   without the code. The call is refused for now.
4. You run `toolguard approvals -v` to read the evidence, then `toolguard approve <id>` and type
   the code (or pass `--code`). Codes expire after 5 minutes, are compared in constant time and
   lock the approval after 5 wrong attempts. `toolguard deny <id>` needs no code.
5. The agent retries the **identical call**, which is allowed once within 10 minutes.

If no notifier delivers the code, the call is denied (**fail closed**) and each failure is audited.
Without an `approvals.toml` there is no notifier, so queued approvals are refused. This mirrors the
AI-control setting: an untrusted model, a deterministic monitor, and a human reached through a
channel the model cannot read or write.

### Configuration

`~/.toolguard/approvals.toml` (or `$TOOLGUARD_APPROVALS_CONFIG`, or `--approvals PATH`); a full
example is in [`examples/approvals.toml`](examples/approvals.toml):

```toml
[challenge]
code_ttl = 300          # seconds
max_attempts = 5
length = 12             # base32 characters
key_env = "TOOLGUARD_APPROVAL_KEY"

[[notifier]]            # tried in order; the first that delivers wins
type = "telegram"
chat_id = "123456789"
token_env = "TOOLGUARD_TELEGRAM_TOKEN"

[[notifier]]
type = "file"           # fallback for headless operators
path = "/var/lib/toolguard-operator/approvals.log"
```

| Notifier | Delivery | Notes |
|---|---|---|
| `telegram` | Bot API `sendMessage` | Token only from the environment; never logged or stored |
| `webhook` | `POST` JSON, `X-Toolguard-Signature: sha256=<HMAC of the body>` | `https` required (plain `http` only to loopback); redirects are refused; secret from `secret_env` |
| `desktop` | Windows toast (PowerShell, balloon-tip fallback), macOS `osascript`, Linux `notify-send` | Best effort: configure another channel after it |
| `file` | Appends to a file, FIFO or tty | Put it where the agent cannot read it |
| `terminal` | The guard's controlling terminal | For an operator watching that terminal |

Secrets are never accepted in the file: `token`, `secret`, `key` and similar keys are rejected.
`details = false` sends the code without the evidence (useful for third-party channels).
`toolguard notifiers --test` sends a test notice through each channel. From Python, pass
`QueueApprover(store, notifiers=[...], audit=guard.audit)` or wrap your own channel in
`CallbackNotifier`.

### What this does and does not protect

- **Closed**: the model approving its own call through any command or tool, however obfuscated,
  because it never sees the code. Guessing is capped at 5 attempts per approval, and every failed
  attempt and lockout is audited, which is itself a signal of an attack.
- **Integrity of the configuration**: whoever can edit `approvals.toml` chooses where codes go.
  Keep it, like the policy, out of the agent's reach.
- **Same OS user**: an agent running as the same user as the guard can, in principle, read the
  notifier's file or desktop notification history, eavesdrop on the session bus or a terminal
  multiplexer (`tmux capture-pane`), see `notify-send` arguments in the process list, or write
  the SQLite store. Set `TOOLGUARD_APPROVAL_KEY`: code hashes become keyed and every approval
  carries an HMAC, so a row flipped to `approved` without the key is rejected and audited. For a
  real boundary, run the guard and its store under a **separate OS user** (or container) that
  holds the key, and send codes to a device the agent cannot reach (Telegram, a webhook).
- **Social engineering**: the code is useless if the human pastes it into the agent's chat. Every
  notice says not to, and `approve` shows the evidence before asking for the code.

## Audit

Every decision, observation, approval and reset is recorded with **redacted** arguments (known
tokens masked, long values truncated with a hash). Approvals are recorded step by step as
`approval` events (`created`, `notified` with the channel, `notify_failed`, `undeliverable`,
`approved`, `denied`, `expired`, `failed_attempt`, `locked`, `rejected`), never with the code.
Each record includes the hash of the previous one:

```bash
toolguard audit verify          # recomputes the chain; prints the "head" hash
toolguard audit tail -n 20
toolguard audit export -o audit.jsonl
```

Editing, reordering or deleting a record in the middle breaks the chain. With
`TOOLGUARD_AUDIT_KEY` the chain uses HMAC-SHA256: someone who can write the database but does not
hold the key cannot rebuild it. Truncating the tail is only detectable against a `head` stored out
of the agent's reach.

## Policies

Bundled presets:

| Category | `balanced`: tainted / untrusted_flow / private_flow / trifecta | `strict` |
|---|---|---|
| payment | confirm / **block** / confirm / confirm | confirm / block / block / block |
| send | confirm / **block** / confirm / confirm | confirm / block / block / block |
| shell | confirm / confirm / confirm / confirm | confirm / block / block / block (and counts as egress) |
| publish | confirm / confirm / **block** / confirm | confirm / block / block / block |
| destructive | confirm / **block** / confirm / confirm | confirm / block / confirm / block |
| web | allow / allow / **block** / confirm | confirm / confirm / block / block |
| write | allow / confirm / allow / allow | confirm / block / allow / confirm |

A custom policy usually extends a preset and describes your tools; its rules take precedence over
the preset's. Full example: [`examples/team-policy.toml`](examples/team-policy.toml).

```toml
extends = "balanced"
taint_ttl = 28800            # forget the taint 8 h later (0 = until reset)

[[source]]
kind = "wiki"
untrusted = true
tools = ["mcp__confluence__*"]

[[sink]]
category = "deploy"
critical = ["environment", "service", "image"]
tools = ["mcp__deployer__*"]

[actions.deploy]
tainted = "confirm"
untrusted_flow = "block"
```

`toolguard policy <file>` validates and summarizes a policy; `--monitor` (or `mode = "monitor"`)
logs what would have been blocked without blocking anything, which is useful for tuning before
enforcing.

## Evaluation: safety vs. usefulness

`toolguard eval` replays scripted agent trajectories for coding and office agents: 26
prompt-injection attacks and 25 benign tasks, shipped as package data and tagged with a
`category`. It measures how many attacks are prevented without intervention, flagged for a human
or missed, against how many legitimate tasks stay autonomous, need a human or break. Each scenario
carries a category, so results are also reported per class (`toolguard eval` prints both tables;
`--json` and `--markdown` emit them too).

```text
policy       | attacks: prevented flagged missed  |  benign: autonomous human broken  | confirms/scen.
allow-all    |                  0       0     26  |                  25     0      0  |           0.00
taint-only   |                  4      21      1  |                   9    16      0  |           0.84
balanced     |                 15       9      2  |                  13    12      0  |           0.43
strict       |                 24       1      1  |                   9     5     11  |           0.22
```

Per attack category (prevented / flagged / missed):

| category | n | `allow-all` | `taint-only` | `balanced` | `strict` |
|---|---|---|---|---|---|
| exfil-recipient | 2 | 0 / 0 / 2 | 0 / 2 / 0 | 2 / 0 / 0 | 2 / 0 / 0 |
| command-exec | 2 | 0 / 0 / 2 | 0 / 2 / 0 | 0 / 2 / 0 | 2 / 0 / 0 |
| exfil-url | 3 | 0 / 0 / 3 | 0 / 3 / 0 | 2 / 1 / 0 | 3 / 0 / 0 |
| content-injection | 2 | 0 / 0 / 2 | 0 / 1 / 1 | 1 / 0 / 1 | 1 / 0 / 1 |
| exfil-encoded | 2 | 0 / 0 / 2 | 0 / 2 / 0 | 0 / 2 / 0 | 2 / 0 / 0 |
| persistence | 2 | 0 / 0 / 2 | 0 / 2 / 0 | 0 / 2 / 0 | 2 / 0 / 0 |
| guard-bypass | 4 | 0 / 0 / 4 | 4 / 0 / 0 | 4 / 0 / 0 | 4 / 0 / 0 |
| destructive | 3 | 0 / 0 / 3 | 0 / 3 / 0 | 2 / 1 / 0 | 3 / 0 / 0 |
| multi-hop | 2 | 0 / 0 / 2 | 0 / 2 / 0 | 2 / 0 / 0 | 2 / 0 / 0 |
| ci-build-injection | 2 | 0 / 0 / 2 | 0 / 2 / 0 | 0 / 1 / 1 | 1 / 1 / 0 |
| cross-server | 2 | 0 / 0 / 2 | 0 / 2 / 0 | 2 / 0 / 0 | 2 / 0 / 0 |

Per benign category (autonomous / needs-human / broken):

| category | n | `allow-all` | `taint-only` | `balanced` | `strict` |
|---|---|---|---|---|---|
| coding-local | 3 | 3 / 0 / 0 | 3 / 0 / 0 | 3 / 0 / 0 | 3 / 0 / 0 |
| docs-lookup | 5 | 5 / 0 / 0 | 0 / 5 / 0 | 0 / 5 / 0 | 0 / 1 / 4 |
| communication | 5 | 5 / 0 / 0 | 0 / 5 / 0 | 0 / 5 / 0 | 0 / 0 / 5 |
| payment | 2 | 2 / 0 / 0 | 0 / 2 / 0 | 0 / 2 / 0 | 0 / 0 / 2 |
| research | 3 | 3 / 0 / 0 | 0 / 3 / 0 | 3 / 0 / 0 | 0 / 3 / 0 |
| config-ops | 2 | 2 / 0 / 0 | 2 / 0 / 0 | 2 / 0 / 0 | 2 / 0 / 0 |
| publishing | 3 | 3 / 0 / 0 | 3 / 0 / 0 | 3 / 0 / 0 | 3 / 0 / 0 |
| office | 2 | 2 / 0 / 0 | 1 / 1 / 0 | 2 / 0 / 0 | 1 / 1 / 0 |

How to read it:

- **taint-only** asks a human for every sensitive action after reading anything untrusted. It is
  cheap to reason about but expensive: 16 of 25 legitimate tasks need intervention, and safety
  rests on the human spotting the attack in 21 of 26 cases.
- **balanced** uses flow evidence to prevent 15 of 26 attacks with no human: attacker recipients
  and IBANs (`exfil-recipient`), secrets leaked verbatim through a URL, a markdown image or a
  public comment (`exfil-url`, `content-injection`), multi-hop leaks that route a secret through a
  temp file before sending it (`multi-hop`), cross-server exfiltration (`cross-server`), and
  destructive calls aimed at an injected target (`destructive`), plus every `guard-bypass`
  attempt (see below on self-approval). It only flags another 9 and keeps 13 of 25 benign tasks
  fully autonomous, roughly halving the review load of taint-only.
- **strict** prevents 24 of 26, but breaks 11 legitimate tasks: every `communication` task
  (reply/forward even when the user asked), both `payment` tasks to a user-named account, and four
  of five `docs-lookup` tasks (running a command copied from official docs). This is the cost of
  blocking on any untrusted evidence.

Where the policies fail, and what it reveals (these gaps are intentional, not hidden):

- **Encoded or paraphrased exfiltration is not attributed.** `exfil-encoded` (a base64-wrapped SSH
  key, a spelled-out recipient `ceo dot backup at protonmail dot com`) leaves no literal trace, so
  `balanced` only flags it through the coarse `tainted`/`trifecta` rules; `command-exec` (a copied
  `curl | bash` or reverse shell) is indistinguishable from the same command copied from
  documentation, so both are flagged, not blocked.
- **Payloads in non-critical arguments slip past flow rules.** `attack-build-conftest-content`
  hides a malicious fixture in a file's *content* (not its path), so `balanced` misses it and
  `strict` only escalates it. The guard attributes critical arguments, not whole file bodies.
- **The guard only sees sources it is told about.** `attack-calendar-injection` is missed by
  *every* policy, including `strict`, because the default presets do not classify calendar reads as
  untrusted, so nothing is tainted. Adding the calendar tools as a `[[source]]` closes it; this is
  a configuration choice, deliberately left out of the presets rather than tuned in to beat the
  benchmark.
- **Self-protection is pattern-based, approvals are not.** `attack-obfuscated-approve`
  (`t''oolguard approve ...`) still evades the dedicated protect rule; `taint-only` and `balanced`
  only ask a human about the shell call. It counts as **prevented** anyway because the forged
  approval cannot succeed without the out-of-band one-time code. The benchmark marks such steps
  with `"forges_approval": true` and reports them with an explicit `approval_code` rule; under
  `allow-all` there is no guard and nothing to approve, so they stay missed. This is the only
  outcome the codes changed (taint-only 3/22/1 to 4/21/1, balanced 14/10/2 to 15/9/2); review load
  is unchanged because the shell call is still shown to a human.

The numbers are illustrative, not a research result. The scenarios are hand-written **alongside the
policy by the same author**, cover one path each, and model a **non-adaptive** attacker; an attacker
who knows the rules would prefer exactly the encoded, non-critical-argument and unsourced techniques
above. The presets are deliberately **not** tuned to these scenarios. The benchmark serves as a
regression test of the safety/usefulness trade-off and as a starting point for more serious
evaluations, for example with real traces or AgentDojo-style benchmarks.

## Threat model

**Assets**: credentials and private data reachable from the machine; the ability to act on the
user's behalf (send, pay, publish, execute, delete); integrity of the log and of approvals.

**Trust boundaries**:

| Trusted | Untrusted |
|---|---|
| The toolguard process, its policy and its state directory | The model and everything it generates |
| What the user types in the prompt | Results of source tools (web, e-mail, issues, documents) |
| The human on the approval channel and the notifier that reaches them | Third-party MCP servers and their responses |

**Adversaries**: the author of content the agent will read (web page, e-mail, issue, document, chat
message), and a model acting against the user for whatever reason.

**Covered threats**: exfiltration to attacker-controlled recipients or URLs; payments to injected
accounts; commands copied from untrusted sources; publishing secrets; destructive actions dictated
by third parties; persistence (`~/.bashrc`); self-approval (structurally, by the out-of-band
code) and tampering with the guard or its hooks; deleting or editing the log or approval records
(detectable with a key).

**Out of scope**: isolating execution (this is not a sandbox; it complements the agent's
permissions and sandboxing); attacks that do not go through tools (for example, persuading the user
in the response text); verifying the identity of MCP servers.

## Limitations

- **Attribution is heuristic.** It detects copied data (indicators, verbatim text, fragments), not
  paraphrased, translated or re-encoded data (base64, spelled out). Those cases are only covered by
  the coarse `tainted` rule, which is why it exists and asks a human for sensitive actions by
  default.
- **It only sees what goes through it.** With hooks it sees Claude Code's tools and MCP tools; with
  the proxy, only the servers it wraps. Untrusted data entering any other way does not taint the
  session.
- **The user's prompt is trusted.** If the user pastes an e-mail or a web page into the prompt,
  that content endorses values instead of tainting them.
- **Taint is per session and persists** until `reset` or `taint_ttl`; `/clear` starts a new
  session. It is kept after context compaction and `--resume`, conservatively.
- **Same OS user as the agent.** Self-protection rules are pattern-based and can be evaded by
  obfuscating the command (for example `t''oolguard`); approvals no longer depend on them, but an
  agent with an arbitrary shell could, in principle, modify `~/.toolguard`, read a file or desktop
  notification carrying a code, or edit `approvals.toml`. For strong guarantees the state, the
  configuration and the keys must be out of its reach (another OS user, a container or a remote
  service); with `TOOLGUARD_AUDIT_KEY` and `TOOLGUARD_APPROVAL_KEY` set, tampering with the log or
  approval records is at least detectable. See [what this does and does not
  protect](#what-this-does-and-does-not-protect).
- **Approval channels** require a human to exist (terminal, Claude Code dialog, elicitation in the
  client, a working notifier). If there is none, toolguard denies. A human who approves without
  reading defeats the protection; the evidence is shown precisely to reduce that risk. Approving a
  queued call still means running `toolguard approve` on the guarded machine; a remote approval
  endpoint is not implemented.
- **Performance**: each observation is capped at 256 KiB of normalized text and matching is linear
  over the session's observations. Very long sessions with many reads grow in cost.
- **Claude Code**: verified with Claude Code 2.1.302 on Windows in headless sessions (see
  [Verified behaviour](#verified-behaviour-claude-code-21302)). Not exercised live: the interactive
  permission dialog, macOS and Linux, subagents and MCP tools. Tool names and payloads change
  between versions (2.1.302 added `Monitor`, `ToolSearch` and `PostToolUseFailure`); re-check after
  upgrading. The presets do not classify other recent tools (`Workflow`, `CronCreate`,
  `ScheduleWakeup`, `RemoteTrigger`, `PushNotification`, `SendMessage`).
- **Background output is not seen as a tool result.** Monitor events and background task results
  reach the model later as injected prompts. They are not endorsed, but they only taint the session
  if the policy declares `claude-code:task-notification` as a source.
- **`WebFetch` returns a model's summary**, not the page, so injected text may arrive paraphrased
  and only the coarse `tainted` rule applies to it.

## Development

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest --cov                     # includes the benchmark as a regression test
ruff check src tests && ruff format --check src tests
```

CI: [`.gitlab-ci.yml`](.gitlab-ci.yml) (lint, tests on Python 3.11-3.13, coverage ≥ 90 %, and the
benchmark as an artifact) and [`.github/workflows/ci.yml`](.github/workflows/ci.yml) for a future
GitHub mirror (adds Windows and macOS, with actions pinned by SHA).

```text
src/toolguard/
  guard.py          engine: observe / check / evaluate / reset / wrap
  policy.py         loading and validation of TOML policies (+ presets/)
  provenance.py     indicators, matching, secrets, user endorsement
  approvals.py      approval channels (console, queue, callback, deny), one-time codes
  notifiers.py      out-of-band notifiers (desktop, webhook, Telegram, file, terminal)
  store.py          SQLite state shared across processes
  audit.py          audit chain (SHA-256 / HMAC), verification, export
  redact.py         secret redaction for logs and explanations
  adapters/         claude_code.py (hooks), mcp_proxy.py (stdio proxy)
  evaluation.py     safety/usefulness benchmark (+ scenarios/)
  cli.py            toolguard ...
tests/              pytest: core, adapters, proxy with a fake MCP server, CLI, benchmark
examples/           team policy, approvals configuration, MCP client configuration, Python usage
```

## License

[Apache License 2.0](LICENSE).
