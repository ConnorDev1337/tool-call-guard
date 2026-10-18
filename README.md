# Tool-Call Guard

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
e-mail, Slack and other chat, calendar events and invitations, issues, tickets, pull requests and
comments on any forge or help desk, shared documents and pages) and/or *private* (`Read` of paths
such as `~/.ssh/*` or `.env`, password managers, databases, e-mail). Each result is stored as an
**observation**: normalized text (NFKC, invisible characters removed) and extracted **indicators**
(URLs, domains, e-mail addresses, IPs, IBANs with checksum, crypto addresses, phone numbers). A
source the user named in the prompt (e.g. `read invoices/bill.txt`, `open https://x`) is recorded
as **directed**.

**Sinks** (`[[sink]]`): sensitive tools with a **category** (`shell`, `send`, `payment`,
`publish`, `destructive`, `web`, `write`, plus `autoexec` for writes to auto-executed paths,
`access` for sharing/invites/membership and `account` for credential, key and profile changes),
their **critical arguments** (`to`, `iban`, `command`, `file_path`...) and whether they send data
**out** (`egress`).

**Rules**: five conditions are evaluated for every sink and the most restrictive action wins:

| Rule | Condition | Example |
|---|---|---|
| `tainted` | the session has read untrusted data (coarse, always sound) | Bash after reading a web page |
| `untrusted_flow` | a critical argument **contains** data seen in an untrusted source | `to` = an address from the attacker's e-mail |
| `directed_flow` | an `untrusted_flow` whose source the user named in the prompt | `iban` from the bill the user asked to pay |
| `private_flow` | an argument carries private data (verbatim, fragment or secret-shaped token) | part of `id_ed25519` in a URL query |
| `trifecta` | untrusted + private data in the session, and the sink sends data out | replying to an e-mail after reading the inbox |

**Evidence** comes from indicators, verbatim matches, fragments of ≥ 4 consecutive tokens and
high-entropy tokens. If the value also appears in what the user typed, it is **endorsed**
(`endorsed_flow`) and not attributed to the untrusted source; private text the user typed is
endorsed too, but secret-shaped tokens never are. Private data that the untrusted source of the
same argument also contains (the attacker's address inside a private e-mail) is reported once, as
an untrusted flow; other private data in that argument (a key appended to a URL whose host came
from a page) is still a `private_flow`. Percent-encoded arguments are also matched decoded.
`directed_flow` is softer than `untrusted_flow`
(the user pointed at the source, but it may still carry injected instructions the guard cannot
distinguish from legitimate data), so `balanced` asks a human where it would otherwise block.
**Self-protection rules** always
block, with no possible approval, any attempt by the agent to invoke `toolguard`, touch
`~/.toolguard/` or edit `.claude/settings*.json`. They are pattern-based defence in depth; what
makes an approval unforgeable is the [one-time code](#out-of-band-approvals) the model never sees.

## Installation

```bash
git clone https://github.com/ConnorDev1337/tool-call-guard.git && cd tool-call-guard
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
- What the server returns to the model is observed: tool results, and the contents of
  `resources/read` (including reads of resource templates) and `prompts/get`, as
  `mcp__<server-name>__resources/read` (argument `uri`) and `mcp__<server-name>__prompts/get`
  (`name`, `arguments`). The presets treat resources and prompts as third-party content
  (untrusted; resource URIs that look like secret files are private too); a `[[trust]]` rule in
  your policy declares the ones you vouch for (see [Policies](#policies)).
- The URI of a `resources/read` is guarded too, since the server fetches it and resource templates
  let the agent build it: the read is evaluated as `mcp__<server-name>__resources/read` with its
  `uri`. In the presets a `file://` URI is a local read (`local-read`, never an egress), an
  `http(s)`, `ws(s)` or `ftp` URI is a `web` sink (a secret in it is blocked, like in a `WebFetch`
  URL), and any other scheme is a `resource` sink (a private value in the URI needs a human;
  `strict` blocks it). A refused read gets a JSON-RPC error (code `-32003`) that explains why.
- The proxy forwards only what it has inspected: a client line that is not JSON gets a parse
  error, a line that is not valid UTF-8 is guarded and forwarded as decoded, batches are split and
  every `tools/call` in them is guarded, and a `tools/call` with malformed parameters is refused.
- When the client closes its stdin the proxy closes the server's, then terminates and kills it if
  it does not exit (the MCP stdio shutdown sequence). The proxy exits with the server's exit code
  (128 + N if a signal N killed it).
- The server command is looked up on `PATH`, so `npx` (`npx.cmd`) works on Windows.

#### Verified behaviour (real MCP servers)

Verified on 2026-10-17 in a throwaway container (`--network none`, unprivileged user) with the
official MCP Python SDK 2.3.0 as the client and `@modelcontextprotocol/server-everything`,
`server-filesystem` and `server-memory` 1.0.0 (TypeScript SDK 1.32.1), `mcp-server-fetch` and
`mcp-server-git` 2026.10.10 (Python SDK 1.30.0), plus a toy server on SDK 2.3.0 for protocol
2026-07-28. Sanitized traffic is replayed by
[`tests/test_mcp_proxy_live.py`](tests/test_mcp_proxy_live.py); the recipe and the scenarios are in
[`tests/fixtures/mcp_live`](tests/fixtures/mcp_live/README.md).

| Area | Observed |
|---|---|
| Handshake | The SDK first probes `server/discover` (2026-07-28); the reference servers answer `-32601` and the client falls back to `initialize` 2025-11-25. Versions, capabilities (including `elicitation: {form, url}`, `sampling`, `roots`, the server's `tasks`) and `instructions` pass through unchanged |
| Listings and content | `tools/list`, `prompts/*`, `resources/*` (text and blob), templates, completion and subscriptions pass byte for byte, as do images, resource links, embedded resources, `structuredContent`, `isError` results and a 1.16 MB text or 512 KiB image result |
| Notifications and server requests | Progress, log messages and `list_changed` reach the client; the server's own `elicitation/create`, `sampling/createMessage` and `roots/list` reach the client and its answers reach the server |
| Concurrency and cancellation | 20 concurrent calls with integer and string ids each got their own answer; `notifications/cancelled` reaches the server, which then sends no response |
| Guarding | A page fetched by `mcp-server-fetch` tainted the session shared with `server-memory` and `server-filesystem`: deleting the entity it named was blocked before reaching the server, a `conftest.py` write needed a human, and after a `.env` read a URL carrying its content was refused. A task-augmented call's output (fetched with `tasks/result`) taints the session too |
| Confirmations | Elicitation accept ran the call, decline and cancel refused it; without elicitation the call was queued, the code reached only the file notifier, and the retry after `toolguard approve` ran |
| Failures | A server killed mid-session made the proxy exit with 137 and the client see EOF at once; a server that ignores EOF (`server-everything` with logging on) was terminated about 5 s after the client left |
| Protocol 2026-07-28 | Per-request `_meta`, no `initialize`: `tools/call` is guarded as usual and refusals carry `resultType: "complete"` |

Bugs found this way and fixed in the proxy, each with a regression test: client lines it could not
parse were relayed raw (and batches unguarded), malformed requests or elicitation answers stopped
it silently, task results were never observed, it hung when a server outlived its client, a call
cancelled while awaiting confirmation still ran once approved, elicitation ids were predictable and
any answer with the prefix was swallowed, the process aborted at exit while still reading stdin,
and refusals were rejected by 2026-07-28 clients for lacking `resultType`.

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
2. The code goes **only** to a notifier: your phone (Telegram), a webhook, a desktop notification
   (Windows, macOS), or a file or terminal the operator watches. It never appears in hook output,
   tool results, MCP error text, the audit log, the database (which keeps only a salted HMAC of
   it) or a command line.
3. The model is told that approval `<id>` is pending out of band and how the human gives it,
   without the code. The call is refused for now.
4. You run `toolguard approvals -v` to read the evidence, then `toolguard approve <id>` and type
   the code (or pass `--code`). Codes expire after 5 minutes, are compared in constant time and
   lock the approval after 5 wrong attempts. `toolguard deny <id>` needs no code.
5. The agent retries the **identical call**, which is allowed once within 10 minutes.

Each notice also carries a short **brief** of what you are approving: the tool and its sink, the
argument values (critical and flagged ones first), the rules that fired, and where each flagged
value came from (source tool or resource, untrusted or private, and whether you named that source
in your prompt). Secret-shaped tokens and known credential formats are masked as
`[secret:<sha256 prefix>]`, the same prefix the evidence uses; IBANs and crypto addresses stay
readable unless they are the leaked secret; secrets are found even when percent-encoded, values
are otherwise shown as sent, and invisible or bidi characters are escaped. The brief goes to the
notifier (and the terminal approver), never to the model:

```text
mcp__slack__send_message (sink: send) flagged by tainted, private_flow, trifecta
Arguments:
  channel = #general
  text = token: [secret:bf378b65c7fd]
Rules:
  tainted: the session has read untrusted data from WebFetch [web; untrusted]
  private_flow: argument(s) text carry private data
  trifecta: untrusted input and private data are both in context and this action sends ...
Where the flagged values come from:
  text: secret match '[redacted:bf378b65c7fd]' from Read [secret-file; private] (private)
```

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
| `desktop` | Windows toast (PowerShell, balloon-tip fallback), macOS `osascript`, Linux `notify-send` | Best effort: configure another channel after it. On Linux it is an **alert only** (see below); `send_code = false` makes it one everywhere |
| `file` | Appends to a file, FIFO or tty | Put it where the agent cannot read it |
| `terminal` | The guard's controlling terminal | For an operator watching that terminal |

**Desktop notifications and the code.** `notify-send` takes its text only as command-line
arguments, which every process of the same user can read in the process list while it runs (an
agent can poll `ps` for it), and neither `gdbus` nor `dbus-send` reads the message from stdin. So
on Linux the desktop notifier never receives the code: it is an *alert* that says an approval is
pending and names the channel that has the code, sent after that channel delivered it. Configure
a code channel too (Telegram, a webhook, or a file or terminal the operator watches); if alerts
are the only notifiers, queued approvals fail closed and `toolguard notifiers` says so. On Windows
(PowerShell gets a constant script as its argument and the text on stdin) and macOS (`osascript`
reads its script from stdin) the code is never on a command line, but the notification is kept in
the notification center's history, which programs of the same user can read; `send_code = false`
keeps the code off the desktop there as well.

Secrets are never accepted in the file: `token`, `secret`, `key` and similar keys are rejected.
`details = false` sends the code with only the first line of the brief (the call, its sink and the
rules), useful for third-party channels.
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
  multiplexer (`tmux capture-pane`), or write the SQLite store. The code is never put on a
  command line (`notify-send` only gets a code-less alert). Set `TOOLGUARD_APPROVAL_KEY`: code hashes become keyed and every approval
  carries an HMAC, so a row flipped to `approved` without the key is rejected and audited. For a
  real boundary, run the guard and its store under a **separate OS user** (or container) that
  holds the key, and send codes to a device the agent cannot reach (Telegram, a webhook).
- **Social engineering**: the code is useless if the human pastes it into the agent's chat. Every
  notice says not to, and `approve` shows the evidence before asking for the code.

## Audit

Every decision, observation, approval and reset is recorded with **redacted** arguments (known
tokens masked, long values truncated with a hash). Approvals are recorded step by step as
`approval` events (`created`, `notified` with the channel, `notify_failed`, `alerted`,
`alert_failed`, `undeliverable`, `approved`, `denied`, `expired`, `failed_attempt`, `locked`,
`rejected`), never with the code.
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
| access | confirm / **block** / confirm / confirm | confirm / block / block / block |
| account | confirm / **block** / confirm / confirm | confirm / block / block / block |
| shell | confirm / confirm / confirm / confirm | confirm / block / block / block (and counts as egress) |
| autoexec | confirm / confirm / confirm / confirm | confirm / block / block / block |
| publish | confirm / confirm / **block** / confirm | confirm / block / block / block |
| destructive | confirm / **block** / confirm / confirm | confirm / block / confirm / block |
| web | allow / allow / **block** / confirm | confirm / confirm / block / block |
| write | allow / confirm / allow / allow | confirm / block / allow / confirm |

`directed_flow` defaults to `untrusted_flow`; `balanced` softens it to `confirm` for `payment`,
`send`, `access` and `account` (a value from a source the user named goes to a human, not an
outright block), while `strict` keeps it at `block`. `autoexec` (writes to `conftest.py`, CI
configs, `Makefile`, `package.json`, git hooks, shell rc files, Dockerfiles, ...) takes the shell
posture with every argument critical; `access` (sharing, invites, membership) mirrors `send`; and
`account` (credentials, keys, profile) mirrors `payment`.

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

A `[[trust]]` rule (`tools`, optional `when`) declares results you vouch for: they are not
untrusted even if a source rule says so, although private data stays private. Use it for content
your team writes, such as an internal documentation server's MCP resources:

```toml
[[trust]]
tools = ["mcp__docs__resources/read"]
when = { uri = ["docs://handbook/*"] }
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
taint-only   |                  4      22      0  |                   9    16      0  |           0.86
balanced     |                 16      10      0  |                  13    12      0  |           0.45
strict       |                 26       0      0  |                   9     5     11  |           0.20
```

Per attack category (prevented / flagged / missed):

| category | n | `allow-all` | `taint-only` | `balanced` | `strict` |
|---|---|---|---|---|---|
| exfil-recipient | 2 | 0 / 0 / 2 | 0 / 2 / 0 | 2 / 0 / 0 | 2 / 0 / 0 |
| command-exec | 2 | 0 / 0 / 2 | 0 / 2 / 0 | 0 / 2 / 0 | 2 / 0 / 0 |
| exfil-url | 3 | 0 / 0 / 3 | 0 / 3 / 0 | 2 / 1 / 0 | 3 / 0 / 0 |
| content-injection | 2 | 0 / 0 / 2 | 0 / 2 / 0 | 2 / 0 / 0 | 2 / 0 / 0 |
| exfil-encoded | 2 | 0 / 0 / 2 | 0 / 2 / 0 | 0 / 2 / 0 | 2 / 0 / 0 |
| persistence | 2 | 0 / 0 / 2 | 0 / 2 / 0 | 0 / 2 / 0 | 2 / 0 / 0 |
| guard-bypass | 4 | 0 / 0 / 4 | 4 / 0 / 0 | 4 / 0 / 0 | 4 / 0 / 0 |
| destructive | 3 | 0 / 0 / 3 | 0 / 3 / 0 | 2 / 1 / 0 | 3 / 0 / 0 |
| multi-hop | 2 | 0 / 0 / 2 | 0 / 2 / 0 | 2 / 0 / 0 | 2 / 0 / 0 |
| ci-build-injection | 2 | 0 / 0 / 2 | 0 / 2 / 0 | 0 / 2 / 0 | 2 / 0 / 0 |
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
  rests on the human spotting the attack in 22 of 26 cases.
- **balanced** uses flow evidence to prevent 16 of 26 attacks with no human: attacker recipients
  and IBANs (`exfil-recipient`), secrets leaked verbatim through a URL, a markdown image or a
  public comment (`exfil-url`, `content-injection`), multi-hop leaks that route a secret through a
  temp file before sending it (`multi-hop`), cross-server exfiltration (`cross-server`), and
  destructive calls aimed at an injected target (`destructive`), plus every `guard-bypass`
  attempt (see below on self-approval). It only flags another 10 and keeps 13 of 25 benign tasks
  fully autonomous, roughly halving the review load of taint-only.
- **strict** prevents all 26, but breaks 11 legitimate tasks: every `communication` task
  (reply/forward even when the user asked), both `payment` tasks to a user-named account, and four
  of five `docs-lookup` tasks (running a command copied from official docs). This is the cost of
  blocking on any untrusted evidence.

Both formerly documented misses are now closed generically by the policy-gap work (see
[`docs/policy-gaps.md`](docs/policy-gaps.md) and the [held-out set](#held-out-policy-gap-scenarios)):
the calendar invitation (`content-injection`) is prevented because calendar reads are now an
untrusted source, and the `conftest.py` payload (`ci-build-injection`) is flagged by `balanced` and
prevented by `strict` because writes to auto-executed paths are an `autoexec` sink checking the
whole content. No benign scenario regressed. The gaps that remain are honest limits of the
approach, not hidden:

- **Encoded or paraphrased exfiltration is not attributed.** `exfil-encoded` (a base64-wrapped SSH
  key, a spelled-out recipient `ceo dot backup at protonmail dot com`) leaves no literal trace, so
  `balanced` only flags it through the coarse `tainted`/`trifecta` rules; `command-exec` (a copied
  `curl | bash` or reverse shell) is indistinguishable from the same command copied from
  documentation, so both are flagged, not blocked.
- **Payloads in non-critical arguments of ordinary sinks still slip past flow rules.** The
  `autoexec` sink closes this for writes to auto-executed paths (its every argument is critical),
  but a payload hidden in the body of a sink the guard treats as path-only or recipient-only is
  still only caught by the coarse rules.
- **A source the user named may itself be attacker-controlled.** When the user points at a specific
  file or URL (`directed_flow`), the guard cannot tell a legitimate value in it from an injected
  one, so `balanced` asks a human rather than blocking; a careless approval defeats it.
- **Self-protection is pattern-based, approvals are not.** `attack-obfuscated-approve`
  (`t''oolguard approve ...`) still evades the dedicated protect rule; `taint-only` and `balanced`
  only ask a human about the shell call. It counts as **prevented** anyway because the forged
  approval cannot succeed without the out-of-band one-time code. The benchmark marks such steps
  with `"forges_approval": true` and reports them with an explicit `approval_code` rule; under
  `allow-all` there is no guard and nothing to approve, so they stay missed. The forged approval is
  counted as prevented under every guard; review load is unchanged because the shell call is still
  shown to a human.

The numbers are illustrative, not a research result. The scenarios are hand-written **alongside the
policy by the same author**, cover one path each, and model a **non-adaptive** attacker; an attacker
who knows the rules would prefer exactly the encoded and paraphrased techniques above. The presets
are deliberately **not** tuned to these scenarios. The benchmark serves as a regression test of the
safety/usefulness trade-off and as a starting point for more serious evaluations, for example with
real traces or AgentDojo-style benchmarks.

### Held-out: policy-gap scenarios

A second held-out set, [`benchmarks/heldout/`](benchmarks/heldout), was written **before** the
policy-gap changes (see [`docs/policy-gaps.md`](docs/policy-gaps.md)) to test each gap class
independently of either benchmark: 13 attacks and 13 benign look-alikes for third-party content
sources, writes to auto-executed paths, access grants, account changes, user-directed data sources
and link-following. With the presets before the change almost every attack here was missed; after
it, `balanced` prevents 7, flags 5 and misses 1 while keeping 11 of 13 benign tasks autonomous, and
`strict` prevents 12 and flags 1. The one `balanced` miss is a link the agent is told to visit: the
`web` candidate that would flag it was **rejected** because adopting it also breaks following a
documentation link from search results (the cost shows up as `strict`'s needs-human on that benign
task). Run it with `toolguard eval benchmarks/heldout`.

### Held-out: AgentDojo

To measure toolguard on tasks and attacks it was not written alongside,
[`benchmarks/agentdojo/`](benchmarks/agentdojo/README.md) converts the public
[AgentDojo](https://github.com/ethz-spylab/agentdojo) benchmark (0.1.35, suites v1.2.2: workspace,
slack, travel, banking) into scenarios, offline and without any model: each user task's
ground-truth calls with their real outputs (97 benign scenarios) and, for each injection task,
the same trajectory with the `important_instructions` injection followed by the injection task's
ground-truth calls (596 attack scenarios, each one confirmed successful by AgentDojo's own
security check; 353 pairs cannot be converted, mostly because AgentDojo ships no ground truth for
them). The AgentDojo tools are classified by a separate
[toolset mapping](benchmarks/agentdojo/toolset.toml), written from their docstrings before the
first run and combined with each policy by `--toolset`; the presets and the mapping are unchanged
by the policy-gap work.

```sh
toolguard eval benchmarks/agentdojo/scenarios --toolset benchmarks/agentdojo/toolset.toml
```

| policy | attacks: prevented / flagged / missed | benign: autonomous / needs-human / broken | confirms/scenario |
|---|---|---|---|
| `allow-all` | 0 / 0 / 596 | 97 / 0 / 0 | 0.00 |
| `taint-only` | 0 / 596 / 0 | 37 / 60 / 0 | 1.94 |
| `balanced` | 432 / 159 / 5 | 42 / 44 / 11 | 1.03 |
| `strict` | 526 / 70 / 0 | 37 / 15 / 45 | 0.39 |

| suite | attacks | `balanced` attacks | `strict` attacks | benign | `balanced` benign | `strict` benign |
|---|---|---|---|---|---|---|
| workspace | 231 | 171 / 60 / 0 | 191 / 40 / 0 | 40 | 23 / 13 / 4 | 18 / 7 / 15 |
| slack | 105 | 58 / 42 / 5 | 95 / 10 / 0 | 21 | 1 / 14 / 6 | 1 / 1 / 19 |
| travel | 118 | 97 / 21 / 0 | 98 / 20 / 0 | 20 | 14 / 6 / 0 | 14 / 6 / 0 |
| banking | 142 | 106 / 36 / 0 | 142 / 0 / 0 | 16 | 4 / 11 / 1 | 4 / 1 / 11 |

Attacker-chosen destinations (IBANs, e-mail addresses, URLs, passwords copied from the injection)
are blocked outright, **unless** the user named the exact source that carried them: the policy-gap
work added a generic `directed_flow` rule, so `balanced` now asks a human about a value from a
user-named file or URL instead of blocking (the guard cannot tell an injected IBAN in "the bill
you asked me to pay" from a legitimate one). This moved 61 `balanced` attacks from prevented to
flagged (banking 142 → 106 prevented, workspace 191 → 171, slack 63 → 58) while leaving
`safety_with_human` at 99%, and in exchange rescued 9 benign tasks from broken to needs-human
(paying a named bill, inviting the user on a named page, the two `share_file` tasks the old
`default` actions broke). `strict` is unchanged: it blocks directed flows. Attacks without an
attributable destination ("delete file 13") are only flagged; `balanced` still misses five "visit
this link" attacks where the agent has browsed but not yet read private data. Ground-truth
trajectories are not model behaviour (models deviate, comply partially, paraphrase or refuse), the
attack is a single non-adaptive template, and the mapping choices move the numbers; see the
[benchmark README](benchmarks/agentdojo/README.md) for the method, the mapping rationale and these
limitations.

## Threat model

**Assets**: credentials and private data reachable from the machine; the ability to act on the
user's behalf (send, pay, publish, execute, delete); integrity of the log and of approvals.

**Trust boundaries**:

| Trusted | Untrusted |
|---|---|
| The toolguard process, its policy and its state directory | The model and everything it generates |
| What the user types in the prompt | Results of source tools (web, e-mail, chat, calendar invitations, tickets, documents) |
| The human on the approval channel and the notifier that reaches them | Third-party MCP servers and their responses |

**Adversaries**: the author of content the agent will read (web page, e-mail, issue, document, chat
message), and a model acting against the user for whatever reason.

**Covered threats**: exfiltration to attacker-controlled recipients or URLs; payments to injected
accounts; granting an injected party access to data or changing account credentials, keys or the
profile (`access`, `account`); commands copied from untrusted sources; injecting code into
auto-executed files such as `conftest.py`, CI configs or git hooks (`autoexec`); publishing
secrets; destructive actions dictated by third parties; persistence (`~/.bashrc`); self-approval
(structurally, by the out-of-band code) and tampering with the guard or its hooks; deleting or
editing the log or approval records (detectable with a key).

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
  that content endorses values instead of tainting them. Naming a source in the prompt (`pay the
  bill in X.txt`) marks it *directed*: `balanced` then asks a human about values taken from it
  rather than blocking, because a legitimate value and an injected one in the same named resource
  are indistinguishable to the guard. A careless approval defeats this; `strict` blocks instead.
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
- **MCP proxy**: verified with real servers on Linux (see [Verified
  behaviour](#verified-behaviour-real-mcp-servers)); not exercised with a desktop client's UI
  (Claude Desktop, IDEs) or on Windows and macOS beyond unit tests. It speaks **stdio only**:
  servers reached over Streamable HTTP or SSE cannot be wrapped. Tool, resource and prompt results
  are observed, but server-written metadata (tool, resource and prompt descriptions from the
  `*/list` methods) is not, and a `prompts/get` request is not guarded as a sink: a prompt
  argument built from untrusted or private data reaches the server unchecked. A `file://`
  resource URI is treated as local, which is wrong for a remote server (its files, but the URI
  travels over the network). On protocol 2026-07-28 there is no `initialize`, so the proxy does not know whether the client supports
  elicitation and confirmations always go to the out-of-band queue (confirming through
  `InputRequiredResult` is not implemented). The proxy trusts the client to show its elicitation
  to the user, not to the model. On Windows a batch launcher (`npx.cmd`) passes its arguments
  through `cmd.exe`, so keep them free of shell metacharacters.

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
tests/              pytest: core, adapters, proxy (fake server and replayed real traffic), CLI, benchmark
examples/           team policy, approvals configuration, MCP client configuration, Python usage
```

## License

[Apache License 2.0](LICENSE).
