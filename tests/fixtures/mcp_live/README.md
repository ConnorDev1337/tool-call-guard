# Traffic captured from real MCP servers behind the proxy

Each JSON file here is one scenario recorded on 2026-10-17 with real MCP servers running behind
`toolguard mcp-proxy`, driven by the official Python SDK client or, for input the SDK never sends,
a minimal JSON-RPC client. [`tests/test_mcp_proxy_live.py`](../../test_mcp_proxy_live.py) replays
them through in-process proxies, so CI covers real protocol traffic without Docker.

## Components

| Component | Version | Role |
|---|---|---|
| `mcp` (Python SDK) | 2.3.0 | Client (`mcp.Client`, stdio); also runs `capture/mail_server.py` |
| `@modelcontextprotocol/server-everything` | 1.0.0 (TypeScript SDK 1.32.1) | Tools, prompts, resources, tasks, notifications, server requests |
| `@modelcontextprotocol/server-filesystem` | 1.0.0 (TypeScript SDK 1.32.1) | Text, media, secret-file source, `write_file` sink |
| `@modelcontextprotocol/server-memory` | 1.0.0 (TypeScript SDK 1.32.1) | `delete_entities` (destructive sink) |
| `mcp-server-fetch` | 2026.10.10 (`mcp` 1.30.0) | Web source and web sink |
| `mcp-server-git` | 2026.10.10 (`mcp` 1.30.0) | Passthrough on a server built on SDK 1.x |
| `capture/mail_server.py` | `mcp` 2.3.0 | Toy mail server; the only one that speaks protocol 2026-07-28 |

Node.js 22.23.3 and Python 3.13.16, from `node:22-bookworm-slim` and
`python:3.13-slim-bookworm` pinned by digest in [`capture/Dockerfile`](capture/Dockerfile).
[`index.json`](index.json) lists the versions reported at run time and what each scenario observed.

## Scenarios

| File | Servers | What it exercises |
|---|---|---|
| `handshake.json` | everything | SDK default connect: `server/discover` probe (2026-07-28), `-32601`, then `initialize` 2025-11-25 with `elicitation: {form, url}`; capability-gated tools appear; tools, prompts, resources (text and blob), templates, completion, subscribe, `logging/setLevel` |
| `tools.json` | everything | Echo, `structuredContent`, image, annotated content, resource links and embedded resources, `isError` for invalid arguments, progress, log notifications, server-initiated `elicitation/create`, `sampling/createMessage` and `roots/list` answered by the client through the proxy |
| `provenance.json` | fetch, memory, filesystem | One session across three proxies: a destructive call runs before any untrusted data; a page fetched from a loopback web server taints the session; deleting the entity it names is blocked and never reaches the server; following a link stays allowed; after a `.env` read the URL carrying its content is refused; a `conftest.py` write needs a human |
| `elicitation.json` | fetch, memory | Confirmations answered through MCP elicitation: accept runs the call, decline and cancel refuse it |
| `queue.json` | fetch, memory | No elicitation: the call is queued, the one-time code goes to a file notifier only, the operator runs `toolguard approve`, the retried call runs (an `oob` event marks the approval) |
| `tasks.json` | everything, memory | Task-augmented `tools/call` (`simulate-research-query`, `taskSupport: required`), `tasks/get`, `tasks/result`; with a policy that makes that tool a source, its result taints the session and a later delete is blocked |
| `protocol.json` | everything | 20 concurrent requests with integer and string ids, progress tokens, cancellation (no response), a line that is not JSON, malformed params, a line that is not valid UTF-8, a batch, then disconnect while a timer runs |
| `crash.json` | memory | Server killed with SIGKILL mid-session: the proxy exits with 137 and the client sees EOF at once |
| `git.json` | git | Plain passthrough to a server built on SDK 1.x |
| `modern.json` | toy mail server | Protocol 2026-07-28 end to end: per-request `_meta`, no `initialize`; an injected recipient is blocked and a confirmation fails closed to the queue |

The `large` scenario (a 1.16 MB text file and a 512 KiB image through the filesystem server) is
checked live but not kept: its summary is in `index.json`.

## Changes since the capture

The files are kept exactly as recorded. When an engine fix changes a refusal written by the
proxy, the replay replaces that refusal in memory and the test lists the new text and the reason
in `AMENDED` ([`test_mcp_proxy_live.py`](../../test_mcp_proxy_live.py)); `observed` in the
fixture and in `index.json` still shows what was seen at capture time.

| Scenario | Recorded | Replayed today | Why |
|---|---|---|---|
| `provenance` | `CONFIRM mcp__fetch__fetch` for the URL carrying the `.env` token | `BLOCK` (`private_flow`) | The page echoes its own URL, so the exfiltration URL's host was attributed to the page and that attribution hid the private flow of the token in its query. A private flow is now only explained away by an untrusted source that contains the same data |

## Format

```json
{"scenario": "...", "servers": ["..."], "policy": "balanced", "observed": {...},
 "events": [{"t": 0.0, "dir": "c2p", "server": "everything", "line": "{...}\n"}, ...]}
```

`dir` is `c2p` (client to proxy), `p2c`, `p2s` (proxy to server) or `s2p`; `client-eof`,
`server-eof`, `client-exit` and `server-exit` mark stdin closing and process exits (with `code`);
`oob` marks the operator's approval. `line` is the exact UTF-8 line and `b64` holds a line that is
not valid UTF-8. `t` is seconds from the first event; events are ordered by a clock shared by the
two taps of every proxy. Hidden characters are written as `\uXXXX` escapes.

## How the files were produced

All third-party code ran only in a throwaway container built from the pinned images and
packages (`npm install --ignore-scripts PACKAGE@VERSION`, `pip install PACKAGE==VERSION` in one
virtual environment per server). Network access was only available while the image was built;
captures ran as an unprivileged user with `--network none`. The web pages came from a server on
the container's loopback interface; no external service was contacted. toolguard was mounted
read-only from this checkout.

```bash
docker build --label agent-task=mcp-proxy-live -t mcp-proxy-live tests/fixtures/mcp_live/capture
docker run --rm --network none --label agent-task=mcp-proxy-live \
  -v "$PWD/src:/toolguard/src:ro" -v "$PWD/tests/fixtures/mcp_live/capture:/capture:ro" \
  -v "$PWD/out:/out" --tmpfs /work:uid=1000,gid=1000 \
  mcp-proxy-live /opt/client/bin/python /capture/driver.py /out
python tests/fixtures/mcp_live/capture/build.py out tests/fixtures/mcp_live
```

- [`capture/driver.py`](capture/driver.py) runs every scenario as
  `client <-> tap <-> toolguard mcp-proxy <-> tap <-> server` and checks its expectations; it
  exits non-zero if any fails. Pass scenario names after the output directory to run only those.
- [`capture/tap.py`](capture/tap.py) relays a process's stdio and logs each line with the shared
  monotonic clock.
- [`capture/build.py`](capture/build.py) merges the taps into one transcript per scenario and
  refuses to write one that names the capture host (container id or host paths).

Sanitization: the driver uses fixed git identities and dates, placeholder values
(`placeholder-token-...` in the `.env` file, `billing@evil-payments.example`) and container paths
(`/work`); no real account or secret was used. Random values (task ids, elicitation and approval
ids, timestamps in task metadata) are left as recorded; the replay maps the proxy's own random
ids.

## Server quirks found while capturing

- `mcp-server-fetch` refuses loopback and private addresses unless started with
  `--allow-private-ips`.
- With `node` on `PATH`, `mcp-server-fetch` (through `readabilipy`) runs `npm install` the first
  time it simplifies an HTML page, which hangs without network. The captures run it with
  `PATH=/usr/bin:/bin`, so `readabilipy` uses its Python extractor.
- `server-memory` writes next to its package by default; it ran with
  `MEMORY_FILE_PATH=/work/memory.jsonl`.
- `server-everything` keeps a timer running after `toggle-simulated-logging` and does not exit
  when its stdin closes; the proxy now terminates it (see `protocol.json`, exit code 143).
- The SDK 2.x client probes `server/discover` first; every reference server answers `-32601` and
  the client falls back to `initialize`.
