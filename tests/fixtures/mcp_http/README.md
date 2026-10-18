# Streamable HTTP traffic captured from real MCP servers behind the proxy

Each JSON file here is one scenario recorded on 2026-10-18 with real MCP servers behind
`toolguard mcp-proxy --listen`, driven by the official Python SDK client over Streamable HTTP or,
for input the SDK never sends, raw `http.client` requests.
[`tests/test_mcp_http_live.py`](../../test_mcp_http_live.py) replays them through an in-process
proxy, so CI covers real HTTP traffic without Docker.

## Components

| Component | Version | Role |
|---|---|---|
| `mcp` (Python SDK) | 2.3.0 (uvicorn 0.54.0, Starlette 1.9.0) | Client (`mcp.Client` over Streamable HTTP); also serves `capture/mail_http_server.py` |
| `@modelcontextprotocol/server-everything` | 1.0.0 (TypeScript SDK 1.32.1) | `streamableHttp` (sessions, event store) and `stdio` behind the HTTP front |
| `capture/mail_http_server.py` | `mcp` 2.3.0 | Toy mail server: sessions with resumable SSE, stateless JSON, protocol 2026-07-28 |

Node.js 22.23.3 and Python 3.13.16, from `node:22-bookworm-slim` and
`python:3.13-slim-bookworm` pinned by digest in [`capture/Dockerfile`](capture/Dockerfile).
[`index.json`](index.json) lists the versions reported at run time and what each scenario observed.

## Scenarios

| File | Server | What it exercises |
|---|---|---|
| `everything.json` | server-everything `streamableHttp` | SDK default connect: `server/discover` probe answered with an error, `initialize` 2025-11-25, session id, GET stream, priming events, SSE responses, progress, log notifications, server-initiated `elicitation/create` and `sampling/createMessage` answered by POST, resources, templates and prompts observed, `DELETE` on close |
| `mail_legacy.json` | mail server (sessions, SSE) | `Authorization` passed through to the server and kept out of the audit log; an injected recipient blocked; confirmations through elicitation on the request's own stream (accept runs the call, decline refuses it); a `resources/read` whose `https://` URI carries a secret read elsewhere in the session is blocked (`-32003`), a private value in a `mail://` URI needs a human; a server elicitation passes through; a response stream closed by the server and resumed with `GET` and `Last-Event-ID` still has its result observed |
| `mail_modern.json` | mail server | Protocol 2026-07-28: no `initialize` and no session, `Mcp-Method` and `Mcp-Name` headers checked against the body and passed on, refusals with `resultType`, a confirmation that fails closed to the approval queue |
| `mail_stateless.json` | mail server (`--stateless --json`) | No session id, plain JSON bodies, an injected recipient blocked |
| `protocol.json` | mail server | Raw requests: foreign `Origin` (403) and `Host` (421), wrong path (404) and content type (415), invalid JSON and batches (400), a 5 MiB body announced (413, refused before it is read), `PUT` (405), `Mcp-Name` contradicting the body (400, `-32020`), malformed `tools/call` params (400), an unknown session and a session after `DELETE` (the server's 404) |
| `stdio_front.json` | server-everything `stdio` behind `--listen` | The proxy as the Streamable HTTP server of a stdio process: it issues the session id, routes progress and server requests to the POST that caused them and log messages to the GET stream |

## Format

```json
{"scenario": "...", "transport": "http-upstream", "server_name": "mail", "policy": "balanced",
 "setup": [...], "observed": {...}, "events": [{"t": 0.0, "dir": "c2p", "conn": 1, "seq": 0,
 "request": {"method": "POST", "target": "/mcp", "headers": [...], "body": "..."}}, ...]}
```

`dir` is `c2p` (client to proxy), `p2c`, `p2u` (proxy to upstream), `u2p`, or `p2s` and `s2p`
for the stdio server of the HTTP front (`line` as in the stdio captures). HTTP events carry the
TCP connection (`conn`) and the request's position on it (`seq`), and one of `request`,
`response` (status and headers), `event` (one server-sent event: `id`, `event`, `retry`, `data`,
or `comment`), `body`, `end` (the response is complete), `abort` (the connection closed first) or
`eof` (that side stopped sending). `t` is seconds from the first event on the clock shared by
the taps. `setup` lists what the scenario recorded in the session before the traffic (a `.env`
read by another integration of the same agent). Hidden characters are written as `\uXXXX`
escapes.

## How the files were produced

All third-party code ran only in a throwaway container built from the pinned images and
packages (`npm install --ignore-scripts PACKAGE@VERSION`, `pip install mcp==2.3.0` in one virtual
environment). Network access was only available while the image was built; captures ran as an
unprivileged user with `--network none`, every server and proxy listening on the container's
loopback interface. No external service was contacted. toolguard and the stdio tap were mounted
read-only from this checkout.

```bash
docker build --label agent-task=mcp-http-live -t mcp-http-live tests/fixtures/mcp_http/capture
docker run --rm --network none --label agent-task=mcp-http-live \
  -v "$PWD/src:/toolguard/src:ro" -v "$PWD/tests/fixtures/mcp_http/capture:/capture:ro" \
  -v "$PWD/tests/fixtures/mcp_live/capture:/stdio-capture:ro" \
  -v "$PWD/out:/out" --tmpfs /work:uid=1000,gid=1000 \
  mcp-http-live /opt/client/bin/python /capture/driver.py /out
python tests/fixtures/mcp_http/capture/build.py out tests/fixtures/mcp_http
```

- [`capture/driver.py`](capture/driver.py) runs every scenario as
  `client <-> TCP tap <-> toolguard mcp-proxy --listen <-> TCP tap <-> server` (or a stdio tap and
  a stdio server for the HTTP front) and checks its expectations; it exits non-zero if any fails.
- [`capture/tcptap.py`](capture/tcptap.py) relays TCP connections and logs every chunk with the
  shared monotonic clock.
- [`capture/build.py`](capture/build.py) parses the logs as HTTP/1.1, merges them into one
  transcript per scenario and refuses to write one that names the capture host.

Sanitization: placeholder values only (`placeholder-token-...` in the `.env` content,
`Bearer placeholder-bearer-...`, which no server checks, `billing@evil-payments.example`) and
container paths (`/work`). Session ids, event ids and dates are left as recorded; the replay maps
the random values the proxy creates (elicitation ids, approval ids, the session ids of its stdio
front).

## Found while capturing

- A request refused before its body was read (bad `Origin`, oversized body) left the body in the
  connection, and the next request on it was parsed from those bytes and answered with an HTML
  400. Refusals now close the connection.
- Upstream `Date` and `Server` headers were relayed next to the proxy's own.
- The Python SDK client closes a resumed stream as soon as it has the response, while the proxy
  keeps relaying it until the server ends it or a write fails (here, at `DELETE`).
- The TypeScript reference server sends a priming event (an `id` with empty `data`) at the start
  of every POST stream; the proxy relays it so the client can resume.
