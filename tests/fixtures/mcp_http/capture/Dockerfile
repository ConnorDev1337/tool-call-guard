# Throwaway image that runs real Streamable HTTP MCP servers behind the toolguard proxy (see
# ../README.md). Network is only available while the image is built; captures run with
# --network none (loopback only) as an unprivileged user, and toolguard itself is mounted
# read-only, so the image never contains it.
FROM node:22-bookworm-slim@sha256:c3de60bf2f9dd0ac6370e6117950ff62d6e339527e7472301c9c78a017978392 AS node
FROM python:3.13-slim-bookworm@sha256:a1165e272e578941b84abc79e4ab38a0305cd12803a5c4247979ac7655f4d641
COPY --from=node /usr/local/bin/node /usr/local/bin/node
COPY --from=node /usr/local/lib/node_modules /usr/local/lib/node_modules
RUN ln -s ../lib/node_modules/npm/bin/npm-cli.js /usr/local/bin/npm \
 && ln -s ../lib/node_modules/npm/bin/npx-cli.js /usr/local/bin/npx
# The TypeScript SDK reference server (Streamable HTTP with sessions and an event store).
RUN npm install -g --ignore-scripts --no-audit --no-fund \
      @modelcontextprotocol/server-everything@1.0.0
# The official Python SDK: the scripted client, and the servers in capture/mail_http_server.py.
RUN python -m venv /opt/client && /opt/client/bin/pip install -q --no-cache-dir mcp==2.3.0
RUN useradd -m driver
USER driver
WORKDIR /home/driver
