# Throwaway image that runs real MCP servers behind the toolguard proxy (see ../README.md).
# Network is only available while the image is built; captures run with --network none and
# toolguard itself is mounted read-only, so the image never contains it.
FROM node:22-bookworm-slim@sha256:c3de60bf2f9dd0ac6370e6117950ff62d6e339527e7472301c9c78a017978392 AS node
FROM python:3.13-slim-bookworm@sha256:a1165e272e578941b84abc79e4ab38a0305cd12803a5c4247979ac7655f4d641
COPY --from=node /usr/local/bin/node /usr/local/bin/node
COPY --from=node /usr/local/lib/node_modules /usr/local/lib/node_modules
RUN ln -s ../lib/node_modules/npm/bin/npm-cli.js /usr/local/bin/npm \
 && ln -s ../lib/node_modules/npm/bin/npx-cli.js /usr/local/bin/npx
RUN npm install -g --ignore-scripts --no-audit --no-fund \
      @modelcontextprotocol/server-everything@1.0.0 \
      @modelcontextprotocol/server-filesystem@1.0.0 \
      @modelcontextprotocol/server-memory@1.0.0
RUN for p in fetch git; do \
      python -m venv /opt/$p && /opt/$p/bin/pip install -q --no-cache-dir mcp-server-$p==2026.10.10 \
      || exit 1; \
    done
# The scripted client: the official Python SDK, in its own environment.
RUN python -m venv /opt/client && /opt/client/bin/pip install -q --no-cache-dir mcp==2.3.0
RUN apt-get update -qq && apt-get install -y -qq --no-install-recommends git >/dev/null \
 && rm -rf /var/lib/apt/lists/*
RUN useradd -m driver
USER driver
WORKDIR /home/driver
