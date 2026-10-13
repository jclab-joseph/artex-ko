# syntax=docker/dockerfile:1
#
# End-to-end runtime image for the Management ↔ Agent split test. Following this
# project's build philosophy, the Go binaries are cross-compiled on the host (pure Go,
# CGO disabled) and copied in — so this image needs no Go toolchain and no specific
# golang base tag. Run e2e/run.sh, which builds dist/ first.
#
# One image carries BOTH binaries (artex, artex-agent); docker-compose picks the role
# per service via `command`. The runtime tools (bash/curl/nmap) are here so the Agent
# can actually execute recon commands through Bash.
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates bash coreutils curl jq dnsutils netcat-openbsd nmap \
    && rm -rf /var/lib/apt/lists/*

# Paths are relative to the build context (the repo root; see compose `context: ..`).
COPY e2e/dist/artex /usr/local/bin/artex
COPY e2e/dist/artex-agent /usr/local/bin/artex-agent
COPY e2e/dist/mcpstub /usr/local/bin/mcpstub
COPY skills/ /app/skills/

WORKDIR /app
