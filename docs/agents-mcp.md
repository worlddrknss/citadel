# Connecting MCP clients to Citadel

Citadel 2.2 runs a [Model Context Protocol](https://modelcontextprotocol.io)
server at `https://<your-citadel>/mcp`. An AI agent connected to it can list
the credentials it has been granted and make HTTP requests with them
(`list_credentials`, `http_request`, and `reveal_credential` when the agent
has a `reveal` grant) without ever holding the secret values.

The agent authenticates with an **agent token** (`cagt_...`), created in the
console under **Agents**. Each MCP client connection acts as that agent, with
only the grants you gave it. Console sessions and IAM access keys aren't
accepted at `/mcp`.

There are two ways to connect:

- **HTTP direct (preferred).** The client talks Streamable HTTP to `/mcp` and
  sends the token in an `Authorization` header. Use this when the client
  supports remote servers with custom headers: Claude Code, Cursor and VS
  Code do.
- **stdio bridge.** For clients that only start local (stdio) servers, such as
  Claude Desktop, the TypeScript SDK ships a bridge:
  `npx -y @worlddrknss/citadel mcp`. It needs Node.js 20 or later and forwards
  every message to `/mcp`.

In the examples, replace `https://citadel.example.com` with your Citadel URL.

## Keep the token out of files you share

The token is a secret. Prefer the client's environment variable or prompt
support (shown below) over pasting it into a config file, and never commit it
to a repository. If a token leaks, revoke it in the console; suspending the
agent stops all its tokens at once.

## Claude Code

### HTTP direct

Export the token in the shell that runs `claude`, then add the server:

```sh
export CITADEL_AGENT_TOKEN=cagt_...
claude mcp add --transport http citadel https://citadel.example.com/mcp \
  --header "Authorization: Bearer ${CITADEL_AGENT_TOKEN}"
```

`claude mcp add` stores the expanded header in your Claude Code settings. To
keep the token out of the file, add the server to the project's `.mcp.json`
instead; Claude Code expands `${VAR}` when it starts:

```json
{
  "mcpServers": {
    "citadel": {
      "type": "http",
      "url": "https://citadel.example.com/mcp",
      "headers": { "Authorization": "Bearer ${CITADEL_AGENT_TOKEN}" }
    }
  }
}
```

### stdio bridge

```sh
claude mcp add citadel --env CITADEL_URL=https://citadel.example.com \
  -- npx -y @worlddrknss/citadel mcp
```

The bridge reads `CITADEL_AGENT_TOKEN` from the environment Claude Code passes
to it, so export it before starting `claude` (or add
`--env CITADEL_AGENT_TOKEN=cagt_...`, which stores it in the settings file).

Check the connection with `claude mcp list`, or `/mcp` inside a session.

## Claude Desktop

Claude Desktop starts local servers from `claude_desktop_config.json`
(**Settings → Developer → Edit Config**). Use the stdio bridge:

```json
{
  "mcpServers": {
    "citadel": {
      "command": "npx",
      "args": ["-y", "@worlddrknss/citadel", "mcp"],
      "env": {
        "CITADEL_URL": "https://citadel.example.com",
        "CITADEL_AGENT_TOKEN": "cagt_..."
      }
    }
  }
}
```

Restart Claude Desktop after editing the file. Claude Desktop starts servers
without your shell's environment, so the token has to be written into this
file; keep it private to your user.

## Cursor

Cursor reads `~/.cursor/mcp.json` (all projects) or `.cursor/mcp.json` (one
project) and expands `${env:NAME}`.

### HTTP direct

```json
{
  "mcpServers": {
    "citadel": {
      "url": "https://citadel.example.com/mcp",
      "headers": { "Authorization": "Bearer ${env:CITADEL_AGENT_TOKEN}" }
    }
  }
}
```

### stdio bridge

```json
{
  "mcpServers": {
    "citadel": {
      "command": "npx",
      "args": ["-y", "@worlddrknss/citadel", "mcp"],
      "env": {
        "CITADEL_URL": "https://citadel.example.com",
        "CITADEL_AGENT_TOKEN": "${env:CITADEL_AGENT_TOKEN}"
      }
    }
  }
}
```

Cursor must be started from an environment where `CITADEL_AGENT_TOKEN` is set.

## VS Code

VS Code (GitHub Copilot agent mode) reads `.vscode/mcp.json` in the workspace,
or the user-level MCP configuration (**MCP: Open User Configuration**). An
`inputs` entry prompts for the token once and stores it securely, so it never
appears in the file.

### HTTP direct

```json
{
  "inputs": [
    { "type": "promptString", "id": "citadel-token", "description": "Citadel agent token", "password": true }
  ],
  "servers": {
    "citadel": {
      "type": "http",
      "url": "https://citadel.example.com/mcp",
      "headers": { "Authorization": "Bearer ${input:citadel-token}" }
    }
  }
}
```

### stdio bridge

```json
{
  "inputs": [
    { "type": "promptString", "id": "citadel-token", "description": "Citadel agent token", "password": true }
  ],
  "servers": {
    "citadel": {
      "type": "stdio",
      "command": "npx",
      "args": ["-y", "@worlddrknss/citadel", "mcp"],
      "env": {
        "CITADEL_URL": "https://citadel.example.com",
        "CITADEL_AGENT_TOKEN": "${input:citadel-token}"
      }
    }
  }
}
```

## The stdio bridge

```text
citadel mcp [--url <url>] [--token-env <name>]
```

| Setting | Meaning |
| --- | --- |
| `--url` or `CITADEL_URL` | Citadel's base URL. The bridge appends `/mcp` (a URL already ending in `/mcp` is used as is). It must be `https`; plain `http` is accepted only for `localhost` and loopback addresses. |
| `CITADEL_AGENT_TOKEN` | The agent token. `--token-env NAME` reads it from another variable, for example to run two bridges as different agents. There is no `--token` flag: command lines are visible to other users of the machine. |
| `CITADEL_CA_FILE` | A PEM file with an extra CA certificate to trust, for a Citadel behind a private CA. The bridge starts Node again with `NODE_EXTRA_CA_CERTS` set to this file (setting `NODE_EXTRA_CA_CERTS` yourself works too). The CA is added to the trusted set; TLS verification is never turned off. |

How it behaves:

- It reads one JSON-RPC 2.0 message per line on stdin and POSTs each to
  `/mcp` with `Accept: application/json, text/event-stream` and the token as
  a Bearer credential. Replies, whether a JSON body or a server-sent event
  stream, are written to stdout, one message per line. Notifications get no
  reply (Citadel answers them with `202 Accepted`).
- It carries the `Mcp-Session-Id` that Citadel returns from `initialize`, and
  the negotiated `MCP-Protocol-Version`, on every later request. Messages that
  arrive while `initialize` is in flight wait for it.
- If Citadel can't be reached or answers with an HTTP error, the client gets a
  JSON-RPC error for that request: code `-32000` (with `data.httpStatus` for
  HTTP errors), or `-32001` when the session has expired, in which case
  restart the client to reconnect. Malformed input lines get `-32700`
  (parse error) or `-32600` (invalid request).
- stdout carries protocol messages only. Diagnostics go to stderr, and the
  token is never printed.
- When stdin closes, the bridge waits for outstanding replies, ends the
  session with an HTTP `DELETE /mcp`, and exits. It also does this on
  SIGINT, SIGTERM and SIGHUP.

The bridge doesn't open the optional GET stream for server-initiated
messages, and it doesn't resume broken event streams; Citadel's tools reply
on the POST that called them.

## Troubleshooting

- **`Citadel rejected the agent token (HTTP 401)`**: the token is wrong,
  expired or revoked, or the agent is suspended. Check the agent in the
  console.
- **`Cannot reach Citadel`**: check the URL and network. The bridge's stderr
  (Claude Code: `claude --debug`; Claude Desktop: the MCP log files) shows the
  underlying error, such as a certificate problem; for a private CA, set
  `CITADEL_CA_FILE`.
- **A tool is missing**: tools follow the agent's grants. `reveal_credential`
  appears only when the agent has a `reveal` grant.
