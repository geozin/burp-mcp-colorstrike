# Burp Mcp ColorStrike

> A Burp Suite MCP extension that enables AI-driven security analysis and offensive testing through a color-based triage workflow. Highlight requests in Burp Proxy History, then let the LLM analyze traffic by color group, identify attack vectors, and execute targeted payloads — all without leaving your chat interface.

A fork of [PortSwigger/mcp-server](https://github.com/PortSwigger/mcp-server) with a focus on manual penetration testing workflows.

---

## What's Different from the Original

### Color-Based Triage Workflow
Requests in Burp Proxy History are organized by highlight color. The LLM reads, groups and analyzes traffic by color — each color representing a different testing context or priority level.

### Three Read Levels
| Tool | Data | Purpose |
|:-----|:-----|:--------|
| `GetProxyHttpHistory` | Color-grouped summary — endpoint names, status codes, param names. No values, no body, no response. | Initial triage |
| `GetRequestsByColor` | Full request + response with token truncation and cookie collapsing | Group vulnerability analysis |
| `GetRequestByIndex` | 100% untruncated — full JWT, raw cookies, complete response | Surgical analysis / JWT attacks |

### Unified Attack Tool
`SendRequest` is the only tool that sends data to the target. It supports:
- **Explicit injection** via `injectAt` — `"body:param"`, `"query:param"`, `"header:Name"`, `"method"`, `"path"`
- **Marker injection** — place `{{payload}}` anywhere in the request
- **Auto injection** — JWT/Bearer auto-routes to Authorization header; fallback to last path segment
- **Differential analysis** — adaptive response output: size/status diff detection, body preview when uniform
- **Delay control** — `delaySeconds` for time-based SQLi calibration

### Real Baseline Timing
Every item in history shows `[baseline: Xms]` — the real latency captured by Burp at intercept time. Used to calibrate time-based SQLi attacks against real response times, not estimated values.

### Persistent Item IDs
Uses `ProxyHttpRequestResponse.id()` — the native Burp ID that matches the `#` column in Proxy History UI and **does not reset after history clear**.

### Backend Sanitization
Automatic pipeline on all history reads:
- JWT/Bearer tokens truncated (`eyJ...[JWT TRUNCATED]`, `Bearer [TOKEN TRUNCATED]`)
- Cookies collapsed (`[N cookies, session=abc123de...]`)
- SVG / base64 / ViewState replaced with `[TRUNCATED]`
- Static extensions filtered (images, fonts, CSS, JS, media, binaries)
- Items > 10,000 chars truncated

---

## Tools

| Tool | Parameters | Usage |
|:-----|:-----------|:------|
| `GetProxyHttpHistory` | `count`, `offset` | Overview / triage — color-grouped summary |
| `GetProxyHttpHistoryRegex` | `regex`, `count`, `offset` | Search specific content in highlighted items |
| `GetRequestsByColor` | `colors[]`, `count`, `offset` | Full analysis of a color group |
| `GetRequestByIndex` | `index` | Deep analysis — full token, no truncation |
| `SendRequest` | `index`, `payloads[]?`, `numberOfRequests?`, `delaySeconds?`, `injectAt?` | Only attack tool |
| `CreateRepeaterTab` | `index`, `tabName?`, `payload?`, `injectAt?` | Send to Repeater by index |
| `SendToIntruder` | `index`, `tabName?`, `payload?`, `injectAt?` | Send to Intruder by index |
| `GetProxyWebsocketHistory` | `count`, `offset` | WebSocket history |
| `GetProxyWebsocketHistoryRegex` | `regex`, `count`, `offset` | Filter WebSocket by regex |
| `GenerateCollaboratorPayload` | `customData?` | Generate OOB payload for SSRF/Blind/DNS *(Pro only)* |
| `GetCollaboratorInteractions` | `payloadId?` | Query Collaborator callbacks *(Pro only)* |
| `UrlEncode` / `UrlDecode` | `content` | URL encode/decode |
| `Base64Encode` / `Base64Decode` | `content` | Base64 encode/decode |
| `SetProxyInterceptState` | `intercepting: Boolean` | Toggle proxy interception |

---

## Workflow

```
1. Browse target with Burp intercepting
2. Highlight interesting requests with colors in Proxy History
   🔴 RED    — critical / high priority
   🟧 ORANGE — interesting / needs testing  
   🟨 YELLOW — low priority / informational
   🟩 GREEN  — confirmed safe / baseline
   🟦 BLUE   — authentication flows
   🟪 MAGENTA — business logic
   🩷 PINK   — parameters / injection points

3. Connect LLM via MCP
4. LLM reads history → groups by color → identifies attack vectors
5. LLM presents CHECKPOINT with payloads before any request is sent
6. You approve [Y/N] → LLM fires SendRequest → analyzes differential response
```

---

## System Prompt

A purpose-built system prompt (`prompt_v20.md`) drives the LLM through a structured workflow:

- **Hard trigger** — first character of response is the tool call
- **Zero-data policy** — never fabricates endpoints, CVEs or vulnerabilities
- **Passive analysis modules** — Tech Stack, Decode & Parsing, Defensive Posture, Business Logic & PII, Technical Diagnosis, Full Attack Surface, Attack Plan
- **Prior authorization protocol** — mandatory CHECKPOINT before every `SendRequest`
- **Attack arsenal** — 33 vectors from SQLi to API-Specific attacks
- **Military output format** — structured, surgical, no walls of text

---

## Installation

### Prerequisites

- Java available in PATH (`java --version`)
- `jar` command available in PATH (`jar --version`)

### Build

```bash
git clone https://github.com/youruser/burp-mcp-ColorStrike.git
cd burp-mcp-ColorStrike
./gradlew embedProxyJar
```

Output: `build/libs/burp-mcp-all.jar`

### Load in Burp Suite

1. Extensions tab → Add
2. Extension Type: Java
3. Select `burp-mcp-all.jar`
4. Click Next

### Connect Your LLM Client

**SSE (direct):**
```
http://127.0.0.1:9876
```

**Stdio proxy (Claude Desktop):**
```json
{
  "mcpServers": {
    "burp": {
      "command": "<path to Java packaged with Burp>",
      "args": [
        "-jar",
        "/path/to/mcp-proxy-all.jar",
        "--sse-url",
        "http://127.0.0.1:9876"
      ]
    }
  }
}
```

---

## Configuration

In the **MCP tab** within Burp Suite:

- **Enabled** — toggle the MCP server on/off
- **Enable tools that can edit your config** — exposes config editing tools
- **Host / Port** — default `127.0.0.1:9876`

---

## Key Differences from PortSwigger/mcp-server

| Feature | Original | ColorStrike |
|:--------|:---------|:------------|
| History filter | Scope-based | Highlight color (no scope required) |
| Item indexing | `mapIndexed` position | Native `ProxyHttpRequestResponse.id()` — persistent |
| JWT handling | Truncated everywhere | Full token via `GetRequestByIndex` |
| Attack tool | `SendRequest` basic | Unified injection engine with 5 injection modes |
| Timing | Not exposed | `[baseline: Xms]` on every item |
| Differential analysis | None | Size/status diff detection + body preview |
| System prompt | None | `prompt_v20.md` — 33 attack vectors, checkpoint protocol |
| Scanner issues | Included | Removed — manual workflow only |

---

## Credits

Fork of [PortSwigger/mcp-server](https://github.com/PortSwigger/mcp-server).  
MCP protocol: [modelcontextprotocol.io](https://modelcontextprotocol.io/)
