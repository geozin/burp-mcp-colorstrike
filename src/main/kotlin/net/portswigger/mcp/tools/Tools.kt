package net.portswigger.mcp.tools

import burp.api.montoya.MontoyaApi
import burp.api.montoya.collaborator.InteractionFilter
import burp.api.montoya.core.BurpSuiteEdition
import burp.api.montoya.http.HttpMode
import burp.api.montoya.http.HttpService
import burp.api.montoya.http.message.HttpHeader
import burp.api.montoya.http.message.requests.HttpRequest
import io.modelcontextprotocol.kotlin.sdk.server.Server
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonPrimitive
import net.portswigger.mcp.config.McpConfig
import net.portswigger.mcp.schema.toSerializableForm
import net.portswigger.mcp.security.HistoryAccessSecurity
import net.portswigger.mcp.security.HistoryAccessType
import net.portswigger.mcp.security.HttpRequestSecurity
import java.util.regex.Pattern

// =============================================================================
// GLOBAL HELPERS
// =============================================================================

private suspend fun checkHistoryPermissionOrDeny(
    accessType: HistoryAccessType, config: McpConfig, api: MontoyaApi, logMessage: String
): Boolean {
    val allowed = HistoryAccessSecurity.checkHistoryAccessPermission(accessType, config)
    if (!allowed) {
        api.logging().logToOutput("MCP $logMessage access denied")
        return false
    }
    return true
}

private fun truncateIfNeeded(serialized: String): String {
    return if (serialized.length > 10000) {
        serialized.substring(0, 10000) + "... (truncated)"
    } else {
        serialized
    }
}

// =============================================================================
// STATIC EXTENSIONS FILTER (CENTRALIZED)
// =============================================================================

/**
 * Single set of static extensions filtered across ALL tools.
 */
private val STATIC_EXTENSIONS = setOf(
    // --- Imagens ---
    ".jpg", ".jpeg", ".png", ".gif", ".webp", ".svg", ".ico", ".bmp",
    ".tiff", ".tif", ".avif", ".heic", ".heif", ".jfif", ".pjpeg", ".pjp",
    ".apng", ".cur",

    // --- Fonts ---
    ".woff", ".woff2", ".ttf", ".otf", ".eot",

    // --- CSS / JS ---
    ".css", ".js", ".mjs", ".cjs",

    // --- Source maps ---
    ".map", ".css.map", ".js.map",

    // --- Media (audio/video) ---
    ".mp3", ".mp4", ".webm", ".ogg", ".ogv", ".oga", ".wav", ".flac",
    ".aac", ".m4a", ".m4v", ".avi", ".mov", ".mkv", ".wmv",

    // --- Documents / generic binaries ---
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".zip", ".gz", ".tar", ".rar", ".7z", ".bz2", ".xz",
    ".exe", ".dll", ".so", ".dylib", ".bin", ".dmg", ".msi", ".deb", ".rpm",

    // --- Other common statics ---
    ".swf", ".flv",
    ".manifest", ".webmanifest",
    ".wasm",

    // --- Proprietary documents ---
    ".wpd"
)

private fun isStaticUrl(url: String): Boolean {
    val lower = url.lowercase()
    val path = lower.substringBefore('?').substringBefore('#')
    return STATIC_EXTENSIONS.any { path.endsWith(it) }
}

// =============================================================================
// FILTERED HISTORY WITH ORIGINAL BURP INDEX
// =============================================================================

/**
 * Loads a history item with its real index in Burp Suite.
 * The burpIndex corresponds exactly to the number shown in the "#" column of Burp Proxy History.
 */
private data class IndexedProxyItem(
    val burpIndex: Int,
    val item: burp.api.montoya.proxy.ProxyHttpRequestResponse
)

/**
 * Returns the filtered HTTP history applying ALL criteria:
 *   1. Must have highlight (any color other than NONE) — items without highlight are ignored
 *   2. URL must not be a static extension
 *
 * burpIndex from .id() — real Burp ID, persistent across history clears.
 * Returned in reverse order (most recent first), preserving the original burpIndex.
 */
private fun getFilteredHttpHistory(api: MontoyaApi): List<IndexedProxyItem> {
    val history = api.proxy().history()
    return history
        .filter { reqRes ->
            val highlight = reqRes.annotations().highlightColor()
            val hasHighlight = highlight != null && highlight != burp.api.montoya.core.HighlightColor.NONE
            hasHighlight && !isStaticUrl(reqRes.finalRequest().url())
        }
        .map { reqRes -> IndexedProxyItem(reqRes.id(), reqRes) }  // .id() = real Burp #, persistent across history clears
        .sortedByDescending { it.burpIndex }
}

// =============================================================================
// NOISE FILTER
// =============================================================================

private fun removeVisualNoise(json: String): String {
    var cleaned = json
    val svgRegex = Regex("""(?i)<svg[\s\S]*?(?:</svg>|<\\/svg>|<\\\\/svg>)""")
    cleaned = cleaned.replace(svgRegex, "<svg>...[TRUNCATED SVG]...</svg>")
    val base64Regex = Regex("""(?i)data:image/[a-zA-Z0-9+.-]+;base64,[a-zA-Z0-9+/=]+""")
    cleaned = cleaned.replace(base64Regex, "data:image/...;base64,[TRUNCATED BASE64]")
    val viewStateRegex = Regex("""(?i)("__VIEWSTATE"\s*(?::|value=)\s*\\?")[a-zA-Z0-9+/=]+\\?"""")
    cleaned = cleaned.replace(viewStateRegex, "$1[TRUNCATED VIEWSTATE]\"")
    return cleaned
}

// =============================================================================
// JWT / TOKEN TRUNCATION
// =============================================================================

/**
 * Truncates JWTs and tokens to avoid context pollution.
 * Patterns covered:
 *   - Full JWT:    eyJ[header].[payload].[signature]  → eyJ...[JWT TRUNCATED]
 *   - Bearer token: Bearer <value>                    → Bearer [TOKEN TRUNCATED]
 *   - Authorization with non-Bearer token (Basic, etc.) → preserves scheme, truncates value
 */
private fun truncateTokens(text: String): String {
    var result = text

    // 3-part JWT (header.payload.signature) — covers any field, not just Authorization
    val jwtRegex = Regex("""eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+""")
    result = result.replace(jwtRegex, "eyJ...[JWT TRUNCATED]")

    // 2-part JWT (unsigned, e.g. unsigned JWS)
    val jwtUnsignedRegex = Regex("""eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]{20,}""")
    result = result.replace(jwtUnsignedRegex, "eyJ...[JWT TRUNCATED]")

    // Bearer <token> em qualquer header ou campo
    val bearerRegex = Regex("""(?i)(Bearer\s+)[A-Za-z0-9_\-\.~+/]+=*""")
    result = result.replace(bearerRegex) { mr -> "${mr.groupValues[1]}[TOKEN TRUNCATED]" }

    // Authorization: Basic/Digest/NTLM/AWS4-HMAC etc. (anything non-Bearer already handled above)
    val authSchemeRegex = Regex("""(?i)(Authorization:\s*(?!Bearer)[A-Za-z0-9_-]+\s+)[^\s"\\,]{16,}""")
    result = result.replace(authSchemeRegex) { mr -> "${mr.groupValues[1]}[TOKEN TRUNCATED]" }

    return result
}

// =============================================================================
// COOKIE COLLAPSE
// =============================================================================

private fun collapseCookiesInJson(json: String): String {
    return try {
        val obj = Json.parseToJsonElement(json).jsonObject.toMutableMap()

        fun collapseHeaderList(
            headers: List<kotlinx.serialization.json.JsonElement>,
            headerName: String
        ): List<kotlinx.serialization.json.JsonElement> {
            return headers.map { h ->
                val hObj = h.jsonObject.toMutableMap()
                val name = hObj["name"]?.jsonPrimitive?.content ?: return@map h
                if (!name.equals(headerName, ignoreCase = true)) return@map h
                val value = hObj["value"]?.jsonPrimitive?.content ?: return@map h

                val isSetCookie = headerName.equals("Set-Cookie", ignoreCase = true)
                val cookies = if (isSetCookie) {
                    listOf(value.split(';').first().trim()).filter { it.isNotEmpty() }
                } else {
                    value.split(';').map { it.trim() }.filter { it.isNotEmpty() }
                }
                val count = cookies.size
                val session = cookies.firstOrNull { c ->
                    val cname = c.split('=').first().lowercase()
                    cname.contains("session") || cname.contains("sess") ||
                    cname.contains("auth") || cname.contains("token")
                }
                val collapsed = if (session != null) {
                    val parts = session.split('=', limit = 2)
                    val cname = parts[0]
                    val shortVal = parts.getOrElse(1) { "" }.take(8)
                    "[$count cookies, $cname=$shortVal...]"
                } else {
                    "[$count cookies]"
                }
                kotlinx.serialization.json.buildJsonObject {
                    hObj.forEach { (k, v) -> if (k != "value") put(k, v) }
                    put("value", kotlinx.serialization.json.JsonPrimitive(collapsed))
                }
            }
        }

        val reqHeaders = obj["request"]?.jsonObject?.get("headers")?.jsonArray?.toList()
        if (reqHeaders != null) {
            val collapsed = collapseHeaderList(reqHeaders, "Cookie")
            val req = obj["request"]!!.jsonObject.toMutableMap()
            req["headers"] = JsonArray(collapsed)
            obj["request"] = JsonObject(req)
        }

        val respHeaders = obj["response"]?.jsonObject?.get("headers")?.jsonArray?.toList()
        if (respHeaders != null) {
            val collapsed = collapseHeaderList(respHeaders, "Set-Cookie")
            val resp = obj["response"]!!.jsonObject.toMutableMap()
            resp["headers"] = JsonArray(collapsed)
            obj["response"] = JsonObject(resp)
        }

        Json.encodeToString(kotlinx.serialization.json.JsonObject.serializer(), JsonObject(obj))
    } catch (e: Exception) {
        json
    }
}

// =============================================================================
// HIGHLIGHT COLOR LABEL
// =============================================================================

private fun highlightLabel(item: burp.api.montoya.proxy.ProxyHttpRequestResponse): String {
    return when (item.annotations().highlightColor()) {
        burp.api.montoya.core.HighlightColor.RED    -> "RED"
        burp.api.montoya.core.HighlightColor.ORANGE -> "ORANGE"
        burp.api.montoya.core.HighlightColor.YELLOW -> "YELLOW"
        burp.api.montoya.core.HighlightColor.GREEN  -> "GREEN"
        burp.api.montoya.core.HighlightColor.CYAN   -> "CYAN"
        burp.api.montoya.core.HighlightColor.BLUE   -> "BLUE"
        burp.api.montoya.core.HighlightColor.PINK   -> "PINK"
        burp.api.montoya.core.HighlightColor.MAGENTA -> "MAGENTA"
        else                                         -> "HIGHLIGHT"
    }
}

// =============================================================================
// GROUPER
// =============================================================================

private data class HistoryGroup(
    val statusCounts: MutableMap<Int, Int> = mutableMapOf(),
    val queryParams: MutableSet<String> = mutableSetOf()
)

private fun summarizeHistory(items: List<String>): String {
    val groups = sortedMapOf<String, HistoryGroup>()

    for (itemJson in items) {
        try {
            val obj = Json.parseToJsonElement(itemJson).jsonObject
            val reqStr = obj["request"]?.jsonPrimitive?.content ?: continue
            val resStr = obj["response"]?.jsonPrimitive?.content ?: continue

            val reqFirstLine = reqStr.substringBefore("\r\n").substringBefore("\n")
            val reqParts = reqFirstLine.split(" ")
            val method  = reqParts.getOrElse(0) { "GET" }
            val rawPath = reqParts.getOrElse(1) { "/" }
            val path    = rawPath.substringBefore('?')
            val key     = "$method $path"

            val resFirstLine = resStr.substringBefore("\r\n").substringBefore("\n")
            val status = resFirstLine.split(" ").getOrNull(1)?.toIntOrNull() ?: 0

            val group = groups.getOrPut(key) { HistoryGroup() }
            group.statusCounts[status] = (group.statusCounts[status] ?: 0) + 1

            val qs = rawPath.substringAfter('?', "")
            if (qs.isNotEmpty() && qs != rawPath) {
                qs.split('&').forEach { param ->
                    val name = param.substringBefore('=')
                    if (name.isNotEmpty()) group.queryParams.add(name)
                }
            }
        } catch (e: Exception) {
            // malformed item, skip
        }
    }

    return groups.entries.joinToString("\n") { (key, group) ->
        val total     = group.statusCounts.values.sum()
        val statusStr = group.statusCounts.entries.sortedBy { it.key }
            .joinToString(", ") { "${it.key}:${it.value}" }
        val line = StringBuilder("  $key (x$total) — $statusStr")
        if (group.queryParams.isNotEmpty()) {
            line.append(" — params: ${group.queryParams.sorted().joinToString(", ")}")
        }
        line.toString()
    }
}

// =============================================================================
// SEND REQUEST — unified attack tool
//
// Parameters:
//   index          — burpIndex of the item (same # shown in Burp Proxy History)
//   payloads       — list of payloads; if null uses numberOfRequests without modification
//   numberOfRequests — how many times to fire without payload (ignored if payloads != null)
//   delaySeconds   — delay between requests in SECONDS (default 0.5s).
//                    The backend converts to ms internally.
//                    Accepts fractions: 0.0 (no delay), 0.5 (500ms), 10.0 (10s)
//
// Injection strategy (in priority order):
//   1. MARKER    — request contains {{payload}} → replaces everywhere
//   2. AUTO-AUTH — payload starts with "eyJ" or "Bearer " → injects into Authorization
//   3. AUTO-PATH — any other payload → injects into last path segment
// =============================================================================

private fun hasPayloadMarker(rawRequest: burp.api.montoya.http.message.requests.HttpRequest): Boolean {
    val method  = rawRequest.method() ?: ""
    val path    = rawRequest.path() ?: ""
    val body    = rawRequest.bodyToString()
    val headers = rawRequest.headers().joinToString("\n") { "${it.name()}: ${it.value()}" }
    return method.contains("{{payload}}") ||
           path.contains("{{payload}}") ||
           body.contains("{{payload}}") ||
           headers.contains("{{payload}}")
}

private fun looksLikeAuthPayload(payload: String): Boolean {
    val trimmed = payload.trimStart()
    return trimmed.startsWith("Bearer ", ignoreCase = true) || trimmed.startsWith("eyJ")
}

private fun injectIntoAuthHeader(headers: MutableMap<String, String>, payload: String) {
    val key = headers.keys.firstOrNull { it.equals("authorization", ignoreCase = true) }
    if (key != null) {
        headers[key] = if (payload.startsWith("Bearer ", ignoreCase = true)) payload
                       else "Bearer $payload"
    }
}

private fun injectIntoLastPathSegment(path: String, payload: String): String {
    val queryStart = path.indexOf('?')
    val pathOnly   = if (queryStart != -1) path.substring(0, queryStart) else path
    val query      = if (queryStart != -1) path.substring(queryStart) else ""
    val lastSlash  = pathOnly.lastIndexOf('/')
    return if (lastSlash == -1) {
        payload + query
    } else {
        pathOnly.substring(0, lastSlash + 1) + payload + query
    }
}

/**
 * Returns true if payload has format "name=value" (named param injection).
 * Ex: "action=update_grid<script>alert(1)</script>"  → true
 *     "eyJhbGci..."                                  → false (JWT)
 *     "<script>alert(1)</script>"                    → false (no name)
 */
private fun looksLikeNamedParam(payload: String): Boolean {
    val eqIdx = payload.indexOf('=')
    if (eqIdx <= 0) return false
    val name = payload.substring(0, eqIdx)
    // name must be alphanumeric/underscore/hyphen and reasonably short
    return name.length <= 64 && name.all { it.isLetterOrDigit() || it == '_' || it == '-' }
}

/**
 * Replaces the VALUE of a named parameter in a query string or form-urlencoded body.
 * Exemplo: replaceParamValue("action=update_grid&page=1", "action", "PAYLOAD")
 *          → "action=PAYLOAD&page=1"
 *
 * If the parameter does not exist in the string, returns null (no change).
 */
private fun replaceParamValue(paramString: String, paramName: String, newValue: String): String? {
    // Captures name=value at start of string or after &
    val regex = Regex("""(^|&)(${Regex.escape(paramName)})=([^&]*)""")
    val match = regex.find(paramString) ?: return null
    val prefix = match.groupValues[1]   // "" ou "&"
    // Always URL-encode the value — correct behavior for form-urlencoded
    val encodedValue = java.net.URLEncoder.encode(newValue, "UTF-8").replace("+", "%20")
    return paramString.substring(0, match.range.first) +
           "$prefix$paramName=$encodedValue" +
           paramString.substring(match.range.last + 1)
}

/**
 * Replaces the value of a field in a JSON body.
 * Supports strings, numbers and booleans.
 * Ex: replaceJsonValue("""{"codigoFilial":73,"foo":"bar"}""", "codigoFilial", "99")
 *     → """{"codigoFilial":99,"foo":"bar"}"""
 *
 * If injected value is numeric or boolean, replaces without quotes.
 * If string, replaces with quotes.
 * Returns null if field not found.
 */
private fun replaceJsonValue(json: String, fieldName: String, newValue: String): String? {
    // Detect if newValue should be inserted as number/bool or JSON string
    val isNumeric = newValue.toDoubleOrNull() != null
    val isBool    = newValue.equals("true", ignoreCase = true) || newValue.equals("false", ignoreCase = true)
    val isNull    = newValue.equals("null", ignoreCase = true)

    // Regex that captures "fieldName": <value> — supports string, number, bool and null
    val valuePattern = """"([^"\\]|\\.)*"|true|false|null|-?\d+(\.\d+)?([eE][+-]?\d+)?"""
    val regex = Regex(""""${Regex.escape(fieldName)}"\s*:\s*($valuePattern)""")
    val match = regex.find(json) ?: return null

    val replacement = when {
        isNull    -> "null"
        isBool    -> newValue.lowercase()
        isNumeric -> newValue
        else      -> "\"${newValue.replace("\\", "\\\\").replace("\"", "\\\"")}\""
    }

    return json.substring(0, match.range.first) +
           "\"$fieldName\": $replacement" +
           json.substring(match.range.last + 1)
}

/**
 * Injects payload into body — auto-detects JSON vs form-urlencoded.
 */
private fun replaceInBody(body: String, paramName: String, newValue: String): String? {
    val trimmed = body.trimStart()
    return if (trimmed.startsWith("{") || trimmed.startsWith("[")) {
        replaceJsonValue(body, paramName, newValue)
    } else {
        replaceParamValue(body, paramName, newValue)
    }
}

/**
 * Injects payload into named param (e.g. "action=FUZZ") in raw HTTP/1.1 request.
 * Search order: (1) form-urlencoded body, (2) path query string.
 * Returns modified request, or null if param not found anywhere.
 */
private fun injectIntoNamedParam(rawContent: String, paramName: String, paramValue: String): String? {
    val lines      = rawContent.split("\n").toMutableList()
    val headerEnd  = lines.indexOfFirst { it.trimEnd().isEmpty() }

    // --- 1. Try in body (JSON or form-urlencoded) ---
    if (headerEnd != -1 && headerEnd < lines.lastIndex) {
        val bodyStart = headerEnd + 1
        val bodyRaw   = lines.subList(bodyStart, lines.size).joinToString("\n")
        val newBody   = replaceInBody(bodyRaw, paramName, paramValue)
        if (newBody != null) {
            val result = lines.subList(0, bodyStart).toMutableList()
            result.addAll(newBody.split("\n"))
            return result.joinToString("\n")
        }
    }

    // --- 2. Try in path query string (first line) ---
    val firstLine = lines[0].trimEnd()
    val parts     = firstLine.split(" ")
    if (parts.size >= 2) {
        val fullPath   = parts[1]
        val qIdx       = fullPath.indexOf('?')
        if (qIdx != -1) {
            val pathOnly = fullPath.substring(0, qIdx + 1)
            val qs       = fullPath.substring(qIdx + 1)
            val newQs    = replaceParamValue(qs, paramName, paramValue)
            if (newQs != null) {
                lines[0] = "${parts[0]} $pathOnly$newQs ${parts.getOrElse(2) { "HTTP/1.1" }}"
                return lines.joinToString("\n")
            }
        }
    }

    return null // param not found
}

/**
 * Injects a raw value into an explicitly indicated param/header.
 * targetLocation: "body" | "query" | "header"
 * Returns null if param/header not found.
 */
private fun injectExplicit(
    rawContent: String,
    targetParam: String,
    targetLocation: String,
    value: String
): String? {
    return when (targetLocation.lowercase()) {
        "body" -> {
            val lines     = rawContent.split("\n").toMutableList()
            val headerEnd = lines.indexOfFirst { it.trimEnd().isEmpty() }
            if (headerEnd == -1 || headerEnd >= lines.lastIndex) return null
            val bodyStart = headerEnd + 1
            val body      = lines.subList(bodyStart, lines.size).joinToString("\n")
            val newBody   = replaceInBody(body, targetParam, value) ?: return null
            val result    = lines.subList(0, bodyStart).toMutableList()
            result.addAll(newBody.split("\n"))
            result.joinToString("\n")
        }
        "query" -> {
            val lines  = rawContent.split("\n").toMutableList()
            val parts  = lines[0].trimEnd().split(" ")
            if (parts.size < 2) return null
            val fullPath = parts[1]
            val qIdx     = fullPath.indexOf('?')
            if (qIdx == -1) return null
            val pathOnly = fullPath.substring(0, qIdx + 1)
            val qs       = fullPath.substring(qIdx + 1)
            val newQs    = replaceParamValue(qs, targetParam, value) ?: return null
            lines[0] = "${parts[0]} $pathOnly$newQs ${parts.getOrElse(2) { "HTTP/1.1" }}"
            lines.joinToString("\n")
        }
        "header" -> {
            // Replace only in headers section (before blank line)
            val lines     = rawContent.split("\n").toMutableList()
            val headerEnd = lines.indexOfFirst { it.trimEnd().isEmpty() }
            val limit     = if (headerEnd != -1) headerEnd else lines.size
            var found     = false
            for (i in 1 until limit) {  // starts at 1, skips request line
                val trimmed = lines[i].trimEnd('\r')
                val colonIdx = trimmed.indexOf(':')
                if (colonIdx > 0) {
                    val name = trimmed.substring(0, colonIdx).trim()
                    if (name.equals(targetParam, ignoreCase = true)) {
                        lines[i] = "$name: $value"
                        found = true
                        break
                    }
                }
            }
            if (!found) return null
            lines.joinToString("\n")
        }
        else -> null
    }
}

/**
 * HTTP/2 version — operates on path, headers map and body separately.
 */
private fun injectExplicitHttp2(
    path: String,
    headers: MutableMap<String, String>,
    body: String,
    targetParam: String,
    targetLocation: String,
    value: String
): Triple<String, MutableMap<String, String>, String>? {
    return when (targetLocation.lowercase()) {
        "body" -> {
            val newBody = replaceInBody(body, targetParam, value) ?: return null
            Triple(path, headers, newBody)
        }
        "query" -> {
            val qIdx = path.indexOf('?')
            if (qIdx == -1) return null
            val pathOnly = path.substring(0, qIdx + 1)
            val qs       = path.substring(qIdx + 1)
            val newQs    = replaceParamValue(qs, targetParam, value) ?: return null
            Triple("$pathOnly$newQs", headers, body)
        }
        "header" -> {
            val key = headers.keys.firstOrNull { it.equals(targetParam, ignoreCase = true) }
                ?: return null
            headers[key] = value
            Triple(path, headers, body)
        }
        else -> null
    }
}

/**
 * Resolves injectAt and applies payload to raw HTTP/1.1 request.
 * Supported formats:
 *   "method"            → replaces HTTP verb on first line
 *   "path"              → replaces last path segment
 *   "body:paramName"    → replaces param value in form-urlencoded body
 *   "query:paramName"   → replaces param value in query string
 *   "header:HeaderName" → replaces header value
 * Returns null if target not found.
 */
private fun resolveInjectAt(rawContent: String, injectAt: String, payload: String): String? {
    return when {
        injectAt.equals("method", ignoreCase = true) -> {
            val lines = rawContent.split("\n").toMutableList()
            val parts = lines[0].trimEnd().split(" ")
            if (parts.size < 2) return null
            lines[0] = "$payload ${parts[1]} ${parts.getOrElse(2) { "HTTP/1.1" }}"
            lines.joinToString("\n")
        }
        injectAt.equals("path", ignoreCase = true) -> {
            val lines = rawContent.split("\n").toMutableList()
            val parts = lines[0].trimEnd().split(" ")
            if (parts.size < 2) return null
            val newPath = injectIntoLastPathSegment(parts[1], payload)
            lines[0] = "${parts[0]} $newPath ${parts.getOrElse(2) { "HTTP/1.1" }}"
            lines.joinToString("\n")
        }
        injectAt.startsWith("body:", ignoreCase = true) -> {
            val paramName = injectAt.substringAfter(":")
            injectExplicit(rawContent, paramName, "body", payload)
        }
        injectAt.startsWith("query:", ignoreCase = true) -> {
            val paramName = injectAt.substringAfter(":")
            injectExplicit(rawContent, paramName, "query", payload)
        }
        injectAt.startsWith("header:", ignoreCase = true) -> {
            val headerName = injectAt.substringAfter(":")
            injectExplicit(rawContent, headerName, "header", payload)
        }
        else -> null
    }
}

/**
 * HTTP/2 version of resolveInjectAt — operates on path, method, headers map and body separately.
 */
private fun resolveInjectAtHttp2(
    path: String,
    method: String,
    headers: MutableMap<String, String>,
    body: String,
    injectAt: String,
    payload: String
): Triple<String, String, String>? {   // (newPath, newMethod, newBody)
    return when {
        injectAt.equals("method", ignoreCase = true) ->
            Triple(path, payload, body)
        injectAt.equals("path", ignoreCase = true) ->
            Triple(injectIntoLastPathSegment(path, payload), method, body)
        injectAt.startsWith("body:", ignoreCase = true) -> {
            val paramName = injectAt.substringAfter(":")
            val newBody = replaceInBody(body, paramName, payload) ?: return null
            Triple(path, method, newBody)
        }
        injectAt.startsWith("query:", ignoreCase = true) -> {
            val paramName = injectAt.substringAfter(":")
            val qIdx = path.indexOf('?')
            if (qIdx == -1) return null
            val pathOnly = path.substring(0, qIdx + 1)
            val qs       = path.substring(qIdx + 1)
            val newQs    = replaceParamValue(qs, paramName, payload) ?: return null
            Triple("$pathOnly$newQs", method, body)
        }
        injectAt.startsWith("header:", ignoreCase = true) -> {
            val headerName = injectAt.substringAfter(":")
            val key = headers.keys.firstOrNull { it.equals(headerName, ignoreCase = true) }
                ?: return null
            headers[key] = payload
            Triple(path, method, body)
        }
        else -> null
    }
}

private fun executeSendRequest(
    index: Int,
    payloads: List<String>?,
    numberOfRequests: Int,
    delaySeconds: Double,
    api: MontoyaApi,
    config: McpConfig,
    injectAt: String? = null
): String {
    val filteredHistory = getFilteredHttpHistory(api)

    // Search by real burpIndex — not by position in filtered list
    val found = filteredHistory.firstOrNull { it.burpIndex == index }
        ?: return "[!] Item #$index not found in filtered history (may be static/out-of-scope)."

    val rawRequest = found.item.finalRequest()
    val rawContent = rawRequest.toString()
    val hasMarker  = hasPayloadMarker(rawRequest)

    val firstLine = rawContent.lines().firstOrNull()?.trimEnd() ?: ""
    val isHttp2   = firstLine.endsWith("HTTP/2") || firstLine.endsWith("HTTP/2.0")

    val hostname = rawRequest.httpService().host()
    val port     = rawRequest.httpService().port()
    val useHttps = rawRequest.httpService().secure()

    val delayMs   = (delaySeconds * 1000).toLong().coerceAtLeast(0L)
    val iterations = payloads?.size?.takeIf { it > 0 } ?: numberOfRequests

    // Collect raw results for later differential analysis
    data class ReqResult(
        val index: Int,
        val payload: String?,
        val status: Int,
        val size: Int,
        val latencyMs: Long,
        val bodyPreview: String,    // always captured, conditionally displayed
        val headersLog: String
    )
    val rawResults = mutableListOf<ReqResult>()
    var sseDetected: String? = null

    val firstPayload  = payloads?.firstOrNull()
    val injectionMode = when {
        injectAt != null                                            -> "explicit($injectAt)"
        hasMarker                                                   -> "marker({{payload}})"
        firstPayload != null && looksLikeAuthPayload(firstPayload) -> "auto(authorization header)"
        firstPayload != null && looksLikeNamedParam(firstPayload)  -> "auto(named param)"
        else                                                        -> "auto(last path segment)"
    }

    val interestingHeaderNames = setOf(
        "location", "www-authenticate",
        "access-control-allow-origin", "access-control-allow-credentials",
        "x-powered-by", "x-request-id", "server", "content-type",
        "zk-error", "x-cache", "vary"
    )

    for (i in 0 until iterations) {
        if (i > 0 && delayMs > 0) Thread.sleep(delayMs)

        val currentPayload = payloads?.getOrNull(i)

        val allowed = runBlocking {
            HttpRequestSecurity.checkHttpRequestPermission(hostname, port, config, rawContent, api)
        }
        if (!allowed) {
            rawResults.add(ReqResult(i, currentPayload, 0, 0, 0L, "Denied by Burp", ""))
            continue
        }

        if (isHttp2) {
            var path = rawRequest.path() ?: "/"

            val headers = linkedMapOf<String, String>()
            for (header in rawRequest.headers()) {
                val name = header.name().lowercase()
                if (name == "host") continue
                headers[name] = header.value()
            }

            var body = rawRequest.bodyToString()
            var method = rawRequest.method() ?: "POST"

            if (currentPayload != null) {
                when {
                    injectAt != null -> {
                        val result = resolveInjectAtHttp2(path, method, headers, body, injectAt, currentPayload)
                        if (result != null) {
                            path   = result.first
                            method = result.second
                            body   = result.third
                        }
                    }
                    hasMarker -> {
                        method = method.replace("{{payload}}", currentPayload)
                        path   = path.replace("{{payload}}", currentPayload)
                        headers.keys.toList().forEach { k ->
                            headers[k] = headers[k]!!.replace("{{payload}}", currentPayload)
                        }
                        body = body.replace("{{payload}}", currentPayload)
                    }
                    looksLikeAuthPayload(currentPayload) -> {
                        val key = headers.keys.firstOrNull { it.equals("authorization", ignoreCase = true) }
                        if (key != null) {
                            headers[key] = if (currentPayload.startsWith("Bearer ", ignoreCase = true))
                                currentPayload else "Bearer $currentPayload"
                        }
                    }
                    looksLikeNamedParam(currentPayload) -> {
                        val eqIdx      = currentPayload.indexOf('=')
                        val paramName  = currentPayload.substring(0, eqIdx)
                        val paramValue = currentPayload.substring(eqIdx + 1)
                        // Try body (JSON or form-urlencoded) first, then path query string
                        val newBody = replaceInBody(body, paramName, paramValue)
                        if (newBody != null) {
                            body = newBody
                        } else {
                            val qIdx = path.indexOf('?')
                            if (qIdx != -1) {
                                val pathOnly = path.substring(0, qIdx + 1)
                                val qs       = path.substring(qIdx + 1)
                                val newQs    = replaceParamValue(qs, paramName, paramValue)
                                if (newQs != null) path = "$pathOnly$newQs"
                                else path = injectIntoLastPathSegment(path, currentPayload)
                            } else {
                                path = injectIntoLastPathSegment(path, currentPayload)
                            }
                        }
                    }
                    else -> {
                        path = injectIntoLastPathSegment(path, currentPayload)
                    }
                }
            }

            val pseudoHeaders = linkedMapOf(
                ":scheme"    to (if (useHttps) "https" else "http"),
                ":method"    to method,
                ":path"      to path,
                ":authority" to hostname
            )

            // Remove content-length — Burp recalculates automatically based on body
            headers.keys.removeIf { it.equals("content-length", ignoreCase = true) }

            val headerList = (pseudoHeaders + headers)
                .map { HttpHeader.httpHeader(it.key, it.value) }

            val request  = HttpRequest.http2Request(
                HttpService.httpService(hostname, port, useHttps), headerList, body)
            val t0       = System.currentTimeMillis()
            val reqRes   = try {
                api.http().sendRequest(request, HttpMode.HTTP_2)
            } catch (e: Exception) {
                if (e.message?.contains("stream", ignoreCase = true) == true ||
                    e.message?.contains("event-stream", ignoreCase = true) == true) {
                    sseDetected = "⚠️ SSE endpoint detected — server returned Content-Type: text/event-stream\n" +
                        "SendRequest cannot consume persistent streams via the Burp API.\n" +
                        "Use CreateRepeaterTab to inspect this endpoint manually in Burp Repeater."
                    break
                }
                throw e
            }
            val latency  = System.currentTimeMillis() - t0
            val response = reqRes?.response()

            val status  = response?.statusCode()?.toInt() ?: 0
            val size    = response?.body()?.length() ?: 0
            val preview = response?.bodyToString()?.take(500) ?: ""
            val hdrs    = response?.headers()?.mapNotNull { h: burp.api.montoya.http.message.HttpHeader ->
                when (h.name().lowercase()) {
                    in interestingHeaderNames -> "${h.name()}: ${h.value().take(80)}"
                    "set-cookie"              -> "Set-Cookie: ${h.value().substringBefore('=').take(40)}=..."
                    else                      -> null
                }
            }?.joinToString(" | ") ?: ""

            rawResults.add(ReqResult(i, currentPayload, status, size, latency, preview, hdrs))

        } else {
            var currentContent = rawContent

            if (currentPayload != null) {
                currentContent = when {
                    injectAt != null -> {
                        resolveInjectAt(currentContent, injectAt, currentPayload) ?: currentContent
                    }
                    hasMarker -> {
                        currentContent.replace("{{payload}}", currentPayload)
                    }
                    looksLikeAuthPayload(currentPayload) -> {
                        val bearerValue = if (currentPayload.startsWith("Bearer ", ignoreCase = true))
                            currentPayload else "Bearer $currentPayload"
                        currentContent.replace(
                            Regex("(?i)(Authorization:\\s*).*"),
                            "$1$bearerValue"
                        )
                    }
                    looksLikeNamedParam(currentPayload) -> {
                        val eqIdx      = currentPayload.indexOf('=')
                        val paramName  = currentPayload.substring(0, eqIdx)
                        val paramValue = currentPayload.substring(eqIdx + 1)
                        injectIntoNamedParam(currentContent, paramName, paramValue)
                            ?: run {
                                // Param not found → fallback to last path segment
                                val lines = currentContent.split("\n").toMutableList()
                                val parts = lines[0].trimEnd().split(" ")
                                if (parts.size >= 2) {
                                    val newPath = injectIntoLastPathSegment(parts[1], currentPayload)
                                    lines[0] = "${parts[0]} $newPath ${parts.getOrElse(2) { "HTTP/1.1" }}"
                                }
                                lines.joinToString("\n")
                            }
                    }
                    else -> {
                        val lines = currentContent.split("\n").toMutableList()
                        val parts = lines[0].trimEnd().split(" ")
                        if (parts.size >= 2) {
                            val newPath = injectIntoLastPathSegment(parts[1], currentPayload)
                            lines[0] = "${parts[0]} $newPath ${parts.getOrElse(2) { "HTTP/1.1" }}"
                        }
                        lines.joinToString("\n")
                    }
                }
            }

            // Recalculate Content-Length in raw HTTP/1.1 content
            val contentWithCorrectLength = run {
                val lines     = currentContent.split("\n").toMutableList()
                val headerEnd = lines.indexOfFirst { it.trimEnd().isEmpty() }
                if (headerEnd != -1) {
                    val bodyBytes = lines.subList(headerEnd + 1, lines.size)
                        .joinToString("\n")
                        .toByteArray(Charsets.UTF_8).size
                    val clIdx = lines.indexOfFirst {
                        it.trimStart().lowercase().startsWith("content-length:")
                    }
                    if (clIdx != -1) {
                        lines[clIdx] = "Content-Length: $bodyBytes"
                    }
                }
                lines.joinToString("\n")
            }

            val fixedContent = contentWithCorrectLength.replace("\r", "").replace("\n", "\r\n")
            val request  = HttpRequest.httpRequest(
                HttpService.httpService(hostname, port, useHttps), fixedContent)
            val t0       = System.currentTimeMillis()
            val reqRes   = try {
                api.http().sendRequest(request)
            } catch (e: Exception) {
                if (e.message?.contains("stream", ignoreCase = true) == true ||
                    e.message?.contains("event-stream", ignoreCase = true) == true) {
                    sseDetected = "⚠️ SSE endpoint detected — server returned Content-Type: text/event-stream\n" +
                        "SendRequest cannot consume persistent streams via the Burp API.\n" +
                        "Use CreateRepeaterTab to inspect this endpoint manually in Burp Repeater."
                    break
                }
                throw e
            }
            val latency  = System.currentTimeMillis() - t0
            val response = reqRes?.response()

            val status  = response?.statusCode()?.toInt() ?: 0
            val size    = response?.body()?.length() ?: 0
            val preview = response?.bodyToString()?.take(500) ?: ""
            val hdrs    = response?.headers()?.mapNotNull { h: burp.api.montoya.http.message.HttpHeader ->
                when (h.name().lowercase()) {
                    in interestingHeaderNames -> "${h.name()}: ${h.value().take(80)}"
                    "set-cookie"              -> "Set-Cookie: ${h.value().substringBefore('=').take(40)}=..."
                    else                      -> null
                }
            }?.joinToString(" | ") ?: ""

            rawResults.add(ReqResult(i, currentPayload, status, size, latency, preview, hdrs))
        }
    }

    // Return SSE message if detected during loop
    if (sseDetected != null) return sseDetected!!

    val delayDisplay = if (delaySeconds == 0.0) "no delay" else "${delaySeconds}s"

    // Adaptive logic: if all sizes are equal, show body preview for differential analysis
    val allSizes      = rawResults.map { it.size }
    val sizesDistinct = allSizes.toSet().size > 1
    val allStatuses   = rawResults.map { it.status }
    val statusDistinct = allStatuses.toSet().size > 1

    val formattedResults = rawResults.joinToString("\n---\n") { r ->
        val payloadStr  = r.payload?.take(40) ?: "none"
        val headersStr  = if (r.headersLog.isNotEmpty()) " | ${r.headersLog}" else ""
        val latencyStr  = "${r.latencyMs}ms"
        val base        = "Req #${r.index} payload=$payloadStr: HTTP ${r.status} | ${r.size}b | ${latencyStr}$headersStr"
        // Show body preview only when all sizes are equal (differential analysis needed)
        if (!sizesDistinct && !statusDistinct && r.bodyPreview.isNotEmpty()) {
            "$base\nbody: ${r.bodyPreview}"
        } else {
            base
        }
    }

    val diffNote = when {
        statusDistinct -> "⚠️ DIFFERENT STATUS detected — differential behavior confirmed"
        sizesDistinct  -> "⚠️ DIFFERENT SIZE detected — possible IDOR/differential behavior"
        else           -> "ℹ️ Uniform sizes and status — body analysis needed (shown below)"
    }

    return "version=${if (isHttp2) "HTTP/2" else "HTTP/1.1"} | " +
           "injection=$injectionMode | " +
           "payloads_count=${payloads?.size ?: numberOfRequests} | " +
           "delay=$delayDisplay\n" +
           "$diffNote\n---\n" +
           formattedResults
}

// =============================================================================
// TOOL REGISTRATION
// =============================================================================

fun Server.registerTools(api: MontoyaApi, config: McpConfig) {

    // -------------------------------------------------------------------------
    // SEND REQUEST — only attack tool
    // -------------------------------------------------------------------------

    mcpTool<SendRequest>(
        "ATTACK TOOL — Fetches request by index from proxy history, auto-detects HTTP/1.1 or HTTP/2, " +
        "and fires the request. Fires one request per payload entry. " +
        "delaySeconds: delay between requests in SECONDS (default 0.5). " +
        "Use injectAt to declare exactly where to inject — payloads contain raw values only. " +
        "injectAt formats: " +
        "'method' → replaces HTTP verb (payloads: [\"GET\",\"PUT\",\"DELETE\"]); " +
        "'path' → replaces last path segment; " +
        "'body:paramName' → replaces param value in form-urlencoded body (e.g. 'body:action'); " +
        "'query:paramName' → replaces param value in query string (e.g. 'query:page'); " +
        "'header:HeaderName' → replaces header value (e.g. 'header:User-Agent'). " +
        "FALLBACK when injectAt is omitted: " +
        "(1) {{payload}} marker in request → replaces everywhere (method, path, headers, body); " +
        "(2) payload starts with eyJ or Bearer → injects into Authorization header; " +
        "(3) payload has format name=value → replaces that param in body or query; " +
        "(4) otherwise → injects into last path segment. " +
        "Do NOT call any read tool after receiving user approval — call this directly."
    ) {
        val allowed = runBlocking {
            checkHistoryPermissionOrDeny(HistoryAccessType.HTTP_HISTORY, config, api, "HTTP send")
        }
        if (!allowed) return@mcpTool "Denied"

        executeSendRequest(index, payloads, numberOfRequests, delaySeconds, api, config, injectAt)
    }

    // -------------------------------------------------------------------------
    // GET REQUEST BY INDEX — deep analysis of specific item
    // -------------------------------------------------------------------------

    mcpTool<GetRequestByIndex>(
        "READ TOOL — Returns the complete request AND response for a specific index " +
        "from filtered proxy history. No summarization, no grouping, no truncation. " +
        "Returns full headers and full body for both request and response. " +
        "Use this for deep analysis of a specific item when the user asks to analyze " +
        "request #N in depth. The index here is the same Item #N shown by GetProxyHttpHistory " +
        "and matches the # column in Burp Proxy History."
    ) {
        val allowed = runBlocking {
            checkHistoryPermissionOrDeny(HistoryAccessType.HTTP_HISTORY, config, api, "HTTP history")
        }
        if (!allowed) return@mcpTool "Denied"

        val filteredHistory = getFilteredHttpHistory(api)

        // Search by real burpIndex
        val found = filteredHistory.firstOrNull { it.burpIndex == index }
            ?: return@mcpTool "[!] Item #$index not found in filtered history (may be static/out-of-scope)."

        val serialized = removeVisualNoise(
            Json.encodeToString(found.item.toSerializableForm())
        )

        val latency = try {
            val ms = found.item.timingData()?.timeBetweenRequestSentAndStartOfResponse()?.toMillis()
            if (ms != null) " [baseline: ${ms}ms]" else ""
        } catch (e: Exception) { "" }

        "[${highlightLabel(found.item)}] Item #$index$latency: $serialized"
    }

    // -------------------------------------------------------------------------
    // GET REQUESTS BY COLOR — deep analysis of all items of one or more colors
    // -------------------------------------------------------------------------

    mcpPaginatedTool<GetRequestsByColor>(
        "READ TOOL — Group analysis by highlight color. Returns enriched data for ALL items " +
        "of the specified color(s): full request + response with the same truncation/cleaning pipeline " +
        "as GetProxyHttpHistory (SVG/base64/ViewState truncated, cookies collapsed, tokens truncated). " +
        "Use to find real vulnerabilities across a color group — SQLi, SSTI, IDOR, PII, mass assignment. " +
        "IMPORTANT: JWT/token attacks and deep token analysis require GetRequestByIndex — " +
        "tokens are truncated here just like in GetProxyHttpHistory. " +
        "colors: list of highlight colors, e.g. [\"RED\"], [\"RED\",\"ORANGE\"]. " +
        "Valid colors: RED, ORANGE, YELLOW, GREEN, CYAN, BLUE, PINK, MAGENTA."
    ) {
        val allowed = runBlocking {
            checkHistoryPermissionOrDeny(HistoryAccessType.HTTP_HISTORY, config, api, "HTTP history")
        }
        if (!allowed) return@mcpPaginatedTool sequenceOf("Denied")

        val upperColors = colors.map { it.uppercase() }.toSet()

        val filteredHistory = getFilteredHttpHistory(api)
            .filter { highlightLabel(it.item) in upperColors }

        if (filteredHistory.isEmpty())
            return@mcpPaginatedTool sequenceOf(
                "[!] No highlighted items found for color(s): ${upperColors.joinToString(", ")}. " +
                "Available colors: RED, ORANGE, YELLOW, GREEN, CYAN, BLUE, PINK, MAGENTA."
            )

        val header = "[COLOR ANALYSIS] ${filteredHistory.size} item(s) | " +
                     "colors: ${upperColors.joinToString(", ")} | " +
                     "indices: ${filteredHistory.joinToString(", ") { "#${it.burpIndex}" }}\n" +
                     "NOTE: JWT/tokens are truncated — use GetRequestByIndex for token attacks.\n"

        // Apply same pipeline as GetProxyHttpHistory: truncation, cleanup, collapsed cookies
        filteredHistory.asSequence().map { indexed ->
            val color      = highlightLabel(indexed.item)
            val serialized = truncateTokens(removeVisualNoise(
                collapseCookiesInJson(Json.encodeToString(indexed.item.toSerializableForm()))
            ))
            val truncated  = truncateIfNeeded(serialized)
            val latency    = try {
                val ms = indexed.item.timingData()?.timeBetweenRequestSentAndStartOfResponse()?.toMillis()
                if (ms != null) " [baseline: ${ms}ms]" else ""
            } catch (e: Exception) { "" }
            "[$color] Item #${indexed.burpIndex}$latency: $truncated"
        }.let { items ->
            sequenceOf(header + items.joinToString("\n\n---\n\n"))
        }
    }

    mcpPaginatedTool<GetProxyHttpHistory>(
        "READ TOOL — Overview and triage. Displays highlighted proxy HTTP history grouped by color with summary. " +
        "Returns endpoint groups, status codes, param names — NOT values, NOT bodies, NOT responses. " +
        "Use to identify what was captured and which items to investigate. " +
        "IMPORTANT: JWT/token attacks and deep analysis require GetRequestByIndex. " +
        "For vulnerability analysis of a color group use GetRequestsByColor instead. " +
        "Item # matches the # column in Burp Proxy History."
    ) {
        val allowed = runBlocking {
            checkHistoryPermissionOrDeny(HistoryAccessType.HTTP_HISTORY, config, api, "HTTP history")
        }
        if (!allowed) return@mcpPaginatedTool sequenceOf("Denied")

        val filteredHistory = getFilteredHttpHistory(api)

        if (filteredHistory.isEmpty()) return@mcpPaginatedTool sequenceOf("No highlighted items found.")

        // Serialize with all cleanups including token truncation
        fun serialize(indexed: IndexedProxyItem): String =
            truncateTokens(removeVisualNoise(
                collapseCookiesInJson(Json.encodeToString(indexed.item.toSerializableForm()))
            ))

        // Extract real request latency via timingData()
        fun latencyMs(indexed: IndexedProxyItem): String {
            return try {
                val td = indexed.item.timingData()
                val ms = td?.timeBetweenRequestSentAndStartOfResponse()?.toMillis()
                if (ms != null) "${ms}ms" else "?"
            } catch (e: Exception) { "?" }
        }

        // Group by color maintaining insertion order
        val byColor = linkedMapOf<String, MutableList<Triple<Int, String, String>>>()
        for (indexed in filteredHistory) {
            val label = highlightLabel(indexed.item)
            byColor.getOrPut(label) { mutableListOf() }
                .add(Triple(indexed.burpIndex, serialize(indexed), latencyMs(indexed)))
        }

        val jsonItemsForSummary = filteredHistory.map { serialize(it) }
        val summary = summarizeHistory(jsonItemsForSummary)

        val output = mutableListOf<String>()
        output.add(
            "Highlighted HTTP history — ${filteredHistory.size} item(s) across ${byColor.size} color(s)\n" +
            "Colors: ${byColor.keys.joinToString(", ")}\n" +
            "Summary:\n$summary\n---\n" +
            "Full items below (Use SendRequest with Item # for attacks, GetRequestByIndex for deep analysis):"
        )

        for ((color, items) in byColor) {
            output.add("=== [$color] — ${items.size} item(s) ===")
            for ((burpIndex, item, latency) in items) {
                output.add("[$color] Item #$burpIndex [${latency}]: " + truncateIfNeeded(item))
            }
        }

        output.asSequence()
    }

    mcpPaginatedTool<GetProxyHttpHistoryRegex>(
        "Displays highlighted proxy HTTP history matching a Regex, grouped by color. " +
        "Only highlighted items are searched — unmarked items are ignored. " +
        "Item # matches the # column in Burp Proxy History. " +
        "Use Item # indices with SendRequest for attacks. " +
        "For deep analysis of a specific item use GetRequestByIndex instead."
    ) {
        val allowed = runBlocking {
            checkHistoryPermissionOrDeny(HistoryAccessType.HTTP_HISTORY, config, api, "HTTP history")
        }
        if (!allowed) return@mcpPaginatedTool sequenceOf("Denied")

        val compiledRegex = Pattern.compile(regex)
        val filteredHistory = getFilteredHttpHistory(api)

        val matchedWithIndex = filteredHistory.mapNotNull { indexed ->
            val serialized = truncateTokens(truncateIfNeeded(
                removeVisualNoise(collapseCookiesInJson(Json.encodeToString(indexed.item.toSerializableForm())))
            ))
            if (compiledRegex.matcher(serialized).find()) Triple(indexed.burpIndex, highlightLabel(indexed.item), serialized) else null
        }

        if (matchedWithIndex.isEmpty()) return@mcpPaginatedTool sequenceOf("No matches.")

        matchedWithIndex.map { (burpIndex, color, item) -> "[$color] Item #$burpIndex: $item" }.asSequence()
    }

    // -------------------------------------------------------------------------
    // REPEATER, INTRUDER AND AUXILIARIES
    // -------------------------------------------------------------------------

    mcpTool<CreateRepeaterTab>(
        "Sends a request to Repeater by index. " +
        "Fetches request directly from Burp Proxy History — no LLM content modification. " +
        "Optional: provide payload + injectAt to inject a specific value before sending (same formats as SendRequest). " +
        "index matches the # column in Burp Proxy History."
    ) {
        val history = api.proxy().history()
        val item = history.firstOrNull { it.id() == index }
            ?: return@mcpTool "[!] Item #$index not found in proxy history."
        val rawRequest = item.finalRequest()

        val finalRequest = if (payload != null && injectAt != null) {
            val rawContent = rawRequest.toString()
            val isHttp2 = rawContent.lines().firstOrNull()?.trimEnd()?.let {
                it.endsWith("HTTP/2") || it.endsWith("HTTP/2.0")
            } ?: false
            if (isHttp2) {
                var path    = rawRequest.path() ?: "/"
                var method  = rawRequest.method() ?: "GET"
                val headers = linkedMapOf<String, String>()
                for (h in rawRequest.headers()) {
                    val n = h.name().lowercase()
                    if (n != "host") headers[n] = h.value()
                }
                var body = rawRequest.bodyToString()
                val result = resolveInjectAtHttp2(path, method, headers, body, injectAt, payload)
                if (result != null) { path = result.first; method = result.second; body = result.third }
                val pseudoHeaders = linkedMapOf(
                    ":scheme"    to (if (rawRequest.httpService().secure()) "https" else "http"),
                    ":method"    to method,
                    ":path"      to path,
                    ":authority" to rawRequest.httpService().host()
                )
                headers.keys.removeIf { it.equals("content-length", ignoreCase = true) }
                val headerList = (pseudoHeaders + headers).map { HttpHeader.httpHeader(it.key, it.value) }
                HttpRequest.http2Request(rawRequest.httpService(), headerList, body)
            } else {
                val injected = resolveInjectAt(rawContent, injectAt, payload) ?: rawContent
                val fixed = injected.replace("\r", "").replace("\n", "\r\n")
                HttpRequest.httpRequest(rawRequest.httpService(), fixed)
            }
        } else {
            rawRequest
        }

        api.repeater().sendToRepeater(finalRequest, tabName)
        val injInfo = if (payload != null) " [injected: $injectAt=$payload]" else ""
        "Sent to Repeater: ${tabName ?: "tab"} — Item #$index${injInfo}"
    }

    mcpTool<SendToIntruder>(
        "Sends a request to Intruder by index. " +
        "Fetches request directly from Burp Proxy History — no LLM content modification. " +
        "Optional: provide payload + injectAt to inject a specific value before sending (same formats as SendRequest). " +
        "index matches the # column in Burp Proxy History."
    ) {
        val history = api.proxy().history()
        val item = history.firstOrNull { it.id() == index }
            ?: return@mcpTool "[!] Item #$index not found in proxy history."
        val rawRequest = item.finalRequest()

        val finalRequest = if (payload != null && injectAt != null) {
            val rawContent = rawRequest.toString()
            val isHttp2 = rawContent.lines().firstOrNull()?.trimEnd()?.let {
                it.endsWith("HTTP/2") || it.endsWith("HTTP/2.0")
            } ?: false
            if (isHttp2) {
                var path    = rawRequest.path() ?: "/"
                var method  = rawRequest.method() ?: "GET"
                val headers = linkedMapOf<String, String>()
                for (h in rawRequest.headers()) {
                    val n = h.name().lowercase()
                    if (n != "host") headers[n] = h.value()
                }
                var body = rawRequest.bodyToString()
                val result = resolveInjectAtHttp2(path, method, headers, body, injectAt, payload)
                if (result != null) { path = result.first; method = result.second; body = result.third }
                val pseudoHeaders = linkedMapOf(
                    ":scheme"    to (if (rawRequest.httpService().secure()) "https" else "http"),
                    ":method"    to method,
                    ":path"      to path,
                    ":authority" to rawRequest.httpService().host()
                )
                headers.keys.removeIf { it.equals("content-length", ignoreCase = true) }
                val headerList = (pseudoHeaders + headers).map { HttpHeader.httpHeader(it.key, it.value) }
                HttpRequest.http2Request(rawRequest.httpService(), headerList, body)
            } else {
                val injected = resolveInjectAt(rawContent, injectAt, payload) ?: rawContent
                val fixed = injected.replace("\r", "").replace("\n", "\r\n")
                HttpRequest.httpRequest(rawRequest.httpService(), fixed)
            }
        } else {
            rawRequest
        }

        api.intruder().sendToIntruder(finalRequest, tabName)
        val injInfo = if (payload != null) " [injected: $injectAt=$payload]" else ""
        "Sent to Intruder: ${tabName ?: "tab"} — Item #$index${injInfo}"
    }

    mcpTool<UrlEncode>("URL encodes string") { api.utilities().urlUtils().encode(content) }
    mcpTool<UrlDecode>("URL decodes string") { api.utilities().urlUtils().decode(content) }
    mcpTool<Base64Encode>("Base64 encodes string") { api.utilities().base64Utils().encodeToString(content) }
    mcpTool<Base64Decode>("Base64 decodes string") { api.utilities().base64Utils().decode(content).toString() }

    mcpTool<SetProxyInterceptState>("Enables/disables Proxy Intercept") {
        if (intercepting) api.proxy().enableIntercept() else api.proxy().disableIntercept()
        "Intercept ${if (intercepting) "enabled" else "disabled"}"
    }

    // -------------------------------------------------------------------------
    // WEBSOCKETS
    // -------------------------------------------------------------------------

    mcpPaginatedTool<GetProxyWebsocketHistory>("Proxy WebSocket history. Respects Project Scope.") {
        val allowed = runBlocking {
            checkHistoryPermissionOrDeny(HistoryAccessType.WEBSOCKET_HISTORY, config, api, "WS history")
        }
        if (!allowed) return@mcpPaginatedTool sequenceOf("Denied")

        api.proxy().webSocketHistory().reversed().asSequence()
            .filter { wsMsg -> api.scope().isInScope(wsMsg.upgradeRequest().url()) }
            .map { truncateIfNeeded(removeVisualNoise(Json.encodeToString(it.toSerializableForm()))) }
    }

    mcpPaginatedTool<GetProxyWebsocketHistoryRegex>("Proxy WebSocket history matching Regex. Respects Project Scope.") {
        val allowed = runBlocking {
            checkHistoryPermissionOrDeny(HistoryAccessType.WEBSOCKET_HISTORY, config, api, "WS history")
        }
        if (!allowed) return@mcpPaginatedTool sequenceOf("Denied")

        val compiledRegex = Pattern.compile(regex)
        val matched = api.proxy().webSocketHistory { it.contains(compiledRegex) }.reversed().asSequence()
            .filter { wsMsg -> api.scope().isInScope(wsMsg.upgradeRequest().url()) }
            .map { truncateIfNeeded(removeVisualNoise(Json.encodeToString(it.toSerializableForm()))) }
            .toList()

        if (matched.isEmpty()) return@mcpPaginatedTool sequenceOf("No matches.")
        matched.mapIndexed { i, item -> "Item #$i: $item" }.asSequence()
    }

    // -------------------------------------------------------------------------
    // COLLABORATOR (Pro only)
    // -------------------------------------------------------------------------

    if (api.burpSuite().version().edition() == BurpSuiteEdition.PROFESSIONAL) {

        val collaboratorClient by lazy { api.collaborator().createClient() }

        mcpTool<GenerateCollaboratorPayload>(
            "Generates a Burp Collaborator payload URL for out-of-band (OOB) testing. " +
            "Inject this payload into requests to detect server-side interactions " +
            "(DNS lookups, HTTP requests, SMTP). " +
            "Use get_collaborator_interactions with the returned payloadId to check for interactions."
        ) {
            api.logging().logToOutput(
                "MCP generating Collaborator payload${customData?.let { " with custom data" } ?: ""}"
            )
            val payload = if (customData != null) {
                collaboratorClient.generatePayload(customData)
            } else {
                collaboratorClient.generatePayload()
            }
            val server = collaboratorClient.server()
            "Payload: $payload\nPayload ID: ${payload.id()}\nCollaborator server: ${server.address()}"
        }

        mcpTool<GetCollaboratorInteractions>(
            "Fetches Burp Collaborator interactions for a specific payload ID or all interactions. " +
            "Use this after injecting a collaborator payload to check if the target made any " +
            "out-of-band interactions."
        ) {
            api.logging().logToOutput(
                "MCP fetching Collaborator interactions${payloadId?.let { " for payload $it" } ?: ""}"
            )
            val interactions = if (payloadId != null) {
                collaboratorClient.getInteractions(InteractionFilter.interactionIdFilter(payloadId))
            } else {
                collaboratorClient.getAllInteractions()
            }

            if (interactions.isEmpty()) {
                "No interactions detected"
            } else {
                interactions.joinToString("\n\n") { Json.encodeToString(it.toSerializableForm()) }
            }
        }
    }
}

// =============================================================================
// DATA CLASSES
// =============================================================================

// --- Attack tool ---
@Serializable
data class SendRequest(
    val index: Int,
    val payloads: List<String>? = null,
    val numberOfRequests: Int = 1,
    val delaySeconds: Double = 0.5,   // 0.0 = no delay, 0.5 = 500ms (default), 1.0 = 1s
    val injectAt: String? = null      // where to inject the payload — examples:
                                      //   "method"            → replaces HTTP verb
                                      //   "path"              → replaces last path segment
                                      //   "body:action"       → replaces value of param 'action' in body
                                      //   "query:page"        → replaces value of param 'page' in query string
                                      //   "header:User-Agent" → replaces value of header 'User-Agent'
                                      // if omitted: uses automatic heuristic (marker > auth > named param > path)
)

// --- Deep analysis tool ---
@Serializable
data class GetRequestByIndex(
    val index: Int  // burpIndex — same # shown in Burp Proxy History "#" column
                    // returns full request + response without truncation
)

// --- Deep analysis by color ---
@Serializable
data class GetRequestsByColor(
    val colors: List<String>,           // list of colors: ["RED"], ["RED","ORANGE"], etc.
                                        // valid colors: RED, ORANGE, YELLOW, GREEN, CYAN, BLUE, PINK, MAGENTA
    override val count: Int = 10,
    override val offset: Int = 0
) : Paginated

// --- Repeater / Intruder ---
@Serializable
data class CreateRepeaterTab(
    val index: Int,                 // burpIndex — same # as Burp Proxy History "#" column
    val tabName: String? = null,    // tab name in Repeater (optional)
    val payload: String? = null,    // payload value to inject (optional)
    val injectAt: String? = null    // where to inject — same formats as SendRequest (optional)
)

@Serializable
data class SendToIntruder(
    val index: Int,                 // burpIndex — same # as Burp Proxy History "#" column
    val tabName: String? = null,    // tab name in Intruder (optional)
    val payload: String? = null,    // payload value to inject (optional)
    val injectAt: String? = null    // where to inject — same formats as SendRequest (optional)
)

// --- Utilities ---
@Serializable data class UrlEncode(val content: String)
@Serializable data class UrlDecode(val content: String)
@Serializable data class Base64Encode(val content: String)
@Serializable data class Base64Decode(val content: String)
@Serializable data class SetProxyInterceptState(val intercepting: Boolean)

// --- Collaborator ---
@Serializable data class GenerateCollaboratorPayload(val customData: String? = null)
@Serializable data class GetCollaboratorInteractions(val payloadId: String? = null)

// --- History ---
@Serializable data class GetProxyHttpHistory(
    override val count: Int = 5,
    override val offset: Int = 0
) : Paginated

@Serializable data class GetProxyHttpHistoryRegex(
    val regex: String,
    override val count: Int = 5,
    override val offset: Int = 0
) : Paginated

@Serializable data class GetProxyWebsocketHistory(
    override val count: Int = 5,
    override val offset: Int = 0
) : Paginated

@Serializable data class GetProxyWebsocketHistoryRegex(
    val regex: String,
    override val count: Int = 5,
    override val offset: Int = 0
) : Paginated
