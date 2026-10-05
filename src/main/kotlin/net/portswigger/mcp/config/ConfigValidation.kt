package net.portswigger.mcp.config

object ConfigValidation {

    private val HOSTNAME_REGEX = Regex("^[a-zA-Z0-9.-]+$")

    fun validateServerConfig(host: String, portText: String): String? {
        val trimmedHost = host.trim()
        val port = portText.trim().toIntOrNull()

        if (trimmedHost.isBlank() || !(trimmedHost.matches(HOSTNAME_REGEX) || isValidIpv6Literal(trimmedHost))) {
            return "Host must be a non-empty alphanumeric string"
        }

        if (port == null) {
            return "Port must be a valid number"
        }

        if (port < 1024 || port > 65535) {
            return "Port is not within valid range"
        }

        return null
    }

    /**
     * Pragmatic check for an IPv6 literal, either bracketed (e.g. "[::1]")
     * or bare (e.g. "::1", "2001:db8::1").
     */
    internal fun isValidIpv6Literal(value: String): Boolean {
        val unbracketed = if (value.startsWith("[") && value.endsWith("]")) {
            value.substring(1, value.length - 1)
        } else {
            value
        }
        return unbracketed.contains(":") && unbracketed.matches(Regex("^[0-9a-fA-F:]+$"))
    }
}