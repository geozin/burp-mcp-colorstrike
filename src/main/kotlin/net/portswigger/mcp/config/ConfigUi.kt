package net.portswigger.mcp.config

import io.ktor.util.network.*
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import net.portswigger.mcp.ServerState
import net.portswigger.mcp.Swing
import net.portswigger.mcp.config.components.*
import net.portswigger.mcp.providers.Provider
import java.awt.BorderLayout
import java.awt.Color
import java.awt.Component.CENTER_ALIGNMENT
import java.awt.Font
import java.awt.GridBagLayout
import javax.swing.*
import javax.swing.Box.*
import javax.swing.JOptionPane.ERROR_MESSAGE
import javax.swing.text.SimpleAttributeSet
import javax.swing.text.StyleConstants

class ConfigUi(private val config: McpConfig, private val providers: List<Provider>) {

    private val panel = JPanel(BorderLayout())
    val component: JComponent get() = panel

    private val listenerHandles = mutableListOf<ListenerHandle>()

    private val enabledToggle: ToggleSwitch = Design.createToggleSwitch(false) { enabled ->
        if (suppressToggleEvents) return@createToggleSwitch

        if (enabled) {
            ConfigValidation.validateServerConfig(hostField.text, portField.text)?.let { error ->
                validationErrorLabel.text = error
                validationErrorLabel.isVisible = true
                suppressToggleEvents = true
                enabledToggle.setState(false, animate = true)
                suppressToggleEvents = false
                return@createToggleSwitch
            }
        }

        validationErrorLabel.isVisible = false
        config.enabled = enabled
        toggleListener?.invoke(enabled)
    }
    private val validationErrorLabel = WarningLabel()
    private val hostField = JTextField(15)
    private val portField = JTextField(5)
    private val reinstallNotice = WarningLabel("Make sure to reinstall after changing server settings")

    private lateinit var serverConfigurationPanel: ServerConfigurationPanel
    private lateinit var advancedOptionsPanel: AdvancedOptionsPanel
    private lateinit var installationPanel: InstallationPanel

    private var toggleListener: ((Boolean) -> Unit)? = null
    private var suppressToggleEvents: Boolean = false
    private var historyAccessRefreshListener: (() -> Unit)? = null

    init {
        enabledToggle.setState(config.enabled, animate = false)
        hostField.text = config.host
        portField.text = config.port.toString()

        // Panel construction touches Swing components and must happen on the EDT.
        // ConfigUi is instantiated from BurpExtension.initialize(), which Burp calls
        // on its own extension-loading thread, not the EDT.
        if (SwingUtilities.isEventDispatchThread()) {
            initializeComponents()
            buildUi()
        } else {
            SwingUtilities.invokeAndWait {
                initializeComponents()
                buildUi()
            }
        }
    }

    private fun initializeComponents() {
        serverConfigurationPanel = ServerConfigurationPanel(
            config = config, enabledToggle = enabledToggle, validationErrorLabel = validationErrorLabel
        )

        advancedOptionsPanel = AdvancedOptionsPanel(
            hostField = hostField, portField = portField, reinstallNotice = reinstallNotice
        )

        installationPanel = InstallationPanel(
            config = config, providers = providers, reinstallNotice = reinstallNotice, parentComponent = panel
        )

        setupConfigListeners()
    }

    private fun setupConfigListeners() {
        // Keep a strong reference on this field: the listener registry holds only a
        // WeakReference, so a local-variable lambda here would be eligible for GC at
        // the next collection, silently stopping checkbox updates.
        historyAccessRefreshListener = {
            SwingUtilities.invokeLater {
                serverConfigurationPanel.updateHistoryAccessCheckboxes()
            }
        }
        val handle = config.addHistoryAccessChangeListener(historyAccessRefreshListener!!)
        listenerHandles.add(handle)
    }

    fun cleanup() {
        listenerHandles.forEach { it.remove() }
        listenerHandles.clear()
        historyAccessRefreshListener = null
    }

    fun onEnabledToggled(listener: (Boolean) -> Unit) {
        toggleListener = listener
    }

    fun getConfig(): McpConfig {
        config.host = hostField.text
        portField.text.toIntOrNull()?.let { config.port = it }
        return config
    }

    fun updateServerState(state: ServerState) {
        CoroutineScope(Dispatchers.Swing).launch {
            suppressToggleEvents = true

            val enableAdvancedOptions = state is ServerState.Stopped || state is ServerState.Failed
            if (::advancedOptionsPanel.isInitialized) {
                advancedOptionsPanel.setFieldsEnabled(enableAdvancedOptions)
            }

            when (state) {
                ServerState.Starting, ServerState.Stopping -> {
                    enabledToggle.isEnabled = false
                }

                ServerState.Running -> {
                    enabledToggle.isEnabled = true
                    enabledToggle.setState(true, animate = false)
                }

                ServerState.Stopped -> {
                    enabledToggle.isEnabled = true
                    enabledToggle.setState(false, animate = false)
                }

                is ServerState.Failed -> {
                    enabledToggle.isEnabled = true
                    enabledToggle.setState(false, animate = false)

                    val friendlyMessage = when (state.exception) {
                        is UnresolvedAddressException -> "Unable to resolve address"
                        else -> state.exception.message ?: state.exception.javaClass.simpleName
                    }

                    Dialogs.showMessageDialog(
                        panel, "Failed to start Burp MCP Server: $friendlyMessage", ERROR_MESSAGE
                    )
                }
            }

            suppressToggleEvents = false
        }
    }

    private fun buildUi() {
        val leftPanel = JPanel(GridBagLayout())

        val headerBox = createVerticalBox().apply {
            add(JLabel("ColorStrike").apply {
                font = Design.Typography.headlineMedium
                foreground = Design.Colors.onSurface
                alignmentX = CENTER_ALIGNMENT
            })
            add(createVerticalStrut(Design.Spacing.SM / 2))
            add(JLabel("Burp MCP Server · Color-Based Triage & Attack Toolkit").apply {
                font = Design.Typography.labelMedium
                foreground = Design.Colors.onSurfaceVariant
                alignmentX = CENTER_ALIGNMENT
            })
            add(createVerticalStrut(Design.Spacing.MD))
            add(createPrismAsciiArea())
            add(createVerticalStrut(Design.Spacing.MD))
            add(JLabel("Burp MCP Server exposes Burp tooling to AI clients.").apply {
                font = Design.Typography.bodyLarge
                foreground = Design.Colors.onSurfaceVariant
                alignmentX = CENTER_ALIGNMENT
            })
            add(createVerticalStrut(Design.Spacing.MD))
            add(
                Anchor(
                    text = "github.com/geozin/burp-mcp-colorstrike",
                    url = "https://github.com/geozin/burp-mcp-colorstrike"
                ).apply { alignmentX = CENTER_ALIGNMENT })
        }

        leftPanel.add(headerBox)

        val rightPanelContent = JPanel().apply {
            layout = BoxLayout(this, BoxLayout.Y_AXIS)
            background = Design.Colors.surface
            border = BorderFactory.createEmptyBorder(
                Design.Spacing.LG, Design.Spacing.LG, Design.Spacing.LG, Design.Spacing.LG
            )
        }

        val rightPanel = JScrollPane(rightPanelContent).apply {
            border = null
            background = Design.Colors.surface
            viewport.background = Design.Colors.surface
            verticalScrollBarPolicy = JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED
            horizontalScrollBarPolicy = JScrollPane.HORIZONTAL_SCROLLBAR_NEVER
            verticalScrollBar.unitIncrement = 16
        }

        rightPanelContent.add(serverConfigurationPanel)
        rightPanelContent.add(createVerticalStrut(Design.Spacing.LG))

        rightPanelContent.add(advancedOptionsPanel)
        rightPanelContent.add(createVerticalGlue())
        rightPanelContent.add(reinstallNotice)
        rightPanelContent.add(createVerticalStrut(10))

        rightPanelContent.add(installationPanel)

        val columnsPanel = ResponsiveColumnsPanel(leftPanel, rightPanel)
        panel.add(columnsPanel, BorderLayout.CENTER)
    }

    /**
     * Renders PRISM_ASCII as a non-editable JTextPane with each ray colored to match its
     * label (R/O/Y/G/B/V), rather than a single flat color — the prism effect only reads as
     * a prism if the rays are actually the colors they're labeled, same idea as Burp's own
     * highlight-color palette this extension is built around.
     */
    private fun createPrismAsciiArea(): JTextPane {
        val rayColors = mapOf(
            'R' to Color(0xE0, 0x3A, 0x3A), // red
            'O' to Color(0xE0, 0x8A, 0x2A), // orange
            'Y' to Color(0xC9, 0xA8, 0x1E), // yellow
            'G' to Color(0x3A, 0xA0, 0x5A), // green
            'B' to Color(0x3A, 0x7A, 0xD0), // blue
            'V' to Color(0x8A, 0x4A, 0xC9)  // violet
        )
        val neutral = Design.Colors.onSurfaceVariant

        return JTextPane().apply {
            isOpaque = false
            isEditable = false
            isFocusable = false
            alignmentX = CENTER_ALIGNMENT
            font = Font("Monospaced", Font.BOLD, 12)
            border = BorderFactory.createEmptyBorder(6, 12, 6, 12)

            val neutralStyle = SimpleAttributeSet().apply { StyleConstants.setForeground(this, neutral) }
            PRISM_ASCII.trimIndent().lines().forEach { line ->
                val rayChar = line.trimEnd().lastOrNull()?.takeIf { it in rayColors }
                val style = rayChar?.let { c ->
                    SimpleAttributeSet().apply { StyleConstants.setForeground(this, rayColors.getValue(c)) }
                } ?: neutralStyle
                document.insertString(document.length, "$line\n", style)
            }
        }
    }

    companion object {
        // Prism: white light in from the left, split into six labeled color rays —
        // ColorStrike's own highlight-color triage, drawn as light instead of a legend.
        private const val PRISM_ASCII = """
            ───────────────────────◢▲◣
                                  ◢███◣
                                 ◢█████◣
                                █████████▶ R
                                █████████▶ O
                                █████████▶ Y
                                █████████▶ G
                                █████████▶ B
                                █████████▶ V
                                 ◥█████◤
                                  ◥███◤
                                   ◥█◤
                         [ COLORSTRIKE :: MCP ]"""
    }
}