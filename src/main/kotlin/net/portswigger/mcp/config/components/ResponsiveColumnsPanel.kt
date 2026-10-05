package net.portswigger.mcp.config.components

import net.portswigger.mcp.config.Design
import java.awt.BorderLayout
import java.awt.GridBagConstraints
import java.awt.GridBagLayout
import java.awt.event.ComponentAdapter
import java.awt.event.ComponentEvent
import javax.swing.BorderFactory
import javax.swing.BoxLayout
import javax.swing.JPanel
import javax.swing.JScrollPane

class ResponsiveColumnsPanel(private val leftPanel: JPanel, private val rightPanel: JScrollPane) : JPanel() {
    private val minWidthForTwoColumns = 900
    private val minWidthForLargePadding = 700
    private var lastLayout = Layout.SINGLE_COLUMN
    private var lastPaddingSize = PaddingSize.SMALL
    private var isInitialized = false

    enum class Layout { SINGLE_COLUMN, TWO_COLUMNS }
    enum class PaddingSize { SMALL, LARGE }

    init {
        isInitialized = true
        updateLayout()

        // Recompute the column layout only in response to actual size changes, rather
        // than from doLayout() itself: calling removeAll()/revalidate() from inside
        // doLayout() can trigger another layout pass, looping.
        addComponentListener(object : ComponentAdapter() {
            override fun componentResized(e: ComponentEvent?) {
                checkAndUpdateLayout()
            }
        })
    }

    override fun updateUI() {
        super.updateUI()
        if (isInitialized) {
            updateLayout() // Reapply layout with updated theme colors
        }
    }

    private fun checkAndUpdateLayout() {
        val currentLayout = if (width >= minWidthForTwoColumns) Layout.TWO_COLUMNS else Layout.SINGLE_COLUMN
        val currentPaddingSize = if (width >= minWidthForLargePadding) PaddingSize.LARGE else PaddingSize.SMALL

        if (currentLayout != lastLayout || currentPaddingSize != lastPaddingSize) {
            lastLayout = currentLayout
            lastPaddingSize = currentPaddingSize
            updateLayout()
        }
    }

    private fun updateLayout() {
        removeAll()

        val padding = when (lastPaddingSize) {
            PaddingSize.LARGE -> Design.Spacing.LG
            PaddingSize.SMALL -> Design.Spacing.SM
        }

        if (rightPanel.viewport.view is JPanel) {
            val contentPanel = rightPanel.viewport.view as JPanel
            contentPanel.border = BorderFactory.createEmptyBorder(padding, padding, padding, padding)
        }

        when (lastLayout) {
            Layout.TWO_COLUMNS -> {
                layout = GridBagLayout()
                val c = GridBagConstraints().apply {
                    fill = GridBagConstraints.BOTH
                    weighty = 1.0
                }

                c.gridx = 0
                c.gridy = 0
                c.weightx = 0.35
                add(leftPanel, c)

                c.gridx = 1
                c.weightx = 0.65
                add(rightPanel, c)
            }

            Layout.SINGLE_COLUMN -> {
                layout = BorderLayout()
                val singleColumnPanel = JPanel().apply {
                    layout = BoxLayout(this, BoxLayout.Y_AXIS)
                    background = Design.Colors.surface
                }

                val headerWrapper = JPanel(BorderLayout()).apply {
                    isOpaque = false
                    border = BorderFactory.createEmptyBorder(padding, padding, Design.Spacing.MD, padding)
                    add(leftPanel, BorderLayout.CENTER)
                }

                singleColumnPanel.add(headerWrapper)

                val scrollWrapper = JPanel(BorderLayout()).apply {
                    isOpaque = false
                    add(rightPanel, BorderLayout.CENTER)
                }
                singleColumnPanel.add(scrollWrapper)

                add(singleColumnPanel, BorderLayout.CENTER)
            }
        }

        revalidate()
        repaint()
    }
}