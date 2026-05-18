package com.ansede.intellij

import com.intellij.openapi.project.DumbAware
import com.intellij.openapi.project.Project
import com.intellij.openapi.wm.ToolWindow
import com.intellij.openapi.wm.ToolWindowFactory
import com.intellij.ui.components.JBLabel
import com.intellij.ui.content.ContentFactory
import com.intellij.util.ui.JBUI
import java.awt.BorderLayout
import javax.swing.*

/**
 * Ansede Static tool window — shows scan instructions when idle,
 * replaced with FindingsPanel after each scan.
 */
class AnsedeToolWindowFactory : ToolWindowFactory, DumbAware {
    override fun createToolWindowContent(project: Project, toolWindow: ToolWindow) {
        val panel = buildIdlePanel(project)
        val content = ContentFactory.getInstance().createContent(panel, "Overview", false)
        toolWindow.contentManager.addContent(content)
    }

    private fun buildIdlePanel(project: Project): JPanel {
        val panel = JPanel(BorderLayout()).apply {
            border = JBUI.Borders.empty(24)
        }

        val instructions = """
            <html>
            <div style='font-family: -apple-system, BlinkMacSystemFont, sans-serif; color: #888;'>
            <h2 style='font-weight:400; margin-bottom:12px;'>Ansede Static</h2>
            <p>Open a Python, JavaScript, TypeScript, Java, C#, or Go file, then:</p>
            <ul style='line-height:1.8'>
              <li><b>Tools → Scan Current File with Ansede</b></li>
              <li>Or right-click the editor → <b>Scan Current File with Ansede</b></li>
            </ul>
            <p style='margin-top:16px;'>Findings appear here with severity, CWE classification,<br>
            and AI-powered remediation suggestions.</p>
            <p style='margin-top:12px; font-size:11px;'>
            CLI: <code>ansede-static --help</code>  ·  Docs: <a href='https://github.com/mattybellx/Ansede'>github.com/mattybellx/Ansede</a>
            </p>
            </div>
            </html>
        """.trimIndent()

        panel.add(JBLabel(instructions), BorderLayout.NORTH)
        return panel
    }
}
