package com.ansede.intellij

import com.intellij.openapi.project.DumbAware
import com.intellij.openapi.project.Project
import com.intellij.openapi.wm.ToolWindow
import com.intellij.openapi.wm.ToolWindowFactory
import com.intellij.ui.content.ContentFactory
import javax.swing.JLabel
import javax.swing.JPanel

class AnsedeToolWindowFactory : ToolWindowFactory, DumbAware {
    override fun createToolWindowContent(project: Project, toolWindow: ToolWindow) {
        val panel = JPanel()
        panel.add(JLabel("Ansede IntelliJ scaffold: connect scan summaries and remediation previews here."))
        val content = ContentFactory.getInstance().createContent(panel, "Overview", false)
        toolWindow.contentManager.addContent(content)
    }
}
