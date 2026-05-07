package com.ansede.intellij

import com.intellij.openapi.actionSystem.AnAction
import com.intellij.openapi.actionSystem.AnActionEvent
import com.intellij.openapi.application.ApplicationManager
import com.intellij.openapi.components.service
import com.intellij.openapi.ui.Messages

class ScanCurrentFileAction : AnAction() {
    override fun actionPerformed(event: AnActionEvent) {
        val project = event.project ?: return
        val service = project.service<AnsedeCliService>()
        ApplicationManager.getApplication().executeOnPooledThread {
            val command = service.buildCommand("python").joinToString(" ")
            Messages.showInfoMessage(project, "Scaffold command: $command", "Ansede Static")
        }
    }
}
