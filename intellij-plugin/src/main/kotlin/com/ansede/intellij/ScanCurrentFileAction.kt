package com.ansede.intellij

import com.intellij.openapi.actionSystem.AnAction
import com.intellij.openapi.actionSystem.AnActionEvent
import com.intellij.openapi.actionSystem.CommonDataKeys
import com.intellij.openapi.application.ApplicationManager
import com.intellij.openapi.components.service
import com.intellij.openapi.fileEditor.FileDocumentManager
import com.intellij.openapi.progress.ProgressIndicator
import com.intellij.openapi.progress.ProgressManager
import com.intellij.openapi.progress.Task
import com.intellij.openapi.project.Project
import com.intellij.openapi.ui.Messages
import com.intellij.openapi.vfs.VirtualFile
import com.intellij.openapi.wm.ToolWindowManager

/**
 * Scans the currently active editor file with ansede-static and displays
 * findings in the Ansede tool window.
 *
 * Two modes:
 *  1. File on disk — passes the path directly to ansede-static
 *  2. Unsaved buffer — pipes editor content via stdin
 */
class ScanCurrentFileAction : AnAction() {

    override fun actionPerformed(event: AnActionEvent) {
        val project = event.project ?: return
        val editor = event.getData(CommonDataKeys.EDITOR) ?: return
        val virtualFile = event.getData(CommonDataKeys.VIRTUAL_FILE) ?: return

        val language = virtualFile.fileType.name
        val document = editor.document
        val isModified = FileDocumentManager.getInstance().isDocumentUnsaved(document)

        ProgressManager.getInstance().run(object : Task.Backgroundable(project, "Ansede: Scanning ${virtualFile.name}…", true) {
            var result: AnsedeCliService.ScanResult? = null

            override fun run(indicator: ProgressIndicator) {
                indicator.isIndeterminate = true
                indicator.text = "Running ansede-static on ${virtualFile.name}…"

                val service = project.service<AnsedeCliService>()

                result = if (isModified || !virtualFile.isInLocalFileSystem) {
                    // Pipe editor content via stdin for unsaved or non-local files
                    val source = ApplicationManager.getApplication().runReadAction<String> {
                        document.text
                    }
                    service.scanStdin(source, language)
                } else {
                    // Pass file path directly for on-disk files (supports cross-file analysis)
                    service.scanFile(virtualFile.path, language)
                }
            }

            override fun onSuccess() {
                val scanResult = result ?: return
                val findings = scanResult.findings
                val summary = scanResult.summary

                // Update tool window content
                val toolWindow = ToolWindowManager.getInstance(project).getToolWindow("Ansede")
                val contentManager = toolWindow?.contentManager ?: return

                val panel = FindingsPanel(project, findings, summary, virtualFile.name, scanResult.elapsedMs)
                val content = com.intellij.ui.content.ContentFactory.getInstance()
                    .createContent(panel, virtualFile.name, false)
                contentManager.removeAllContents(true)
                contentManager.addContent(content)
                toolWindow.show()

                if (findings.isEmpty()) {
                    Messages.showInfoMessage(
                        project,
                        "No findings in ${virtualFile.name} (${scanResult.elapsedMs}ms).",
                        "Ansede Static — Clean"
                    )
                }
            }

            override fun onError(error: Exception) {
                Messages.showErrorDialog(
                    project,
                    "ansede-static scan failed: ${error.message}",
                    "Ansede Static Error"
                )
            }
        })
    }

    override fun update(event: AnActionEvent) {
        val virtualFile = event.getData(CommonDataKeys.VIRTUAL_FILE)
        val supported = virtualFile != null && isSupportedFile(virtualFile)
        event.presentation.isEnabledAndVisible = supported
    }

    private fun isSupportedFile(file: VirtualFile): Boolean {
        val ext = file.extension?.lowercase() ?: return false
        return ext in setOf("py", "js", "ts", "jsx", "tsx", "java", "cs", "go", "php", "rb")
    }
}
