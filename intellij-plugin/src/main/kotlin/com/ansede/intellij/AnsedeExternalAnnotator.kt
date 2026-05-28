package com.ansede.intellij

import com.intellij.lang.annotation.AnnotationHolder
import com.intellij.lang.annotation.ExternalAnnotator
import com.intellij.lang.annotation.HighlightSeverity
import com.intellij.openapi.application.ApplicationManager
import com.intellij.openapi.diagnostic.Logger
import com.intellij.openapi.editor.Editor
import com.intellij.openapi.util.TextRange
import com.intellij.psi.PsiFile

/**
 * Inline annotator that highlights ansede-static findings as error squiggles
 * directly in the editor.
 *
 * Registered in plugin.xml as an externalAnnotator for supported file types.
 * The annotator runs the CLI and maps findings to editor highlights.
 */
class AnsedeExternalAnnotator : ExternalAnnotator<PsiFile, List<AnsedeCliService.Finding>>() {

    private val log = Logger.getInstance(AnsedeExternalAnnotator::class.java)

    /**
     * Phase 1: Collect the file to analyse. Called in the background read-action.
     */
    override fun collectInformation(file: PsiFile): PsiFile {
        return file
    }

    /**
     * Phase 2 (optional): Collect information with an editor reference for more
     * precise highlighting ranges. Called on the EDT with a held read-action.
     */
    override fun collectInformation(file: PsiFile, editor: Editor, hasErrors: Boolean): PsiFile {
        return file
    }

    /**
     * Phase 3: Run the analysis and return findings. Called in a background
     * read-action — safe to invoke the CLI here.
     */
    override fun doAnnotate(file: PsiFile): List<AnsedeCliService.Finding>? {
        val virtualFile = file.virtualFile ?: return null
        val project = file.project

        // Only supported file types
        val ext = virtualFile.extension?.lowercase() ?: return null
        if (ext !in setOf("py", "js", "ts", "jsx", "tsx", "java", "cs", "go", "rb", "php")) {
            return null
        }

        return try {
            val service = ApplicationManager.getApplication().getService(AnsedeCliService::class.java)
            val code = String(virtualFile.contentsToByteArray())
            val response = service.scanStdin(code, virtualFile.extension ?: "py")
            if (response.exitCode != 0) {
                log.warn("Annotator scan failed for ${virtualFile.name}: ${response.stderr}")
                null
            } else {
                response.findings
            }
        } catch (e: Exception) {
            log.warn("Annotator exception for ${virtualFile.name}: ${e.message}")
            null
        }
    }

    /**
     * Phase 4: Apply findings as editor annotations. Called on the EDT.
     */
    override fun apply(file: PsiFile, findings: List<AnsedeCliService.Finding>?, holder: AnnotationHolder) {
        if (findings.isNullOrEmpty()) return

        for (finding in findings) {
            val line = finding.line
            if (line == null || line < 1) continue

            val document = file.viewProvider.document ?: continue
            if (line > document.lineCount) continue

            val lineStart = document.getLineStartOffset(line - 1)
            val lineEnd = document.getLineEndOffset(line - 1)

            val severity = when (finding.severity.lowercase()) {
                "critical", "high" -> HighlightSeverity.ERROR
                "medium" -> HighlightSeverity.WARNING
                else -> HighlightSeverity.WEAK_WARNING
            }

            val cweTag = if (finding.cwe.isNotEmpty()) " [${finding.cwe}]" else ""
            val message = "${finding.title}$cweTag — ${finding.description}"

            holder.newAnnotation(severity, message)
                .range(TextRange(lineStart, lineEnd))
                .tooltip(message)
                .create()
        }
    }
}
