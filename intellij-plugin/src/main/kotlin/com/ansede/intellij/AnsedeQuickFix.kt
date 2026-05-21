package com.ansede.intellij

import com.intellij.codeInsight.intention.IntentionAction
import com.intellij.codeInspection.LocalQuickFix
import com.intellij.codeInspection.ProblemDescriptor
import com.intellij.openapi.editor.Editor
import com.intellij.openapi.project.Project
import com.intellij.psi.PsiFile

/**
 * Quick-fix action that inserts an ansede suppression comment at the problem line.
 *
 * Registered in plugin.xml as an intentionAction so that any diagnostic
 * produced by the ansede tool window can be suppressed directly from the editor.
 */
class AnsedeQuickFix : IntentionAction, LocalQuickFix {

    override fun getText(): String = "Suppress with ansede: ignore"

    override fun getFamilyName(): String = "Ansede Suppression"

    /**
     * Available when the caret is on a line containing an ansede diagnostic.
     */
    override fun isAvailable(project: Project, editor: Editor, file: PsiFile): Boolean {
        val caretLine = editor.caretModel.logicalPosition.line
        val text = file.text
        val lines = text.split("\n")
        if (caretLine >= lines.size) return false

        // Check if this line has an ansede finding marker in the tool window
        // (we use a heuristic: look for common CWE patterns in nearby comments)
        val lineText = lines[caretLine]
        return lineText.contains("CWE-") || lineText.contains("ansede")
    }

    /**
     * Insert an inline suppression comment at the end of the current line.
     */
    override fun invoke(project: Project, editor: Editor, file: PsiFile) {
        val caretLine = editor.caretModel.logicalPosition.line
        val document = editor.document
        val lineCount = document.lineCount
        if (caretLine >= lineCount) return

        val lineEndOffset = document.getLineEndOffset(caretLine)
        val lineText = document.getText(
            com.intellij.openapi.util.TextRange(
                document.getLineStartOffset(caretLine),
                lineEndOffset
            )
        )

        // Determine comment syntax based on file type
        val fileName = file.name
        val commentPrefix = when {
            fileName.endsWith(".py") -> "  # ansede: ignore"
            fileName.endsWith(".kt") || fileName.endsWith(".java") -> "  // ansede: ignore"
            fileName.endsWith(".js") || fileName.endsWith(".ts") || fileName.endsWith(".tsx") -> "  // ansede: ignore"
            fileName.endsWith(".go") -> "  // ansede: ignore"
            fileName.endsWith(".rb") -> "  # ansede: ignore"
            fileName.endsWith(".cs") -> "  // ansede: ignore"
            else -> "  // ansede: ignore"
        }

        val insertText = if (lineText.trimEnd().endsWith(commentPrefix.split(" ")[0].trim())) {
            // Line already has a comment — append the suppression token
            " [$TAG]"
        } else {
            " $commentPrefix"
        }

        document.insertString(lineEndOffset, insertText)
    }

    /**
     * IntentionAction startInWriteAction requirement.
     */
    override fun startInWriteAction(): Boolean = true

    /**
     * LocalQuickFix implementation for inspection tool window.
     */
    override fun applyFix(project: Project, descriptor: ProblemDescriptor) {
        // IntentionAction handles the actual edit; this is a stub
        // for the inspection integration path.
    }

    companion object {
        private const val TAG = "suppress"
    }
}
