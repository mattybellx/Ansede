package com.ansede.intellij

import com.intellij.icons.AllIcons
import com.intellij.ui.JBColor
import com.intellij.ui.components.JBScrollPane
import com.intellij.ui.table.JBTable
import com.intellij.util.ui.JBUI
import java.awt.BorderLayout
import java.awt.Color
import java.awt.Font
import javax.swing.*
import javax.swing.table.DefaultTableModel
import javax.swing.table.TableRowSorter

/**
 * Displays ansede-static scan findings in a sortable table with severity
 * color-coding and a summary header.
 */
class FindingsPanel(
    private val project: com.intellij.openapi.project.Project,
    findings: List<AnsedeCliService.Finding>,
    summary: AnsedeCliService.ScanSummary,
    fileName: String,
    elapsedMs: Long
) : JPanel(BorderLayout()) {

    private val columns = arrayOf("#", "Severity", "CWE", "Rule", "Line", "Confidence", "Title")
    private val tableModel = object : DefaultTableModel(columns, 0) {
        override fun isCellEditable(row: Int, column: Int) = false
        override fun getColumnClass(columnIndex: Int): Class<*> = when (columnIndex) {
            0 -> Int::class.java
            4 -> Int::class.java
            5 -> String::class.java
            else -> String::class.java
        }
    }

    init {
        // ── Header Panel ──────────────────────────────────────────
        val header = buildHeader(summary, fileName, elapsedMs)
        add(header, BorderLayout.NORTH)

        // ── Findings Table ────────────────────────────────────────
        val table = JBTable(tableModel).apply {
            setSelectionMode(ListSelectionModel.SINGLE_SELECTION)
            autoResizeMode = JTable.AUTO_RESIZE_LAST_COLUMN
            rowHeight = 24
            font = Font("JetBrains Mono", Font.PLAIN, 12)

            // Column widths
            columnModel.getColumn(0).preferredWidth = 35
            columnModel.getColumn(1).preferredWidth = 70
            columnModel.getColumn(2).preferredWidth = 70
            columnModel.getColumn(3).preferredWidth = 80
            columnModel.getColumn(4).preferredWidth = 45
            columnModel.getColumn(5).preferredWidth = 65
            columnModel.getColumn(6).preferredWidth = 400
        }

        // Sort by severity then line
        val sorter = TableRowSorter(tableModel)
        sorter.setComparator(1) { a: Any, b: Any ->
            severityRank(a.toString()) - severityRank(b.toString())
        }
        sorter.setComparator(4) { a: Any, b: Any ->
            (a as? Int ?: 0) - (b as? Int ?: 0)
        }
        table.rowSorter = sorter

        // Populate rows
        findings.sortedByDescending { severityRank(it.severity) }
            .forEachIndexed { idx, f ->
                tableModel.addRow(arrayOf(
                    idx + 1,
                    f.severity.uppercase(),
                    f.cwe,
                    f.rule_id,
                    f.line,
                    "${(f.confidence * 100).toInt()}%",
                    f.title
                ))
            }

        val scrollPane = JBScrollPane(table).apply {
            border = JBUI.Borders.empty()
        }
        add(scrollPane, BorderLayout.CENTER)

        // ── Detail Panel ──────────────────────────────────────────
        if (findings.isNotEmpty()) {
            val detailArea = JTextArea().apply {
                isEditable = false
                font = Font("JetBrains Mono", Font.PLAIN, 11)
                rows = 6
                background = JBColor(0xF7F7F7, 0x2B2B2B)
                border = JBUI.Borders.empty(8)
            }

            // Show detail on row selection
            table.selectionModel.addListSelectionListener {
                val row = table.selectedRow
                if (row >= 0) {
                    val modelRow = table.convertRowIndexToModel(row)
                    val f = findings.getOrNull(modelRow)
                    if (f != null) {
                        detailArea.text = buildString {
                            appendLine("▸ ${f.title}")
                            appendLine()
                            appendLine(f.description.ifBlank { "(no description)" })
                            if (f.remediation.isNotBlank()) {
                                appendLine()
                                appendLine("┌─ Remediation ──────────────────────────────")
                                appendLine(f.remediation)
                                appendLine("└────────────────────────────────────────────")
                            }
                            if (f.auto_fix.isNotBlank()) {
                                appendLine()
                                appendLine("┌─ Auto-Fix ─────────────────────────────────")
                                appendLine(f.auto_fix)
                                appendLine("└────────────────────────────────────────────")
                            }
                        }
                        detailArea.caretPosition = 0
                    }
                }
            }

            // Select first row
            table.setRowSelectionInterval(0, 0)

            val splitPane = JSplitPane(JSplitPane.VERTICAL_SPLIT, scrollPane, JBScrollPane(detailArea)).apply {
                resizeWeight = 0.6
                dividerLocation = 220
            }
            remove(scrollPane)
            add(splitPane, BorderLayout.CENTER)
        }

        border = JBUI.Borders.empty()
    }

    // ── Header Builder ────────────────────────────────────────────

    private fun buildHeader(summary: AnsedeCliService.ScanSummary, fileName: String, elapsedMs: Long): JPanel {
        val panel = JPanel().apply {
            layout = BoxLayout(this, BoxLayout.Y_AXIS)
            border = JBUI.Borders.compound(
                JBUI.Borders.empty(12, 16, 8, 16),
                JBUI.Borders.customLine(JBColor.border(), 0, 0, 1, 0)
            )
        }

        val titleLabel = JLabel("<html><b style='font-size:14px'>$fileName</b></html>")
        panel.add(titleLabel)

        val total = summary.total_findings
        val stats = buildString {
            append("<html><span style='color:#666'>")
            if (total == 0) {
                append("✓ No findings")
            } else {
                append("$total finding${if (total != 1) "s" else ""}")
                if (summary.critical > 0) append("  ● ${summary.critical} critical")
                if (summary.high > 0) append("  ● ${summary.high} high")
                if (summary.medium > 0) append("  ● ${summary.medium} medium")
                if (summary.low > 0) append("  ● ${summary.low} low")
            }
            append("  ·  ${elapsedMs}ms")
            if (summary.engine_version.isNotBlank()) append("  ·  v${summary.engine_version}")
            append("</span></html>")
        }
        panel.add(JLabel(stats))
        panel.add(Box.createVerticalStrut(4))

        return panel
    }

    private fun severityRank(severity: String): Int = when (severity.lowercase()) {
        "critical" -> 5
        "high" -> 4
        "medium" -> 3
        "low" -> 2
        "info", "note" -> 1
        else -> 0
    }
}
