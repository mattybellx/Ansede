package com.ansede.intellij

import com.google.gson.Gson
import com.google.gson.reflect.TypeToken
import com.intellij.openapi.application.ApplicationManager
import com.intellij.openapi.components.Service
import com.intellij.openapi.diagnostic.Logger
import java.io.BufferedReader
import java.io.File
import java.io.InputStreamReader
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Path
import java.util.concurrent.TimeUnit

@Service(Service.Level.APP)
class AnsedeCliService {

    private val logger = Logger.getInstance(AnsedeCliService::class.java)
    private val gson = Gson()

    /**
     * Map of IntelliJ language IDs to ansede-static --lang values.
     */
    private val languageMap = mapOf(
        "Python" to "python",
        "JavaScript" to "javascript",
        "TypeScript" to "typescript",
        "JSX Harmony" to "javascript",
        "TypeScript JSX" to "typescript",
        "JAVA" to "java",
        "C#" to "csharp",
        "Go" to "go",
    )

    // ── CLI Command Building ──────────────────────────────────────

    fun buildCommand(language: String, filePath: String? = null): List<String> {
        val args = mutableListOf(resolveExecutable())
        if (filePath != null) {
            args.add(filePath)
        } else {
            args.add("--stdin")
        }
        args.addAll(listOf("--lang", mapLanguage(language), "--format", "json", "--fail-on", "never"))
        return args
    }

    fun mapLanguage(intellijLang: String): String =
        languageMap[intellijLang] ?: "auto"

    fun resolveExecutable(): String =
        System.getenv("ANSEDE_EXECUTABLE") ?: defaultExecutablePath()

    private fun defaultExecutablePath(): String {
        val os = System.getProperty("os.name").lowercase()
        val home = System.getProperty("user.home")
        return when {
            os.contains("win") -> "$home\\AppData\\Local\\ansede\\ansede-static.exe"
            os.contains("mac") -> "/usr/local/bin/ansede-static"
            else -> "/usr/local/bin/ansede-static"
        }
    }

    fun isAvailable(): Boolean = try {
        val candidate = File(resolveExecutable())
        candidate.exists() && candidate.canExecute()
    } catch (_: Exception) {
        false
    }

    // ── Scanning ──────────────────────────────────────────────────

    data class ScanResult(
        val findings: List<Finding>,
        val summary: ScanSummary,
        val elapsedMs: Long,
        val exitCode: Int,
        val stderr: String
    )

    data class Finding(
        val rule_id: String = "",
        val cwe: String = "",
        val title: String = "",
        val description: String = "",
        val severity: String = "medium",
        val confidence: Double = 0.0,
        val line: Int = 0,
        val column: Int = 0,
        val file: String = "",
        val remediation: String = "",
        val auto_fix: String = ""
    )

    data class ScanSummary(
        val total_findings: Int = 0,
        val critical: Int = 0,
        val high: Int = 0,
        val medium: Int = 0,
        val low: Int = 0,
        val files_scanned: Int = 1,
        val engine_version: String = ""
    )

    /**
     * Scan a file on disk and return parsed findings.
     */
    fun scanFile(filePath: String, language: String): ScanResult {
        val start = System.currentTimeMillis()
        val cmd = buildCommand(language, filePath)
        return executeScan(cmd, start)
    }

    /**
     * Scan source code provided as a string via stdin.
     */
    fun scanStdin(source: String, language: String): ScanResult {
        val start = System.currentTimeMillis()
        val cmd = buildCommand(language, null)
        return executeScanWithInput(cmd, source, start)
    }

    // ── Internal Execution ────────────────────────────────────────

    private fun executeScan(cmd: List<String>, startMs: Long): ScanResult {
        return try {
            val pb = ProcessBuilder(cmd)
                .redirectErrorStream(false)
            val proc = pb.start()
            val stdout = proc.inputStream.bufferedReader(StandardCharsets.UTF_8).readText()
            val stderr = proc.errorStream.bufferedReader(StandardCharsets.UTF_8).readText()
            val exited = proc.waitFor(30, TimeUnit.SECONDS)
            val exitCode = if (exited) proc.exitValue() else -1
            val elapsed = System.currentTimeMillis() - startMs
            parseOutput(stdout, stderr, exitCode, elapsed)
        } catch (e: Exception) {
            logger.warn("ansede-static scan failed: ${e.message}")
            ScanResult(
                findings = emptyList(),
                summary = ScanSummary(),
                elapsedMs = System.currentTimeMillis() - startMs,
                exitCode = -1,
                stderr = e.message ?: "unknown error"
            )
        }
    }

    private fun executeScanWithInput(cmd: List<String>, stdin: String, startMs: Long): ScanResult {
        return try {
            val pb = ProcessBuilder(cmd)
                .redirectErrorStream(false)
            val proc = pb.start()
            proc.outputStream.bufferedWriter(StandardCharsets.UTF_8).use { writer ->
                writer.write(stdin)
                writer.flush()
            }
            val stdout = proc.inputStream.bufferedReader(StandardCharsets.UTF_8).readText()
            val stderr = proc.errorStream.bufferedReader(StandardCharsets.UTF_8).readText()
            val exited = proc.waitFor(30, TimeUnit.SECONDS)
            val exitCode = if (exited) proc.exitValue() else -1
            val elapsed = System.currentTimeMillis() - startMs
            parseOutput(stdout, stderr, exitCode, elapsed)
        } catch (e: Exception) {
            logger.warn("ansede-static stdin scan failed: ${e.message}")
            ScanResult(
                findings = emptyList(),
                summary = ScanSummary(),
                elapsedMs = System.currentTimeMillis() - startMs,
                exitCode = -1,
                stderr = e.message ?: "unknown error"
            )
        }
    }

    /**
     * Parse ansede-static --format json output into structured data.
     * Handles v2.x output format with "findings" array and optional "summary" block.
     */
    private fun parseOutput(stdout: String, stderr: String, exitCode: Int, elapsedMs: Long): ScanResult {
        if (stdout.isBlank()) {
            return ScanResult(
                findings = emptyList(),
                summary = ScanSummary(),
                elapsedMs = elapsedMs,
                exitCode = exitCode,
                stderr = stderr
            )
        }

        return try {
            // Try new v2 format: { "findings": [...], "summary": {...}, ... }
            val rootType = object : TypeToken<Map<String, Any>>() {}.type
            val root: Map<String, Any> = gson.fromJson(stdout.trim(), rootType)

            @Suppress("UNCHECKED_CAST")
            val findingsRaw = root["findings"] as? List<Map<String, Any>> ?: emptyList()
            val findings = findingsRaw.map { raw ->
                Finding(
                    rule_id = raw["rule_id"] as? String ?: "",
                    cwe = raw["cwe"] as? String ?: "",
                    title = raw["title"] as? String ?: "",
                    description = raw["description"] as? String ?: "",
                    severity = (raw["severity"] as? String)?.lowercase() ?: "medium",
                    confidence = (raw["confidence"] as? Number)?.toDouble() ?: 0.0,
                    line = (raw["line"] as? Number)?.toInt() ?: 0,
                    column = (raw["column"] as? Number)?.toInt() ?: 0,
                    file = raw["file"] as? String ?: "",
                    remediation = raw["remediation"] as? String ?: "",
                    auto_fix = raw["auto_fix"] as? String ?: ""
                )
            }

            @Suppress("UNCHECKED_CAST")
            val summaryRaw = root["summary"] as? Map<String, Any> ?: emptyMap()
            val summary = ScanSummary(
                total_findings = findings.size,
                critical = findings.count { it.severity == "critical" },
                high = findings.count { it.severity == "high" },
                medium = findings.count { it.severity == "medium" },
                low = findings.count { it.severity == "low" },
                files_scanned = (summaryRaw["files_scanned"] as? Number)?.toInt() ?: 1,
                engine_version = summaryRaw["engine_version"] as? String ?: ""
            )

            ScanResult(findings, summary, elapsedMs, exitCode, stderr)
        } catch (e: Exception) {
            // Fallback: try parsing as flat findings array
            tryParseFlatArray(stdout, stderr, exitCode, elapsedMs) ?: ScanResult(
                findings = emptyList(),
                summary = ScanSummary(),
                elapsedMs = elapsedMs,
                exitCode = exitCode,
                stderr = "Parse error: ${e.message}\n$stderr"
            )
        }
    }

    private fun tryParseFlatArray(stdout: String, stderr: String, exitCode: Int, elapsedMs: Long): ScanResult? {
        return try {
            val listType = object : TypeToken<List<Map<String, Any>>>() {}.type
            val rawList: List<Map<String, Any>> = gson.fromJson(stdout.trim(), listType)
            val findings = rawList.map { raw ->
                Finding(
                    rule_id = raw["rule_id"] as? String ?: "",
                    cwe = raw["cwe"] as? String ?: "",
                    title = raw["title"] as? String ?: "",
                    severity = (raw["severity"] as? String)?.lowercase() ?: "medium",
                    confidence = (raw["confidence"] as? Number)?.toDouble() ?: 0.0,
                    line = (raw["line"] as? Number)?.toInt() ?: 0,
                    column = (raw["column"] as? Number)?.toInt() ?: 0,
                    file = raw["file"] as? String ?: "",
                    remediation = raw["remediation"] as? String ?: ""
                )
            }
            val summary = ScanSummary(
                total_findings = findings.size,
                critical = findings.count { it.severity == "critical" },
                high = findings.count { it.severity == "high" },
                medium = findings.count { it.severity == "medium" },
                low = findings.count { it.severity == "low" }
            )
            ScanResult(findings, summary, elapsedMs, exitCode, stderr)
        } catch (_: Exception) {
            null
        }
    }
}
