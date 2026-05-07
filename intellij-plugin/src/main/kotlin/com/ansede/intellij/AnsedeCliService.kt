package com.ansede.intellij

import com.intellij.openapi.components.Service
import java.io.File

@Service(Service.Level.APP)
class AnsedeCliService {
    fun buildCommand(language: String): List<String> = listOf(
        resolveExecutable(),
        "--stdin",
        "--lang",
        language,
        "--format",
        "json",
        "--fail-on",
        "never",
        "--explain",
    )

    fun resolveExecutable(): String = System.getenv("ANSEDE_EXECUTABLE") ?: "ansede-static"

    fun isAvailable(): Boolean = try {
        val candidate = File(resolveExecutable())
        candidate.name.isNotBlank()
    } catch (_: Exception) {
        false
    }
}
