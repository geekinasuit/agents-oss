#!/usr/bin/env kotlin

@file:DependsOn("com.github.ajalt.clikt:clikt-jvm:5.1.0")

/**
 * Release automation: packages the repository's tracked files into a source tarball,
 * computes its SRI integrity, publishes a GitHub release with the tarball as an asset,
 * and prints the ready-to-paste `bazel_dep` + `archive_override` block for consumers.
 *
 * Usage:
 *   scripts/release.main.kts --tag v0.1.0 [--notes-file notes.md] [--dry-run]
 *
 * Requirements: run from the repository root with a clean working tree; the `gh` CLI
 * authenticated for this repository; network on first run (clikt is fetched from Maven
 * Central by the script runner). Works in plain git clones and in jj workspaces
 * (including non-colocated ones, where no `.git` directory exists).
 */

import com.github.ajalt.clikt.core.CliktCommand
import com.github.ajalt.clikt.core.Context
import com.github.ajalt.clikt.core.main
import com.github.ajalt.clikt.parameters.options.flag
import com.github.ajalt.clikt.parameters.options.option
import com.github.ajalt.clikt.parameters.options.required
import com.github.ajalt.clikt.parameters.options.validate
import com.github.ajalt.clikt.parameters.types.file
import java.io.File
import java.security.MessageDigest
import java.util.Base64
import kotlin.io.path.createTempDirectory
import kotlin.system.exitProcess

fun fail(message: String): Nothing {
    System.err.println("error: $message")
    exitProcess(1)
}

fun exec(vararg cmd: String): String {
    val process = ProcessBuilder(*cmd).redirectErrorStream(true).start()
    val output = process.inputStream.bufferedReader().readText()
    if (process.waitFor() != 0) fail("command failed: ${cmd.joinToString(" ")}\n$output")
    return output.trim()
}

data class RepoFacts(val dirty: Boolean, val head: String, val files: String, val remote: String)

class Release : CliktCommand(name = "release") {
    override fun help(context: Context) =
        "Package the tracked fileset at HEAD as a source tarball and publish it as a GitHub release."

    private val tag: String by option(help = "release tag, shaped vX.Y.Z (e.g. v0.1.0)")
        .required()
        .validate { require(Regex("""v\d+\.\d+\.\d+""").matches(it)) { "tag must look like v0.1.0, was '$it'" } }

    private val notesFile: File? by option(help = "markdown file with the release notes; defaults to a generated consumer pin block")
        .file(mustExist = true, canBeDir = false)

    private val dryRun: Boolean by option(help = "do everything except publish; print the gh command instead")
        .flag()

    override fun run() {
        val version = tag.removePrefix("v")

        // ---- repository facts (git clone or jj workspace) ----
        if (!File("MODULE.bazel").isFile) fail("run from the repository root (MODULE.bazel not found)")
        val moduleName = Regex("""name\s*=\s*"([^"]+)"""").find(File("MODULE.bazel").readText())
            ?.groupValues?.get(1) ?: fail("could not read module name from MODULE.bazel")

        val isGit = File(".git").exists()
        val isJj = File(".jj").exists()
        if (!isGit && !isJj) fail("neither .git nor .jj found — not a repository root?")

        val facts = if (isGit) {
            RepoFacts(
                dirty = exec("git", "status", "--porcelain").isNotEmpty(),
                head = exec("git", "rev-parse", "HEAD"),
                files = exec("git", "ls-files"),
                remote = exec("git", "remote", "get-url", "origin"),
            )
        } else {
            RepoFacts(
                dirty = !exec("jj", "st").contains("The working copy has no changes."),
                head = exec("jj", "log", "-r", "@-", "-T", "commit_id", "--no-graph"),
                files = exec("jj", "file", "list", "-r", "@-"),
                remote = exec("jj", "git", "remote", "list").lineSequence().first()
                    .substringAfter(' ').trim(),
            )
        }
        if (facts.dirty) fail("working tree is dirty — commit or discard changes before releasing")

        val repoSlug = Regex("""github\.com[:/]([^/]+/[^/.\s]+)""").find(facts.remote)
            ?.groupValues?.get(1) ?: fail("could not parse a github.com owner/repo from remote '${facts.remote}'")

        // ---- build the source tarball from the tracked fileset ----
        val assetName = "$moduleName-$tag.tar.gz"
        val workDir = createTempDirectory("release-$moduleName").toFile()
        val fileList = File(workDir, "files.txt").apply { writeText(facts.files + "\n") }
        val asset = File(workDir, assetName)
        exec("tar", "czf", asset.absolutePath, "-T", fileList.absolutePath)

        val digest = MessageDigest.getInstance("SHA-256").digest(asset.readBytes())
        val integrity = "sha256-" + Base64.getEncoder().encodeToString(digest)

        val assetUrl = "https://github.com/$repoSlug/releases/download/$tag/$assetName"
        val pinBlock = """
            bazel_dep(name = "$moduleName", version = "$version")
            archive_override(
                module_name = "$moduleName",
                urls = ["$assetUrl"],
                integrity = "$integrity",
            )
        """.trimIndent()

        // ---- notes ----
        val notes = notesFile ?: File(workDir, "notes.md").apply {
            writeText("Consume from another Bazel module:\n\n```\n$pinBlock\n```\n")
        }

        // ---- publish ----
        println("release $tag of $repoSlug at ${facts.head}")
        println("  asset:     $assetName (${asset.length()} bytes)")
        println("  integrity: $integrity")
        if (dryRun) {
            println("dry run — skipping: gh release create $tag ${asset.name} --repo $repoSlug --target ${facts.head}")
        } else {
            exec(
                "gh", "release", "create", tag, asset.absolutePath,
                "--repo", repoSlug, "--target", facts.head,
                "--title", tag, "--notes-file", notes.absolutePath,
            )
            println("published: https://github.com/$repoSlug/releases/tag/$tag")
        }
        println()
        println(pinBlock)
    }
}

Release().main(args)
