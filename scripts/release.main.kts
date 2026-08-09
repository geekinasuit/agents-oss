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
 * Notes: when --notes-file is absent, the notes are generated — a changelog of
 * merged-commit subjects since the previous release (the highest vX.Y.Z tag the FORGE
 * holds, newest first, PR numbers intact), closed by the consumer pin block. --dry-run
 * prints the notes that would ship, so they can be reviewed before a real publish. A tag
 * that already exists is refused, including on a dry run: publishing would bind the release
 * to that tag and drop the target commit, so the release is wrong either way, and the
 * pre-declared next version is what wants bumping.
 *
 * Requirements: run from the repository root of a jj workspace (colocated or not) with a
 * clean working tree; the `gh` CLI authenticated for this repository; network (the forge is
 * asked which tags exist, and clikt is fetched from Maven Central by the script runner on
 * first run). Generating notes additionally needs the previous release tag present in this
 * workspace, since the changelog range is resolved here; --notes-file skips that.
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

/** One finished subprocess: exit status and both streams, captured whole. */
data class Ran(val code: Int, val out: String, val err: String)

/**
 * Run [cmd] to completion and capture both streams separately. Stderr is captured rather
 * than merged because the stdout of these commands is PARSED — tag names, commit subjects,
 * the tracked fileset that becomes the tarball — so a tool's warning or hint must never
 * become a changelog line or a tarball entry. It goes to a file rather than a second pipe:
 * draining two pipes from one thread deadlocks as soon as either fills.
 */
fun run(vararg cmd: String): Ran {
    val errFile = File.createTempFile("release-stderr", ".txt").apply { deleteOnExit() }
    val process = ProcessBuilder(*cmd).redirectError(errFile).start()
    val out = process.inputStream.bufferedReader().readText()
    return Ran(process.waitFor(), out.trim(), errFile.readText().trim())
}

/** [run] the command, returning its stdout; any nonzero exit is a breakage, reported with
 * both streams so the operator sees what the tool actually said. */
fun exec(vararg cmd: String): String {
    val ran = run(*cmd)
    if (ran.code != 0) fail("command failed: ${cmd.joinToString(" ")}\n${ran.out}\n${ran.err}")
    return ran.out
}

/**
 * [run] the command where a nonzero exit is an ANSWER ("this revision does not resolve
 * here") rather than a breakage — returns the whole [Ran] so the caller can tell the answer
 * apart from a real failure by inspecting stderr, which a plain null cannot express.
 */
fun probe(vararg cmd: String): Ran = run(*cmd)

data class RepoFacts(val dirty: Boolean, val head: String, val files: String, val remote: String)

/**
 * Every tag the FORGE holds, across all pages. The forge is the authority, and TAGS are the
 * right question rather than releases: publishing binds the release to a pre-existing tag if
 * one is there — silently ignoring the target commit — so a tag without a release is exactly
 * the case a release-only view misses. It also sidesteps draft releases, which carry a tag
 * name but no tag, and the default page limit, which would silently truncate the answer.
 * A local tag list would not do: releases mint their tag server-side, so it is stale from the
 * moment the previous release published, and reading it would re-list already-published
 * commits in the next changelog — wrong in a way nothing downstream can detect.
 */
fun forgeTags(repoSlug: String): List<String> =
    exec("gh", "api", "repos/$repoSlug/tags", "--paginate", "--jq", ".[].name")
        .lines().map { it.trim() }.filter { it.isNotEmpty() }

/**
 * Highest vX.Y.Z tag by numeric component compare (so v0.10.0 outranks v0.9.0, which a
 * lexicographic compare gets backwards), or null when the repository holds no release tag.
 * Treated as the predecessor of the release being cut, which assumes releases are cut in
 * ascending order from one line of history — true of this module, and the assumption to
 * revisit first if a maintenance branch ever gets its own releases.
 */
fun highestReleaseTag(names: List<String>): String? =
    names
        .mapNotNull { name ->
            Regex("""v(\d+)\.(\d+)\.(\d+)""").matchEntire(name)
                ?.let { m -> name to m.groupValues.drop(1).map(String::toInt) }
        }
        .maxWithOrNull(compareBy({ it.second[0] }, { it.second[1] }, { it.second[2] }))
        ?.first

/** The previous release's commit as this workspace resolves it, or null when the workspace
 * has not fetched that tag. A nonzero exit for any other reason is a breakage, not an
 * answer: the two are told apart by jj's own "doesn't exist" wording, so a broken command
 * cannot masquerade as a missing tag. */
fun resolvePrevLocally(prevTag: String): String? {
    val ran = probe("jj", "log", "-r", prevTag, "-T", "commit_id", "--no-graph")
    if (ran.code == 0) return ran.out
    if (!ran.err.contains("doesn't exist")) {
        fail("could not resolve $prevTag in this workspace: ${ran.err}")
    }
    return null
}

/** Merged-commit subjects in prev..head, newest first — the literal first line of each
 * description, one per commit. Squash subjects carry their PR number already; nothing here
 * truncates or rewords. */
fun changelogSubjects(prev: String, head: String): List<String> =
    exec("jj", "log", "-r", "$prev..$head", "-T", "description.first_line() ++ \"\\n\"", "--no-graph")
        .lines().map { it.trim() }.filter { it.isNotEmpty() }

class Release : CliktCommand(name = "release") {
    override fun help(context: Context) =
        "Package the tracked fileset at HEAD as a source tarball and publish it as a GitHub release."

    private val tag: String by option(help = "release tag, shaped vX.Y.Z (e.g. v0.1.0)")
        .required()
        .validate { require(Regex("""v\d+\.\d+\.\d+""").matches(it)) { "tag must look like v0.1.0, was '$it'" } }

    private val notesFile: File? by option(help = "markdown file with the release notes; when absent, notes are generated (changelog since the previous tag + the consumer pin block)")
        .file(mustExist = true, canBeDir = false)

    private val dryRun: Boolean by option(help = "do everything except publish; print the gh command instead")
        .flag()

    override fun run() {
        val version = tag.removePrefix("v")

        // ---- repository facts ----
        if (!File("MODULE.bazel").isFile) fail("run from the repository root (MODULE.bazel not found)")
        // First name/version matches belong to the module() call, which precedes every
        // bazel_dep in this file.
        val moduleText = File("MODULE.bazel").readText()
        val moduleName = Regex("""name\s*=\s*"([^"]+)"""").find(moduleText)
            ?.groupValues?.get(1) ?: fail("could not read module name from MODULE.bazel")
        val moduleVersion = Regex("""version\s*=\s*"([^"]+)"""").find(moduleText)
            ?.groupValues?.get(1) ?: fail("could not read module version from MODULE.bazel")
        if (moduleVersion != version) {
            fail(
                "MODULE.bazel declares version $moduleVersion but this release is $tag" +
                    " — reconcile before tagging (MODULE.bazel pre-declares the next release's version)"
            )
        }

        if (!File(".jj").exists()) fail(".jj not found — this repository is worked with jj")

        val facts = RepoFacts(
            dirty = !exec("jj", "st").contains("The working copy has no changes."),
            head = exec("jj", "log", "-r", "@-", "-T", "commit_id", "--no-graph"),
            files = exec("jj", "file", "list", "-r", "@-"),
            remote = exec("jj", "git", "remote", "list").lineSequence().first()
                .substringAfter(' ').trim(),
        )
        if (facts.dirty) fail("working tree is dirty — commit or discard changes before releasing")

        val repoSlug = Regex("""github\.com[:/]([^/]+/[^/.\s]+)""").find(facts.remote)
            ?.groupValues?.get(1) ?: fail("could not parse a github.com owner/repo from remote '${facts.remote}'")

        // ---- previous release (for the generated changelog) ----
        val tags = forgeTags(repoSlug)
        // Publishing binds the release to a pre-existing tag and drops the target commit, so
        // an existing tag makes THIS release wrong whatever its release state — refused here
        // rather than at publish, and refused on a dry run too, since a dry run that prints
        // notes for a release that cannot be cut correctly is worse than no output.
        if (tag in tags) {
            fail(
                "$tag already exists as a tag — MODULE.bazel pre-declares the NEXT release's" +
                    " version, so bump it before cutting again"
            )
        }
        val prevTag = highestReleaseTag(tags)
        // A repository that has tags but none shaped vX.Y.Z would otherwise get the
        // first-release notes, which read as a fact rather than the inference they are.
        if (prevTag == null && tags.isNotEmpty()) {
            fail("no vX.Y.Z release tag among ${tags.size} tags — release-tag shape is what the changelog range is computed from")
        }

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

        // ---- notes: --notes-file verbatim, else generated (changelog + pin block) ----
        val notes = notesFile ?: File(workDir, "notes.md").apply {
            val heading = if (prevTag == null) "## Changes" else "## Changes since $prevTag"
            val changes = when {
                prevTag == null -> "First release tag in this repository."
                else -> {
                    // Only the generated path needs the predecessor present locally, which is
                    // why the check lives here: the changelog range is resolved in this
                    // workspace, so a tag published elsewhere (or before a fetch here) has to
                    // say what to do instead of surfacing a bare revision error.
                    if (resolvePrevLocally(prevTag) == null) {
                        fail(
                            "$prevTag exists on the forge but not in this workspace — fetch" +
                                " before releasing, or pass --notes-file to skip the generated changelog"
                        )
                    }
                    val subjects = changelogSubjects(prevTag, facts.head)
                    if (subjects.isEmpty()) "No merged changes since $prevTag."
                    else subjects.joinToString("\n") { "- $it" }
                }
            }
            writeText("$heading\n\n$changes\n\n## Consume from another Bazel module\n\n```\n$pinBlock\n```\n")
        }

        // ---- publish ----
        println("release $tag of $repoSlug at ${facts.head}")
        println("  asset:     $assetName (${asset.length()} bytes)")
        println("  integrity: $integrity")
        if (dryRun) {
            println("dry run — skipping: gh release create $tag ${asset.name} --repo $repoSlug --target ${facts.head}")
            println()
            println("--- release notes (${if (notesFile != null) "from --notes-file" else "generated"}) ---")
            println(notes.readText().trimEnd())
            println("--- end release notes ---")
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
