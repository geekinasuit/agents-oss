#!/usr/bin/env kotlin

@file:DependsOn("com.github.ajalt.clikt:clikt-jvm:5.1.0")
@file:DependsOn("org.apache.commons:commons-compress:1.27.1")
@file:Import("lib/ReleaseCore.kts")

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
 * holds, newest first, PR numbers intact), closed by the consumer pin block. When
 * --notes-file is given, its content ships as written PLUS the pin block appended — the
 * pin section is the one part a consumer actually needs, so no notes path omits it; a pin
 * block already in the supplied file is not detected, so it would ship duplicated.
 * --dry-run prints the notes that would ship, so they can be reviewed before a real
 * publish. A tag that already exists is refused, including on a dry run: publishing would
 * bind the release to that tag and drop the target commit, so the release is wrong either
 * way, and the pre-declared next version is what wants bumping.
 *
 * The archive is written with normalized entry metadata — fixed order (the tracked
 * fileset's), zero mtimes, zero uid/gid, mode by executable bit alone, no gzip timestamp
 * (see scripts/lib/ReleaseCore.kts for the exact contract and its honest residual) — so
 * its bytes are a function of the released commit's content. That is what makes the
 * dry-run pin block REAL: the hash a dry run prints is the hash the publish records.
 *
 * Requirements: run from the repository root of a jj workspace (colocated or not) with a
 * clean working tree (asserted structurally: the working-copy commit must be empty); the
 * `gh` CLI authenticated for this repository; network (the forge is asked which tags exist,
 * `jj git fetch` refreshes remote-tracking bookmarks so the target-commit-pushed check is a
 * local read, and clikt + commons-compress are fetched from Maven Central by the script
 * runner on first run). That fetch runs on --dry-run too, so a dry run updates remote-tracking
 * bookmarks — the one repository state a dry run changes. Generating notes additionally
 * needs the previous release tag present in this workspace, since the changelog range is
 * resolved here; --notes-file skips that.
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

/** The previous release's commit as this workspace resolves it, or null when the workspace
 * has not fetched that tag. A nonzero exit here is an ANSWER ("this revision does not
 * resolve here"), not a breakage — told apart from a real failure by jj's own "doesn't
 * exist" wording, so a broken command cannot masquerade as a missing tag. */
fun resolvePrevLocally(prevTag: String): String? {
    val ran = run("jj", "log", "-r", prevTag, "-T", "commit_id", "--no-graph")
    if (ran.code == 0) return ran.out
    if (!ran.err.contains("doesn't exist")) {
        fail("could not resolve $prevTag in this workspace: ${ran.err}")
    }
    return null
}

/** Merged-commit subjects in prev..head, newest first — the literal first line of each
 * description, one per commit. Squash subjects carry their PR number already; nothing here
 * truncates or rewords. Blank-description commits are dropped by ReleaseCore's filter,
 * which records that as a decision. */
fun changelogSubjects(prev: String, head: String): List<String> =
    ReleaseCore.changelogSubjects(
        exec("jj", "log", "-r", "$prev..$head", "-T", "description.first_line() ++ \"\\n\"", "--no-graph")
            .lines()
    )

class Release : CliktCommand(name = "release") {
    override fun help(context: Context) =
        "Package the tracked fileset at HEAD as a source tarball and publish it as a GitHub release."

    private val tag: String by option(help = "release tag, shaped vX.Y.Z (e.g. v0.1.0)")
        .required()
        .validate { require(Regex("""v\d+\.\d+\.\d+""").matches(it)) { "tag must look like v0.1.0, was '$it'" } }

    private val notesFile: File? by option(help = "markdown file with the release notes; ships as written plus the consumer pin block appended (do not include your own — it is always appended, so a duplicate would ship). When absent, notes are generated (changelog since the previous tag + the pin block)")
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
            // Structural, not prose: the working-copy commit must be empty. The tarball is
            // built from files on disk while --target names @-, so this gate is what makes
            // those the same bytes — and no status-message wording, commit description, or
            // tracked filename can talk it open (see ReleaseCore.isDirty).
            dirty = ReleaseCore.isDirty(exec("jj", "diff", "-r", "@", "--summary")),
            head = exec("jj", "log", "-r", "@-", "-T", "commit_id", "--no-graph"),
            files = exec("jj", "file", "list", "-r", "@-"),
            remote = try {
                ReleaseCore.pickRemoteUrl(exec("jj", "git", "remote", "list").lines())
            } catch (e: IllegalArgumentException) {
                fail(e.message ?: "could not choose a remote")
            },
        )
        if (facts.dirty) fail("working tree is dirty — commit or discard changes before releasing")

        val repoSlug = Regex("""github\.com[:/]([^/]+/[^/.\s]+)""").find(facts.remote)
            ?.groupValues?.get(1) ?: fail("could not parse a github.com owner/repo from remote '${facts.remote}'")

        // ---- refusals before any archive work ----
        // gh release create --target needs facts.head on the forge, and the dry run catches
        // that early. The clone already knows: a commit is pushed iff it is reachable from a
        // remote-tracking bookmark. Asking jj rather than the forge keeps this a clean local
        // yes/no — a network, auth, or rate-limit failure surfaces as a failed `jj git fetch`,
        // never as a false "not pushed" the way one gh exit code would. Fetch first so the
        // remote-tracking bookmarks reflect the forge now; gh release create stays the
        // authority if they drift before publish.
        exec("jj", "git", "fetch")
        val unpushed = exec(
            "jj", "log", "--no-graph", "-r", "${facts.head} ~ ::remote_bookmarks()", "-T", "commit_id"
        ).isNotBlank()
        if (unpushed) fail("target commit ${facts.head} is not on the forge — push before releasing")

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

        // ---- generated-notes preconditions, still before any archive work ----
        // Everything in this block belongs to the generated changelog, so --notes-file
        // skips all of it: a repository whose tags fit no release shape can still take a
        // hand-written release, because it is never asked the previous-release question.
        var prevTag: String? = null
        var changelogLines: List<String>? = null
        if (notesFile == null) {
            prevTag = ReleaseCore.highestReleaseTag(tags)
            // A repository that has tags but none shaped vX.Y.Z would otherwise get the
            // first-release notes, which read as a fact rather than the inference they are.
            if (prevTag == null && tags.isNotEmpty()) {
                fail("no vX.Y.Z release tag among ${tags.size} tags — release-tag shape is what the changelog range is computed from")
            }
            if (prevTag != null) {
                // Only the generated path needs the predecessor present locally: the
                // changelog range is resolved in this workspace, so a tag published
                // elsewhere (or before a fetch here) has to say what to do instead of
                // surfacing a bare revision error.
                if (resolvePrevLocally(prevTag) == null) {
                    fail(
                        "$prevTag exists on the forge but not in this workspace — fetch" +
                            " before releasing, or pass --notes-file to skip the generated changelog"
                    )
                }
                changelogLines = changelogSubjects(prevTag, facts.head)
            }
        }

        // ---- build the source tarball from the tracked fileset ----
        val assetName = "$moduleName-$tag.tar.gz"
        val workDir = createTempDirectory("release-$moduleName").toFile()
        // Cleanup on every exit path, fail() included — fail() exits the process, and a
        // shutdown hook is the one place that sees every exit. Nothing below hands out
        // workDir paths that outlive the run except the uploaded asset, which gh has
        // already read by then.
        Runtime.getRuntime().addShutdownHook(Thread { workDir.deleteRecursively() })
        val asset = File(workDir, assetName)
        val trackedPaths = facts.files.lines().map { it.trim() }.filter { it.isNotEmpty() }
        ReleaseCore.writeReproducibleTarGz(File("."), trackedPaths, asset)

        val digest = MessageDigest.getInstance("SHA-256").digest(asset.readBytes())
        val integrity = "sha256-" + Base64.getEncoder().encodeToString(digest)

        val assetUrl = "https://github.com/$repoSlug/releases/download/$tag/$assetName"
        val pinBlock = ReleaseCore.pinBlock(moduleName, version, assetUrl, integrity)

        // ---- notes: --notes-file plus the pin block, else generated (changelog + pin block) ----
        val notes = File(workDir, "notes.md").apply {
            val supplied = notesFile
            if (supplied != null) {
                writeText(supplied.readText().trimEnd() + "\n\n" + ReleaseCore.pinSection(pinBlock))
            } else {
                val heading = if (prevTag == null) "## Changes" else "## Changes since $prevTag"
                val changes = when {
                    prevTag == null -> "First release tag in this repository."
                    else -> {
                        val subjects = changelogLines.orEmpty()
                        if (subjects.isEmpty()) "No merged changes since $prevTag."
                        else subjects.joinToString("\n") { "- $it" }
                    }
                }
                writeText("$heading\n\n$changes\n\n" + ReleaseCore.pinSection(pinBlock))
            }
        }

        // ---- publish ----
        println("release $tag of $repoSlug at ${facts.head}")
        println("  asset:     $assetName (${asset.length()} bytes)")
        println("  integrity: $integrity")
        if (dryRun) {
            println("dry run — skipping: gh release create $tag ${asset.name} --repo $repoSlug --target ${facts.head}")
            println()
            println("--- release notes (${if (notesFile != null) "from --notes-file + pin block" else "generated"}) ---")
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
