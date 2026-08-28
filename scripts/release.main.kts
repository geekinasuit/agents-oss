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
 *   scripts/release.main.kts --tag v0.1.0 [--notes-file notes.md] [--dry-run] [--skip-consumer-smoke]
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
 * Before publishing, a consumer-smoke gate extracts the just-built tarball and runs
 * `bazel test @<module>//...` against it from a throwaway consumer workspace — proving the
 * packaged bytes build and test as an EXTERNAL dependency (canonical name `<module>+`, not
 * the root's `_main`) rather than only as the root module. A real publish always runs it; a
 * dry run runs it too (so the dry run is the gate's first real exercise) and can skip it with
 * --skip-consumer-smoke to preview notes without the ~90s build. It is a MINIMAL consumer
 * config (a JDK 21 pin), a consumability floor — not a promise about any named downstream.
 *
 * Requirements: run from the repository root of a jj workspace (colocated or not) with a
 * clean working tree (asserted structurally: the working-copy commit must be empty); the
 * `gh` CLI authenticated for this repository; `bazel` on PATH (the consumer-smoke gate runs
 * it, on --dry-run too unless --skip-consumer-smoke); network (the forge is asked which tags exist,
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

/**
 * Run [cmd] in [dir] with its stdout and stderr streamed straight to this process's
 * terminal, returning the exit code. Distinct from [run], whose output is PARSED: here the
 * output is a ~90s bazel build the operator watches live, so it is inherited, not captured.
 */
fun runStreaming(dir: File, vararg cmd: String): Int =
    try {
        ProcessBuilder(*cmd).directory(dir).inheritIO().start().waitFor()
    } catch (e: java.io.IOException) {
        fail("could not run '${cmd.joinToString(" ")}' in $dir: ${e.message}")
    }

/**
 * Consumer-smoke gate: prove the just-built [asset] tarball builds and tests as an EXTERNAL
 * Bazel dependency before it is published. The tarball is extracted to a throwaway directory
 * (so exactly the shipped bytes are under test — this also catches a file the module needs
 * but forgot to track, which pointing at the working copy would silently pass), and a
 * throwaway consumer whose local_path_override names the extracted module pulls it in. As a
 * DEPENDENCY its canonical repo name resolves to `<module>+`, never the root module's
 * `_main` — the exact condition AGENCY-038 is about. `bazel test @<module>//...` must pass,
 * or the release is refused.
 *
 * This checks the module is consumable under a MINIMAL consumer config — a JDK 21 runtime
 * pin, which agency's test launcher needs (a 24+ runtime rejects the security-manager flag
 * its tests set) — NOT that any particular downstream's config works: coach, for one,
 * carries a --config=ci for a sandbox issue agents-oss does not have. It is a consumability
 * floor, not a promise about a named consumer.
 */
fun consumerSmoke(asset: File, moduleName: String, version: String) {
    val probeRoot = createTempDirectory("release-consumer-$moduleName").toFile()
    Runtime.getRuntime().addShutdownHook(Thread { probeRoot.deleteRecursively() })

    val moduleDir = File(probeRoot, "module")
    ReleaseCore.extractTarGz(asset, moduleDir)
    val bazelVersionFile = File(moduleDir, ".bazelversion")
    if (!bazelVersionFile.isFile) {
        fail("packaged tarball has no .bazelversion — the consumer smoke pins the module's bazel version from it")
    }

    val workspace = File(probeRoot, "consumer").apply { mkdirs() }
    File(workspace, "MODULE.bazel")
        .writeText(ReleaseCore.consumerProbeModule(moduleName, version, moduleDir.absolutePath))
    File(workspace, ".bazelversion").writeText(bazelVersionFile.readText().trim() + "\n")
    // Minimal consumer config, NOT coach's: only the JDK 21 runtime pin agency's test
    // launcher needs. Mirrors agents-oss's own .bazelrc, under which its CI is green.
    File(workspace, ".bazelrc").writeText(
        "common --java_runtime_version=21\ncommon --tool_java_runtime_version=21\ntest --test_output=errors\n"
    )
    // Its own output base under probeRoot, torn down with the rest, so the probe's Bazel
    // analysis and action state never mingle with the developer's default output base.
    val outputBase = File(probeRoot, "ob")

    println("consumer smoke: bazel test @$moduleName//... against the packaged tarball")
    val code = runStreaming(
        workspace,
        "bazel", "--output_base=${outputBase.absolutePath}", "test", "@$moduleName//...",
    )
    if (code != 0) {
        fail("consumer smoke FAILED (exit $code) — the packaged module does not build/test as an external dependency")
    }
    println("consumer smoke: passed")
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

    private val skipConsumerSmoke: Boolean by option(
        "--skip-consumer-smoke",
        help = "skip the consumer-smoke gate; honored ONLY with --dry-run (a real publish always runs it)." +
            " For previewing notes without the ~90s consumer build.",
    ).flag()

    override fun run() {
        val version = tag.removePrefix("v")

        // Argument check, up front: skipping the gate is a dry-run-only preview. Refusing it
        // here — before any fetch, tag query, or tarball build — makes it an argument error,
        // not work thrown away just before publish.
        if (skipConsumerSmoke && !dryRun) {
            fail("--skip-consumer-smoke is only valid with --dry-run; a real publish always runs the consumer-smoke gate")
        }

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

        // ---- consumer-smoke gate: the packaged module must build+test as an external dep ----
        // Runs before publish and refuses it on failure. A real publish ALWAYS runs it; a dry
        // run may skip it to preview notes without the ~90s consumer build (the skip-on-real-
        // publish misuse is already refused at the top of run(), so here skip implies dry run).
        if (skipConsumerSmoke) {
            println("consumer smoke: SKIPPED (--skip-consumer-smoke; dry run only)")
        } else {
            consumerSmoke(asset, moduleName, version)
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
