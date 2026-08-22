/*
 * Pure logic for the release script, held apart from the command flow so it is testable:
 * tag selection, the dirty gate, remote choice, changelog filtering, and the
 * reproducible-archive writer. Everything here is a function of its arguments — no
 * subprocesses, no network — which is what lets scripts/release.test.main.kts exercise it
 * hermetically.
 *
 * API returns stdlib types only. The .main.kts script compiler crashes with an
 * undiagnosable FIR error when an importing script's declarations name a type declared in
 * an imported .kts file, so nothing here leaks a library-declared type across the boundary.
 *
 * Dependency note: an @file:Import-ed .kts cannot carry its own @file:DependsOn — every
 * importer declares org.apache.commons:commons-compress for the archive writer below.
 */

import org.apache.commons.compress.archivers.tar.TarArchiveEntry
import org.apache.commons.compress.archivers.tar.TarArchiveOutputStream
import java.io.File
import java.nio.file.Files
import java.util.zip.GZIPOutputStream

object ReleaseCore {

    /**
     * Highest vX.Y.Z tag by numeric component compare (so v0.10.0 outranks v0.9.0, which a
     * lexicographic compare gets backwards), or null when the repository holds no release
     * tag. Components parse via toLongOrNull: a digit run too long for the type is treated
     * exactly like a non-conforming name and skipped, rather than throwing — tag names come
     * from the forge, which anyone with push access can extend, so a malformed tag must not
     * crash the release of a well-formed one.
     *
     * Treated as the predecessor of the release being cut, which assumes releases are cut
     * in ascending order from one line of history — true of this module, and the assumption
     * to revisit first if a maintenance branch ever gets its own releases.
     */
    fun highestReleaseTag(names: List<String>): String? =
        names
            .mapNotNull { name ->
                val m = Regex("""v(\d+)\.(\d+)\.(\d+)""").matchEntire(name) ?: return@mapNotNull null
                val parts = m.groupValues.drop(1).map { it.toLongOrNull() ?: return@mapNotNull null }
                name to parts
            }
            .maxWithOrNull(compareBy({ it.second[0] }, { it.second[1] }, { it.second[2] }))
            ?.first

    /**
     * The dirty gate, asked structurally: [diffSummary] is the output of
     * `jj diff -r @ --summary`, and a clean tree is exactly an empty working-copy commit.
     * No prose is matched, so no commit description, filename, or future jj rewording can
     * make a dirty tree read clean — a tracked file NAMED like jj's old status sentence
     * shows up here as a summary line and correctly reads dirty.
     */
    fun isDirty(diffSummary: String): Boolean = diffSummary.isNotBlank()

    /**
     * The push remote's URL from `jj git remote list` output (lines shaped "name url").
     * Prefers `origin` by name; with no origin and exactly one remote, that remote; with no
     * origin among several, refuses — line order is not a choice, and for an OSS
     * contributor (fork + upstream) the first line deciding where a release publishes is
     * the wrong kind of surprise. Throws IllegalArgumentException with the reason; the
     * caller renders it as a refusal.
     */
    fun pickRemoteUrl(remoteListLines: List<String>): String {
        val remotes = remoteListLines
            .map { it.trim() }.filter { it.isNotEmpty() }
            .map { line -> line.substringBefore(' ') to line.substringAfter(' ').trim() }
        require(remotes.isNotEmpty()) { "no git remotes configured — add one before releasing" }
        val origin = remotes.firstOrNull { it.first == "origin" }
        if (origin != null) return origin.second
        if (remotes.size == 1) return remotes.single().second
        throw IllegalArgumentException(
            "multiple remotes and none named origin (${remotes.joinToString { it.first }}) — " +
                "the release target is ambiguous; name one origin"
        )
    }

    /**
     * Changelog lines from raw `jj log` first-line-per-commit output. Blank lines are
     * dropped, and that drop is a decision, not a trimming side effect: a commit with an
     * empty description has nothing to say in a changelog, so it contributes no line — the
     * changelog under-reports the commit COUNT by design, never the content.
     */
    fun changelogSubjects(rawLines: List<String>): List<String> =
        rawLines.map { it.trim() }.filter { it.isNotEmpty() }

    /**
     * Writes [out] as a tar.gz of [trackedPaths] (repo-root-relative, archived in the given
     * order) whose bytes are a function of the paths' CONTENT alone. Every axis tar would
     * take from the environment is pinned: entry order is the caller's list (jj's tracked
     * fileset, not directory iteration), entry names are encoded UTF-8 (an explicit charset
     * on the writer — the single-argument constructor would encode a short non-ASCII name
     * with the JVM's default charset, so one commit could archive to different bytes on two
     * machines), mtime is 0, uid/gid are 0 with empty user/group names, and mode is 0644 or
     * 0755 by the executable bit alone. The gzip layer is the JDK's, whose header carries
     * MTIME=0 — the byte the observed v0.1.1 dry-run/publish hash split lived in.
     *
     * Honest residual: the DEFLATE stream is the JDK's zlib. Entry metadata is canonical,
     * so the uncompressed tar payload is reproducible anywhere; re-deriving the COMPRESSED
     * hash assumes a matching deflate implementation, which holds run-to-run and
     * machine-to-machine on the same JDK line but is not a cross-toolchain guarantee.
     *
     * Symlinks are refused loudly: reading one through File.readBytes would silently
     * archive the target's content as a regular file, changing meaning without changing
     * the hash's apparent provenance.
     */
    fun writeReproducibleTarGz(repoRoot: File, trackedPaths: List<String>, out: File) {
        GZIPOutputStream(out.outputStream().buffered()).use { gz ->
            TarArchiveOutputStream(gz, "UTF-8").use { tar ->
                tar.setLongFileMode(TarArchiveOutputStream.LONGFILE_POSIX)
                for (path in trackedPaths) {
                    val f = File(repoRoot, path)
                    require(!Files.isSymbolicLink(f.toPath())) {
                        "tracked symlink at $path — the reproducible writer archives regular files only"
                    }
                    require(f.isFile) { "tracked path is not a regular file: $path" }
                    val entry = TarArchiveEntry(path)
                    entry.size = f.length()
                    entry.setModTime(0L)
                    entry.setUserId(0)
                    entry.setGroupId(0)
                    entry.userName = ""
                    entry.groupName = ""
                    entry.mode = if (f.canExecute()) "755".toInt(8) else "644".toInt(8)
                    tar.putArchiveEntry(entry)
                    f.inputStream().use { it.copyTo(tar) }
                    tar.closeArchiveEntry()
                }
            }
        }
    }

    /** The ready-to-paste consumer block; also the tail of generated release notes. */
    fun pinBlock(moduleName: String, version: String, assetUrl: String, integrity: String): String =
        """
        bazel_dep(name = "$moduleName", version = "$version")
        archive_override(
            module_name = "$moduleName",
            urls = ["$assetUrl"],
            integrity = "$integrity",
        )
        """.trimIndent()

    /** The notes section that carries [pinBlock]; appended to hand-written notes too, so a
     * --notes-file release is not the one kind that ships without the section a consumer
     * actually needs. */
    fun pinSection(pinBlock: String): String =
        "## Consume from another Bazel module\n\n```\n$pinBlock\n```\n"
}
