#!/usr/bin/env kotlin

@file:DependsOn("org.apache.commons:commons-compress:1.27.1")
@file:Import("lib/ReleaseCore.kts")

/*
 * Hermetic tests for scripts/lib/ReleaseCore.kts — no network, no jj, no gh; every cell
 * exercises a pure function or the archive writer against a temp-dir fixture.
 *
 * The reproducibility cells assert the property AGENCY-037 item 1 is about, in the DoD's
 * direct form: every archive entry carries normalized mtime/uid/gid/mode and the caller's
 * ordering, the gzip header carries no timestamp, and a rebuild after re-touching every
 * fixture mtime is byte-identical. (Two builds in one unchanged context would pass a
 * gzip-timestamp-only fix; the re-touch between builds plus the per-entry assertions are
 * what make these cells discriminating.)
 */

import org.apache.commons.compress.archivers.tar.TarArchiveEntry
import org.apache.commons.compress.archivers.tar.TarArchiveInputStream
import java.io.File
import java.nio.file.Files
import java.util.zip.GZIPInputStream
import kotlin.io.path.createTempDirectory
import kotlin.system.exitProcess

var failures = 0

fun ok(name: String, condition: Boolean) {
    if (condition) println("PASS $name") else { failures++; println("FAIL $name") }
}

fun <T> eq(name: String, expected: T, actual: T) {
    if (expected == actual) println("PASS $name")
    else { failures++; println("FAIL $name: expected $expected, got $actual") }
}

fun refuses(name: String, block: () -> Unit) {
    try { block(); failures++; println("FAIL $name: no refusal") }
    catch (e: IllegalArgumentException) { println("PASS $name") }
}

// ---- highestReleaseTag ----

eq("numeric compare beats lexicographic", "v0.10.0",
    ReleaseCore.highestReleaseTag(listOf("v0.9.0", "v0.10.0")))
eq("non-conforming names are skipped", "v1.2.3",
    ReleaseCore.highestReleaseTag(listOf("v1.2.3", "foo", "v1.2", "v1.2.3-rc1")))
eq("no release-shaped tag yields null", null,
    ReleaseCore.highestReleaseTag(listOf("foo", "release-2020")))
eq("empty list yields null", null, ReleaseCore.highestReleaseTag(emptyList()))
// The forge is the authority precisely because it is not this script's own state; anyone
// with push access can create a malformed tag, and it must not crash the release of a
// well-formed one. A component too long even for Long is skipped like any other
// non-conforming name — no NumberFormatException.
eq("a beyond-Long digit run is skipped, not thrown", "v0.1.0",
    ReleaseCore.highestReleaseTag(listOf("v99999999999999999999.0.0", "v0.1.0")))
eq("a beyond-Int digit run now parses (Long components)", "v99999999999.0.0",
    ReleaseCore.highestReleaseTag(listOf("v99999999999.0.0", "v0.1.0")))

// ---- isDirty ----

eq("empty diff summary is clean", false, ReleaseCore.isDirty(""))
eq("whitespace-only summary is clean", false, ReleaseCore.isDirty("  \n"))
eq("a modified file is dirty", true, ReleaseCore.isDirty("M scripts/release.main.kts"))
// The old gate matched jj's status PROSE, so a tracked file named like the clean-tree
// sentence (or a commit whose first description line contained it) read as clean — the
// fails-open shape AGENCY-037 item 2 records. Structurally, the same input is a summary
// line like any other and correctly reads dirty.
eq("the old fails-open sentinel now reads dirty", true,
    ReleaseCore.isDirty("A The working copy has no changes."))

// ---- pickRemoteUrl ----

eq("origin preferred by name over line order", "https://github.com/geekinasuit/agents-oss.git",
    ReleaseCore.pickRemoteUrl(listOf(
        "upstream https://github.com/other/x.git",
        "origin https://github.com/geekinasuit/agents-oss.git",
    )))
eq("a single non-origin remote is unambiguous", "git@github.com:me/fork.git",
    ReleaseCore.pickRemoteUrl(listOf("fork git@github.com:me/fork.git")))
refuses("several remotes and no origin is ambiguous") {
    ReleaseCore.pickRemoteUrl(listOf("fork git@github.com:me/x.git", "upstream https://github.com/other/x.git"))
}
refuses("no remotes at all") { ReleaseCore.pickRemoteUrl(emptyList()) }

// ---- changelogSubjects ----

// Blank lines are empty-description commits: dropped as a decision (the changelog
// under-reports the commit count by design, never the content).
eq("blank descriptions drop, subjects survive verbatim", listOf("subj one (#12)", "subj two"),
    ReleaseCore.changelogSubjects(listOf("subj one (#12)", "", "   ", "subj two")))

// ---- writeReproducibleTarGz ----

val fixtureRoot = createTempDirectory("release-test-fixture").toFile()
Runtime.getRuntime().addShutdownHook(Thread { fixtureRoot.deleteRecursively() })
File(fixtureRoot, "a").mkdirs()
File(fixtureRoot, "b").mkdirs()
File(fixtureRoot, "zed.txt").writeText("last alphabetically, first in the list\n")
File(fixtureRoot, "a/one.txt").writeText("plain file\n")
File(fixtureRoot, "b/two.sh").apply { writeText("#!/bin/sh\necho hi\n"); setExecutable(true) }
// Deliberately NOT sorted: the contract is the CALLER's order (jj's tracked fileset), and
// the entry-order cell below fails if the writer re-sorts or iterates the filesystem.
val paths = listOf("zed.txt", "a/one.txt", "b/two.sh")

val out1 = File(fixtureRoot, "build1.tar.gz")
ReleaseCore.writeReproducibleTarGz(fixtureRoot, paths, out1)
val bytes1 = out1.readBytes()

// Re-touch every fixture mtime to distinct values, then rebuild: byte-identical output is
// the content-function-of-the-commit property. (The observed v0.1.1 dry-run/publish split
// was 21 seconds of wall clock in one byte of gzip header; per-entry mtimes varied too.)
var t = 1_000_000_000_000L
for (p in paths) { File(fixtureRoot, p).setLastModified(t); t += 977_000L }
val out2 = File(fixtureRoot, "build2.tar.gz")
ReleaseCore.writeReproducibleTarGz(fixtureRoot, paths, out2)
ok("rebuild after re-touching every mtime is byte-identical", bytes1.contentEquals(out2.readBytes()))

// The gzip header's MTIME field (bytes 4-7) — where the v0.1.1 hash split lived.
ok("gzip header carries no timestamp",
    bytes1[4] == 0.toByte() && bytes1[5] == 0.toByte() && bytes1[6] == 0.toByte() && bytes1[7] == 0.toByte())

val entries = mutableListOf<TarArchiveEntry>()
TarArchiveInputStream(GZIPInputStream(out1.inputStream())).use { tar ->
    var e = tar.nextEntry
    while (e != null) { entries.add(e as TarArchiveEntry); e = tar.nextEntry }
}
eq("entries appear in the caller's order", paths, entries.map { it.name })
for (e in entries) {
    eq("entry ${e.name} mtime is zero", 0L, e.modTime.time)
    eq("entry ${e.name} uid is zero", 0L, e.longUserId)
    eq("entry ${e.name} gid is zero", 0L, e.longGroupId)
    eq("entry ${e.name} user name is empty", "", e.userName)
    eq("entry ${e.name} group name is empty", "", e.groupName)
}
eq("plain file mode is 644", "644".toInt(8), entries.first { it.name == "a/one.txt" }.mode and "777".toInt(8))
eq("executable mode is 755", "755".toInt(8), entries.first { it.name == "b/two.sh" }.mode and "777".toInt(8))

// Entry names are pinned to UTF-8, not the JVM default charset (writeReproducibleTarGz is
// constructed with an explicit charset). This reads the raw ustar name field — the first
// 100 bytes of the uncompressed tar, NUL-padded — and asserts UTF-8. It pins the contract:
// a UTF-8-default JVM would pass this under the single-arg constructor too, so the value is
// the regression it catches on a non-UTF-8 default or a future writer change.
val utf8Name = "café.txt"  // café.txt — 'é' is C3 A9 in UTF-8, E9 in Latin-1
File(fixtureRoot, utf8Name).writeText("unicode name\n")
val utf8Out = File(fixtureRoot, "build-utf8.tar.gz")
ReleaseCore.writeReproducibleTarGz(fixtureRoot, listOf(utf8Name), utf8Out)
val utf8Tar = GZIPInputStream(utf8Out.inputStream()).use { it.readBytes() }
val nameField = utf8Tar.copyOfRange(0, 100).takeWhile { it != 0.toByte() }.toByteArray()
eq("non-ASCII entry name is encoded UTF-8",
    utf8Name.toByteArray(Charsets.UTF_8).toList(), nameField.toList())

// Symlinks are refused loudly rather than silently archived as their target's content.
Files.createSymbolicLink(File(fixtureRoot, "sneaky-link").toPath(), File(fixtureRoot, "zed.txt").toPath())
refuses("a tracked symlink is refused") {
    ReleaseCore.writeReproducibleTarGz(fixtureRoot, listOf("sneaky-link"), File(fixtureRoot, "build3.tar.gz"))
}
refuses("a directory path is refused") {
    ReleaseCore.writeReproducibleTarGz(fixtureRoot, listOf("a"), File(fixtureRoot, "build4.tar.gz"))
}

// ---- pin block shape ----

val pin = ReleaseCore.pinBlock("agency", "0.2.0", "https://example.com/agency-v0.2.0.tar.gz", "sha256-abc")
ok("pin block names the module and version",
    "bazel_dep(name = \"agency\", version = \"0.2.0\")" in pin)
ok("pin block carries the integrity", "integrity = \"sha256-abc\"," in pin)
ok("pin section fences the block", ReleaseCore.pinSection(pin).let { "```" in it && pin in it })

// ---- verdict ----

if (failures > 0) {
    System.err.println("$failures failure(s)")
    exitProcess(1)
}
println("all release core tests passed")
