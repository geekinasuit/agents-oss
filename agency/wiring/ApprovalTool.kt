package com.geekinasuit.agency.wiring

import com.geekinasuit.agency.nostr.ApprovalSigning
import com.geekinasuit.agency.nostr.Bip340
import com.geekinasuit.agency.nostr.GateOpenNotice
import com.geekinasuit.agency.nostr.GiftWrapEncoding
import com.geekinasuit.agency.nostr.Nip59
import com.geekinasuit.agency.nostr.NostrFilter
import com.geekinasuit.agency.nostr.PublishResult
import com.geekinasuit.agency.nostr.ReconnectingPublisher
import com.geekinasuit.agency.nostr.ReconnectingSubscription
import com.geekinasuit.agency.nostr.ReconnectingSubscription.Delivery
import com.geekinasuit.agency.nostr.RecipientKey
import com.geekinasuit.agency.nostr.RelayAuth
import com.geekinasuit.agency.nostr.RelayConfig
import com.geekinasuit.agency.nostr.RelayConnection
import com.geekinasuit.agency.nostr.RelayMessage
import com.geekinasuit.agency.nostr.encodeApproval
import java.io.BufferedReader
import java.io.InputStreamReader
import java.io.PrintStream
import java.security.SecureRandom
import java.time.Duration
import java.time.Instant
import kotlin.system.exitProcess

/**
 * The approver's tool: read the gate-open notices a lead sent you over nostr, and approve one.
 *
 *  - `approval inbox --relay URL --key-file F --lead PUB [--auth none|nip42] [--wait SECONDS]` prints
 *    every notice addressed to the key in F that the lead PUB signed, once per nonce, each artifact
 *    as inert text.
 *  - `approval approve --relay URL --key-file F --lead PUB --nonce N [--auth …] [--wait …]` prints the
 *    notice for nonce N, then asks you to type the first [CONFIRM_CHARS] characters of its digest.
 *    Only then does it sign the approval, gift-wrap it to the lead and publish it, and it reports the
 *    relay's answer. What you type is the confirmation that you read what you are approving; nothing
 *    is signed without it.
 *
 * The key file holds your secret key as 64 hex characters; it is read into a clearable holder, zeroed,
 * and never printed. `--wait` (1 to 600, default 10) is how many seconds the relay has to send its
 * stored notices and EOSE; one that has not by then, reachable or not, is a refusal, not an empty
 * inbox. A connection attempt still under way when it runs out is let finish, which can add up to
 * the 10-second connect and authentication timeouts. `--auth` (default nip42) is whether the relay
 * needs NIP-42. Text from the lead or the relay is shown with every code point that is not visible
 * text escaped ([inert]). Exit 0 on success, 1 on a refusal, 2 on a usage error (checked before the
 * key file or the network is touched), each with a line on stderr saying why.
 */
object ApprovalTool {
  /** How many characters of the digest the approver types to confirm. */
  const val CONFIRM_CHARS = 8

  @JvmStatic
  fun main(args: Array<String>) {
    exitProcess(run(args.toList(), BufferedReader(InputStreamReader(System.`in`)), System.out, System.err))
  }

  /** [connect] opens a connection to a relay URL authenticating with a fresh holder of the key file at
   * the given path; a test replaces it. */
  fun run(
    args: List<String>,
    input: BufferedReader,
    out: PrintStream,
    err: PrintStream,
    connect: (url: String, keyFile: String) -> RelayConnection = ::defaultConnect,
  ): Int {
    val command = args.firstOrNull() ?: return usage(err, "no command")
    val allowed = COMMANDS[command] ?: return usage(err, "unknown command '$command'")
    val options =
      try {
        Options.of(command, flagsOf(args.drop(1), allowed))
      } catch (x: IllegalArgumentException) {
        return usage(err, x.message ?: "bad arguments")
      }
    return try {
      val newConnection = { connect(options.relay, options.keyFile) }
      val notices = inbox(newConnection, options)
      when (command) {
        "inbox" -> {
          if (notices.isEmpty()) out.println("no gate-open notices from the lead")
          notices.forEach { show(it, out) }
          0
        }
        else -> {
          val nonce = checkNotNull(options.nonce)
          val notice = notices.firstOrNull { it.nonce == nonce } ?: throw IllegalArgumentException("no notice for nonce $nonce")
          show(notice, out)
          // Restated next to the prompt: a long artifact pushes the header out of view.
          out.println(
            "approving ${inert(notice.gateId)}: artifact of ${notice.artifact.count { it == '\n' } + 1} line(s), " +
              "${notice.artifact.codePointCount(0, notice.artifact.length)} character(s), digest ${notice.payloadDigest}"
          )
          out.print("type the first $CONFIRM_CHARS characters of the digest to approve: ")
          out.flush()
          if (input.readLine()?.trim() != notice.payloadDigest.take(CONFIRM_CHARS)) {
            err.println("approval: not approved")
            return 1
          }
          publish(notice, newConnection, options, out)
        }
      }
    } catch (x: IllegalArgumentException) {
      err.println("approval: ${inert(x.message.orEmpty())}")
      1
    } catch (x: java.io.IOException) {
      err.println("approval: ${x.javaClass.simpleName}: ${inert(x.message.orEmpty())}")
      1
    }
  }

  // The flags, each checked before anything touches the key or the network, so a bad one is a usage
  // error (exit 2).
  private class Options(
    val relay: String,
    val keyFile: String,
    val lead: String,
    val auth: RelayAuth,
    val wait: Duration,
    val nonce: String?,
  ) {
    companion object {
      fun of(command: String, flags: Map<String, String>): Options {
        val relay = flags.required("--relay")
        require(relay.startsWith("ws://") || relay.startsWith("wss://")) { "--relay must be a ws:// or wss:// URL" }
        val lead =
          try {
            RecipientKey.of(flags.required("--lead")).hex
          } catch (x: IllegalArgumentException) {
            throw IllegalArgumentException("--lead: ${x.message}")
          }
        val auth =
          when (flags["--auth"] ?: "nip42") {
            "nip42" -> RelayAuth.Nip42(TIMEOUT)
            "none" -> RelayAuth.None
            else -> throw IllegalArgumentException("--auth is none or nip42")
          }
        val waitSeconds = flags["--wait"]?.let { w -> w.toLongOrNull()?.takeIf { it in 1..600 } ?: throw IllegalArgumentException("--wait is 1 to 600 seconds") } ?: 10
        val nonce = if (command == "approve") flags.required("--nonce") else null
        return Options(relay, flags.required("--key-file"), lead, auth, Duration.ofSeconds(waitSeconds), nonce)
      }
    }
  }

  // A fresh holder per connection, cleared here if the connection cannot even be built around it.
  private fun defaultConnect(url: String, keyFile: String): RelayConnection {
    val key = readSecretKeyFile(keyFile)
    try {
      return RelayConnection(RelayConfig(url, key))
    } catch (x: Throwable) {
      key.clear()
      throw x
    }
  }

  // The notices addressed to the key in the key file from the lead, once per nonce, in arrival order.
  // Only a relay that sends its stored events and then EOSE has answered: one that cannot be reached,
  // refuses us, or drops the subscription before EOSE until --wait runs out is a refusal, never an
  // empty inbox.
  private fun inbox(newConnection: () -> RelayConnection, options: Options): List<GateOpenNotice> {
    val key = readSecretKeyFile(options.keyFile)
    try {
      val me = key.useKeyBytes { Bip340.xonlyPubkeyFromKeyBytes(it) }
      val filter = NostrFilter(kinds = listOf(Nip59.GIFT_WRAP_KIND), tags = mapOf('p' to listOf(me)))
      val subscription = ReconnectingSubscription(newConnection, TIMEOUT, options.auth, SUBSCRIPTION_ID, listOf(filter), BACKOFF)
      val byNonce = linkedMapOf<String, GateOpenNotice>()
      val deadline = Instant.now().plus(options.wait)
      var answered = false
      var lastFault: String? = null
      try {
        while (!answered && Instant.now().isBefore(deadline)) {
          when (val d = subscription.next(Duration.ofMillis(200))) {
            is Delivery.Received ->
              when (val m = d.message) {
                is RelayMessage.Eose -> if (m.subscriptionId == SUBSCRIPTION_ID) answered = true
                is RelayMessage.Event -> {
                  if (m.subscriptionId != SUBSCRIPTION_ID) continue
                  val rumor = key.useKeyBytes { Nip59.unwrap(it, m.event) } ?: continue
                  val notice = ApprovalSigning.decodeNotice(rumor, options.lead) ?: continue
                  byNonce.putIfAbsent(notice.nonce, notice)
                }
                else -> Unit
              }
            is Delivery.Unavailable -> lastFault = d.detail
            is Delivery.Interrupted -> lastFault = d.detail
            else -> Unit
          }
        }
      } finally {
        subscription.close()
      }
      if (!answered) {
        throw IllegalArgumentException(
          "the relay did not finish sending its stored notices within ${options.wait.seconds}s" +
            (lastFault?.let { " (last: $it)" } ?: "")
        )
      }
      return byNonce.values.toList()
    } finally {
      key.clear()
    }
  }

  private fun publish(notice: GateOpenNotice, newConnection: () -> RelayConnection, options: Options, out: PrintStream): Int {
    val lead = options.lead
    val key = readSecretKeyFile(options.keyFile)
    val wrap =
      try {
        key.useKeyBytes { bytes ->
          val carrier = ApprovalSigning.sign(notice, bytes, freshHex())
          val now = Instant.now().epochSecond
          val encoding =
            encodeApproval(bytes, RecipientKey.of(lead), carrier, now, now - random.nextInt(SEAL_BACKDATE_SECONDS), freshHex(), freshHex())
          (encoding as? GiftWrapEncoding.Wrapped)?.event ?: throw IllegalArgumentException("the approval is too large to wrap")
        }
      } finally {
        key.clear()
      }
    val publisher = ReconnectingPublisher(newConnection, TIMEOUT, options.auth)
    try {
      return when (val result = publisher.publish(wrap, TIMEOUT)) {
        PublishResult.Accepted -> {
          out.println("approved ${inert(notice.gateId)}: the relay accepted it")
          0
        }
        is PublishResult.Rejected -> throw IllegalArgumentException("the relay rejected the approval: ${result.message.take(200)}")
        is PublishResult.Failed -> throw IllegalArgumentException("the approval was not sent: ${result.detail.take(200)}")
      }
    } finally {
      publisher.close()
    }
  }

  private fun show(notice: GateOpenNotice, out: PrintStream) {
    out.println("gate:   ${inert(notice.gateId)}")
    out.println("nonce:  ${inert(notice.nonce)}")
    out.println("digest: ${notice.payloadDigest}")
    out.println("----- artifact -----")
    out.println(inert(notice.artifact, keepLines = true))
    out.println("----- end -----")
  }

  /**
   * Text from the lead or the relay, shown inert, so it can neither drive the terminal nor reorder or
   * hide what the approver reads. A code point is shown as itself only when it is a letter, mark,
   * number, punctuation mark, symbol or space separator ([SHOWN_CATEGORIES]) and not a default
   * ignorable code point ([isDefaultIgnorable]), which renders as nothing. Every other code point —
   * controls, format characters, line and paragraph separators, surrogates, private use, unassigned
   * — is shown as an escape: \uXXXX, or \u{XXXXX} above U+FFFF. A backslash is shown as \\, so an
   * escape in the text cannot pass for one this made. With [keepLines], newline and tab are kept.
   *
   * It walks code points, so a character outside the Basic Multilingual Plane is judged whole. A code
   * point the running JDK's Unicode tables do not know is unassigned, so it is escaped.
   */
  internal fun inert(text: String, keepLines: Boolean = false): String = buildString {
    text.codePoints().forEach { cp ->
      when {
        cp == '\\'.code -> append("\\\\")
        keepLines && (cp == '\n'.code || cp == '\t'.code) -> appendCodePoint(cp)
        Character.getType(cp) in SHOWN_CATEGORIES && !isDefaultIgnorable(cp) -> appendCodePoint(cp)
        cp > 0xFFFF -> append("\\u{%x}".format(cp))
        else -> append("\\u%04x".format(cp))
      }
    }
  }

  /** Whether [cp] is a Default_Ignorable_Code_Point, per DerivedCoreProperties.txt of Unicode 15.0
   * (the version JDK 21 implements): code points a renderer shows as nothing. */
  internal fun isDefaultIgnorable(cp: Int): Boolean = DEFAULT_IGNORABLE.any { cp in it }

  private val DEFAULT_IGNORABLE: List<IntRange> =
    listOf(
      0x00AD..0x00AD,
      0x034F..0x034F,
      0x061C..0x061C,
      0x115F..0x1160,
      0x17B4..0x17B5,
      0x180B..0x180F,
      0x200B..0x200F,
      0x202A..0x202E,
      0x2060..0x206F,
      0x3164..0x3164,
      0xFE00..0xFE0F,
      0xFEFF..0xFEFF,
      0xFFA0..0xFFA0,
      0xFFF0..0xFFF8,
      0x1BCA0..0x1BCA3,
      0x1D173..0x1D17A,
      0xE0000..0xE0FFF,
    )

  private fun usage(err: PrintStream, why: String): Int {
    err.println("approval: $why")
    err.println(
      "usage: approval inbox --relay URL --key-file F --lead PUB [--auth none|nip42] [--wait S] | " +
        "approval approve --relay URL --key-file F --lead PUB --nonce N [--auth none|nip42] [--wait S]"
    )
    return 2
  }

  private val random = SecureRandom()

  private fun freshHex(): String {
    val bytes = ByteArray(32)
    random.nextBytes(bytes)
    return bytes.joinToString("") { "%02x".format(it) }
  }

  // The general categories inert() shows as themselves: letters, marks, numbers, punctuation,
  // symbols, and the space separator.
  internal val SHOWN_CATEGORIES: Set<Int> =
    setOf(
        Character.UPPERCASE_LETTER, Character.LOWERCASE_LETTER, Character.TITLECASE_LETTER,
        Character.MODIFIER_LETTER, Character.OTHER_LETTER,
        Character.NON_SPACING_MARK, Character.COMBINING_SPACING_MARK, Character.ENCLOSING_MARK,
        Character.DECIMAL_DIGIT_NUMBER, Character.LETTER_NUMBER, Character.OTHER_NUMBER,
        Character.CONNECTOR_PUNCTUATION, Character.DASH_PUNCTUATION, Character.START_PUNCTUATION,
        Character.END_PUNCTUATION, Character.INITIAL_QUOTE_PUNCTUATION, Character.FINAL_QUOTE_PUNCTUATION,
        Character.OTHER_PUNCTUATION,
        Character.MATH_SYMBOL, Character.CURRENCY_SYMBOL, Character.MODIFIER_SYMBOL, Character.OTHER_SYMBOL,
        Character.SPACE_SEPARATOR,
      )
      .map { it.toInt() }
      .toSet()

  private const val SUBSCRIPTION_ID = "notices"
  private val TIMEOUT: Duration = Duration.ofSeconds(10)
  private val BACKOFF = ReconnectingSubscription.Backoff(Duration.ofMillis(500), Duration.ofSeconds(5))

  // NIP-17's "up to two days in the past" for the seal; the wrap carries the real time.
  private const val SEAL_BACKDATE_SECONDS = 2 * 24 * 60 * 60

  private val COMMON = setOf("--relay", "--key-file", "--lead", "--auth", "--wait")
  private val COMMANDS = mapOf("inbox" to COMMON, "approve" to COMMON + "--nonce")
}
