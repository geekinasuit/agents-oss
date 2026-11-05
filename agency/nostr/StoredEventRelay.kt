package com.geekinasuit.agency.nostr

import java.util.concurrent.CopyOnWriteArrayList
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.long

/**
 * A relay double with a store, for cells about WHICH stored events a client gets back: a [FakeRelay]
 * only sends what a script tells it to. It answers each REQ the way a relay that follows NIP-01 does,
 * newest `created_at` first and the lowest id first among equals, cut to the filter's `limit` and to
 * [clamp], then EOSE. A REQ stays subscribed, so [publish] sends a matching event to it live, until a
 * CLOSE or a REQ under the same id.
 *
 * It reads one filter per REQ, and `kinds`, `#<letter>` tags, `until` and `limit` in it, the parts of
 * a filter this repo sends. A second filter fails the relay's thread, and so does any other key,
 * once a stored event reaches it. [untilOrder] picks how it reads `until`: NIP-01's "at or before",
 * or "before", for a cell that must hold on a relay that reads the boundary differently from the NIP.
 *
 * It is a test double, not a relay. What a real relay does with `until` is checked against that relay.
 *
 * Usage: construct it, [store] what the relay holds, call [serveOneConnection] once per connection the
 * cell expects, and point a [RelayConnection] at [url].
 */
class StoredEventRelay(
  private val untilOrder: UntilOrder,
  private val clamp: Int = DEFAULT_CLAMP,
) : AutoCloseable {

  /** How a relay reads `until`. */
  enum class UntilOrder {
    AT_OR_BEFORE,
    BEFORE,
  }

  private val relay = FakeRelay()
  val url: String = relay.url

  /** Every REQ the relay was sent, as text, in order. */
  val requests = CopyOnWriteArrayList<String>()

  /** The id of every subscription the relay has ended on a CLOSE, in order. */
  val closed = CopyOnWriteArrayList<String>()

  private val lock = Any()
  private val stored = mutableListOf<NostrEvent>()
  private val subscribed = LinkedHashMap<String, JsonObject>()
  private var session: FakeRelay.Session? = null

  /** Add [events] to what the relay holds, and send none of them live. */
  fun store(vararg events: NostrEvent) = synchronized(lock) { stored += events }

  /** Add [event] to what the relay holds, and send it to each open subscription it matches. */
  fun publish(event: NostrEvent) =
    synchronized(lock) {
      stored += event
      for ((id, filter) in subscribed) if (matches(event, filter)) session?.sendText(eventFrame(id, event))
    }

  /** Accept one connection and answer it until the client goes away. */
  fun serveOneConnection() =
    relay.serve { client ->
      synchronized(lock) {
        session = client
        subscribed.clear()
      }
      while (true) answer(client, client.nextClientText(IDLE_MILLIS) ?: break)
      synchronized(lock) { if (session === client) session = null }
    }

  /** Re-raise anything the relay's thread threw. Call after the client-side assertions. */
  fun assertClean() = relay.assertScriptClean()

  override fun close() = relay.close()

  private fun answer(client: FakeRelay.Session, frame: String) {
    val message = Json.parseToJsonElement(frame).jsonArray
    val id = message[1].jsonPrimitive.content
    when (message[0].jsonPrimitive.content) {
      "REQ" -> {
        requests += frame
        check(message.size == 3) { "the stored-event relay reads one filter per REQ, got $frame" }
        val filter = message[2].jsonObject
        synchronized(lock) {
          subscribed[id] = filter
          for (event in query(filter)) client.sendText(eventFrame(id, event))
          client.sendText("[\"EOSE\",\"$id\"]")
        }
      }
      "CLOSE" -> {
        synchronized(lock) { subscribed.remove(id) }
        closed += id
      }
      else -> error("the stored-event relay does not handle $frame")
    }
  }

  private fun query(filter: JsonObject): List<NostrEvent> =
    stored
      .filter { matches(it, filter) }
      .sortedWith(compareByDescending<NostrEvent> { it.createdAt }.thenBy { it.id })
      .take(minOf(filter["limit"]?.jsonPrimitive?.long ?: Long.MAX_VALUE, clamp.toLong()).toInt())

  private fun matches(event: NostrEvent, filter: JsonObject): Boolean =
    filter.all { (key, value) ->
      when {
        key == "kinds" -> value.strings().contains(event.kind.toString())
        key.startsWith("#") ->
          event.tags.any { it.size >= 2 && it[0] == key.drop(1) && it[1] in value.strings() }
        key == "until" -> beforeUntil(event.createdAt, value.jsonPrimitive.long)
        key == "limit" -> true
        else -> error("the stored-event relay does not read a filter's $key")
      }
    }

  private fun beforeUntil(createdAt: Long, until: Long): Boolean =
    when (untilOrder) {
      UntilOrder.AT_OR_BEFORE -> createdAt <= until
      UntilOrder.BEFORE -> createdAt < until
    }

  private fun JsonElement.strings(): List<String> = jsonArray.map { it.jsonPrimitive.content }

  private fun eventFrame(id: String, event: NostrEvent) = "[\"EVENT\",\"$id\",${event.serialize()}]"

  private companion object {
    // High enough that a cell reaches a clamp only by naming one.
    const val DEFAULT_CLAMP = 1000

    // Long enough to outlast any cell: the wait ends when the client closes.
    const val IDLE_MILLIS = 30_000
  }
}
