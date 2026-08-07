package com.geekinasuit.agency.shared.harness

import com.sun.net.httpserver.HttpServer
import java.net.InetSocketAddress
import org.json.JSONArray
import org.json.JSONObject

/**
 * A stand-in `/v1/chat/completions` endpoint on an ephemeral loopback port, for tests that
 * need the real HTTP path without needing a real model.
 *
 * Everything the harness sends is captured ([lastRequestBody], [lastAuthHeader]) and
 * everything it receives is settable per call, so both directions of the wire are
 * assertable. Shared between the harness's own tests and the lead's cognition tests: one
 * fake, so the two layers cannot disagree about what an endpoint does.
 */
class FakeOpenAiEndpoint(
  @Volatile var body: String,
  @Volatile var status: Int = 200,
  @Volatile var delayMs: Long = 0,
) : AutoCloseable {

  @Volatile var lastRequestBody: String? = null

  @Volatile var lastAuthHeader: String? = null

  @Volatile var requestCount: Int = 0

  private val server: HttpServer = HttpServer.create(InetSocketAddress(LOOPBACK, EPHEMERAL), 0)

  init {
    server.createContext(OpenAiCompatHarness.CHAT_COMPLETIONS_PATH) { exchange ->
      lastRequestBody = exchange.requestBody.readBytes().decodeToString()
      lastAuthHeader = exchange.requestHeaders.getFirst("Authorization")
      requestCount++
      if (delayMs > 0) Thread.sleep(delayMs)
      val bytes = body.toByteArray()
      exchange.sendResponseHeaders(status, bytes.size.toLong())
      exchange.responseBody.use { it.write(bytes) }
    }
    server.start()
  }

  val baseUrl: String
    get() = "http://$LOOPBACK:${server.address.port}"

  override fun close() = server.stop(0)

  companion object {
    private const val LOOPBACK = "127.0.0.1"
    private const val EPHEMERAL = 0

    /**
     * A response body captured verbatim from a live `qwen3-coder:30b` over loopback, on the
     * probed wire (temperature 0, max_tokens 500, non-streaming) with the lead's own system
     * prompt and a rendered wake state for ticket TEST-7.
     *
     * Kept as captured bytes — escapes, `system_fingerprint` and all — because a fixture we
     * author agrees with whatever we already believe the wire looks like, and would go on
     * agreeing if that belief were wrong.
     */
    const val CAPTURED_OLLAMA_RESPONSE =
      """{"id":"chatcmpl-77","object":"chat.completion","created":1785988614,"model":"qwen3-coder:30b","system_fingerprint":"fp_ollama","choices":[{"index":0,"message":{"role":"assistant","content":"{\"proposals\": [\n   {\"type\": \"pod-spawn\", \"taskRef\": \"plan:TEST-7\"}\n ], \"reasoning\": \"No plan artifact exists for ticket TEST-7, so we need to spawn a planner pod to create the plan.\"}"},"finish_reason":"stop"}],"usage":{"prompt_tokens":331,"completion_tokens":57,"total_tokens":388}}"""

    /**
     * A well-formed envelope carrying [content] as the assistant's reply, for cells about
     * what the MODEL said rather than about how the endpoint behaved. [topLevelModel] is
     * settable because the envelope's own `model` field is endpoint-controlled, and whether
     * the substrate ever reads it is a property worth testing.
     */
    fun reply(
      content: String,
      promptTokens: Int = 10,
      completionTokens: Int = 20,
      topLevelModel: String = "fake-model",
      finishReason: String = "stop",
    ): String =
      JSONObject()
        .put("id", "chatcmpl-fake")
        .put("object", "chat.completion")
        .put("model", topLevelModel)
        .put(
          "choices",
          JSONArray()
            .put(
              JSONObject()
                .put("index", 0)
                .put("finish_reason", finishReason)
                .put("message", JSONObject().put("role", "assistant").put("content", content))
            ),
        )
        .put(
          "usage",
          JSONObject()
            .put("prompt_tokens", promptTokens)
            .put("completion_tokens", completionTokens)
            .put("total_tokens", promptTokens + completionTokens),
        )
        .toString()
  }
}
