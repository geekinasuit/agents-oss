package com.geekinasuit.agency.shared.harness

import java.io.File
import java.net.ConnectException
import java.net.URI
import java.net.UnknownHostException
import java.net.http.HttpClient
import java.net.http.HttpConnectTimeoutException
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.net.http.HttpTimeoutException
import java.time.Duration
import org.json.JSONObject

/** How a profile authenticates to its endpoint. A safety knob with no safe default, so it
 * is a required field rather than one that quietly picks a side (see [OpenAiCompatProfile]). */
enum class OpenAiAuthMode {
  /** No credential is sent. The only mode currently served. */
  NONE,

  /** `Authorization: Bearer <key>`. Declared so a keyed profile is a data addition rather
   * than a reshaping of this type; the code path that would read a key does not exist here. */
  BEARER,
}

/**
 * Which endpoint to speak to, as which model, with which credential posture.
 *
 * A value object rather than constructor arguments on the harness so that adding a
 * provider is adding data. [authMode] has deliberately no default: both possible defaults
 * are wrong in a way that fails silently — defaulting to [OpenAiAuthMode.NONE] would let a
 * keyed endpoint be configured unauthenticated, and defaulting to
 * [OpenAiAuthMode.BEARER] would invite a key into a profile that should not carry one.
 */
data class OpenAiCompatProfile(
  val name: String,
  val baseUrl: String,
  val model: String,
  val authMode: OpenAiAuthMode,
) {
  init {
    require(name.isNotBlank()) { "profile name must not be blank" }
    require(model.isNotBlank()) { "profile model must not be blank" }
    require(baseUrl.startsWith("http://") || baseUrl.startsWith("https://")) {
      "profile baseUrl must be an http(s) URL, was '$baseUrl'"
    }
    require(!baseUrl.endsWith("/")) { "profile baseUrl must not end in '/', was '$baseUrl'" }
    // Fail closed on the keyed posture, matching how a fenced pod transport refuses at
    // construction: a key needs provisioning, a lifecycle, an activation guard and negative
    // tests that no journal or environment ever carries it, none of which exist here. A
    // profile that cannot be built cannot be reached by a misconfiguration.
    require(authMode == OpenAiAuthMode.NONE) {
      "authMode=$authMode is not served yet: only key-free endpoints are " +
        "reachable until the keyed-cognition work lands the key " +
        "lifecycle and its activation guard"
    }
  }

  /**
   * Whether the endpoint is a loopback address, decided on the literal host so the answer
   * is a property of the configuration and cannot move at runtime.
   *
   * This is the honest form of "zero egress": it says a packet addressed here
   * does not leave the machine. It cannot see a second HTTP client, a telemetry lane, or a
   * DNS lookup — the classes an egress *claim* would have to cover.
   */
  val isLoopback: Boolean
    get() {
      val host = URI(baseUrl).host ?: return false
      return host == "localhost" || host == "127.0.0.1" || host == "::1" || host == "[::1]"
    }

  companion object {
    const val OLLAMA_BASE_URL = "http://localhost:11434"

    /**
     * Local Ollama: loopback, no credential, no billing relationship.
     *
     * Loopback is ENFORCED here, not merely the default. `baseUrl` is overridable so tests
     * can point at an ephemeral port, and an override is exactly how a profile documented
     * as key-free-and-local would quietly acquire a remote endpoint — sending an
     * unauthenticated prompt, mail contents included, off the machine. A constructor that
     * refuses is the only version of that guarantee a caller cannot skip.
     */
    fun ollama(model: String, baseUrl: String = OLLAMA_BASE_URL): OpenAiCompatProfile {
      val profile =
        OpenAiCompatProfile(
          name = "ollama",
          baseUrl = baseUrl,
          model = model,
          authMode = OpenAiAuthMode.NONE,
        )
      require(profile.isLoopback) {
        "the ollama profile is loopback-only, was '$baseUrl': a key-free profile carries no " +
          "credential, so a remote endpoint would be an unauthenticated prompt leaving the host"
      }
      return profile
    }
  }
}

/** One completed (or failed) chat exchange. [ok] is the signal to branch on. */
data class ChatTurn(
  val text: String,
  val promptTokens: Int?,
  val completionTokens: Int?,
  /** HTTP status of a completed exchange, or one of the harness's non-HTTP codes. */
  val status: Int,
  val ok: Boolean,
  /** Set exactly when [ok] is false: what went wrong, in the substrate's words. */
  val error: String? = null,
)

/**
 * One [HarnessStrategy] over the OpenAI-compatible `/v1/chat/completions` shape,
 * so provider plurality is a matter of which [OpenAiCompatProfile] is passed rather
 * than which class is instantiated.
 *
 * Follows [ClaudeHarness]'s shape: [execute] is the neutral seam every strategy offers,
 * and [chat] is the transport-native call with the fields this wire actually carries
 * (token usage, HTTP status). Cognition uses [chat]; [execute] exists so this harness is
 * substitutable wherever the neutral interface is what's held.
 *
 * Requests are non-streaming and pinned to `temperature: 0`, which is what makes a
 * within-wake retry a repeat rather than a resample — the property the cognition
 * layer's single-attempt retry cap rests on. Built on the JDK HTTP client: no
 * new dependency, and the whole request path is visible in this file.
 */
class OpenAiCompatHarness(
  val profile: OpenAiCompatProfile,
  private val client: HttpClient =
    HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(CONNECT_TIMEOUT_SEC)).build(),
) : HarnessStrategy {
  override val name = "openai-compat:${profile.name}"

  /**
   * One non-streaming chat completion.
   *
   * Never throws for a remote-side failure: a timeout, a refused connection, an error
   * status and a well-formed-but-unusable body all come back as `ok = false` with a
   * classified [ChatTurn.error]. The caller is a wake loop that must journal a fact and
   * carry on, not one that can meaningfully catch an exception.
   */
  fun chat(
    systemPrompt: String,
    userPrompt: String,
    maxTokens: Int = DEFAULT_MAX_TOKENS,
    timeoutSec: Int = DEFAULT_TIMEOUT_SEC,
  ): ChatTurn {
    val body =
      JSONObject()
        .put("model", profile.model)
        .put("stream", false)
        .put("temperature", 0)
        .put("max_tokens", maxTokens)
        .put(
          "messages",
          listOf(
            JSONObject().put("role", "system").put("content", systemPrompt),
            JSONObject().put("role", "user").put("content", userPrompt),
          ),
        )
    val request =
      HttpRequest.newBuilder()
        .uri(URI("${profile.baseUrl}$CHAT_COMPLETIONS_PATH"))
        .header("Content-Type", "application/json")
        .timeout(Duration.ofSeconds(timeoutSec.toLong()))
        .POST(HttpRequest.BodyPublishers.ofString(body.toString()))
        .build()

    val response =
      try {
        client.send(request, HttpResponse.BodyHandlers.ofString())
      } catch (e: HttpConnectTimeoutException) {
        // BEFORE the HttpTimeoutException arm — it is a subclass, and the two mean opposite
        // things to a caller deciding whether the endpoint exists: a filtered port times out
        // connecting, which is "nothing is there", not "the model took too long".
        return failed(CONNECT_FAILURE_CODE, "could not connect to ${profile.baseUrl}: timed out")
      } catch (e: HttpTimeoutException) {
        return failed(TIMEOUT_CODE, "request timed out after ${timeoutSec}s")
      } catch (e: ConnectException) {
        return failed(CONNECT_FAILURE_CODE, "could not connect to ${profile.baseUrl}: refused")
      } catch (e: UnknownHostException) {
        return failed(CONNECT_FAILURE_CODE, "could not connect to ${profile.baseUrl}: unknown host")
      } catch (e: Exception) {
        // Everything else is a fault DURING an exchange with something that was reachable —
        // a reset, a truncated stream. Message only: an exception's text can name the
        // endpoint, never a response body.
        return failed(TRANSPORT_FAILURE_CODE, "request failed: ${e.javaClass.simpleName}: ${e.message}")
      }

    if (response.statusCode() !in 200..299) {
      return failed(response.statusCode(), "endpoint returned HTTP ${response.statusCode()}")
    }
    return try {
      val obj = JSONObject(response.body())
      val choices = obj.optJSONArray("choices")
      if (choices == null || choices.length() == 0) {
        return failed(response.statusCode(), "response carried no choices")
      }
      // A reply cut off at the token cap is a CONFIGURATION fault, not an unreliable model.
      // Left unread, truncated JSON reaches the parser, fails, and is journaled as model
      // degradation — so a max_tokens set too low for the model would read as the model
      // getting worse. Checked before the content is handed on for exactly that reason.
      if (choices.getJSONObject(0).opt("finish_reason") == "length") {
        return failed(
          response.statusCode(),
          "reply was truncated at the $maxTokens-token cap (finish_reason=length)",
        )
      }
      val message =
        choices.getJSONObject(0).optJSONObject("message")
          ?: return failed(response.statusCode(), "response choice carried no message")
      // `opt` rather than `optString`, which reports an absent key and an empty string
      // identically — a reply with no content field is a broken envelope, not an empty answer.
      val content =
        message.opt("content") as? String
          ?: return failed(response.statusCode(), "response message carried no content string")
      val usage = obj.optJSONObject("usage")
      ChatTurn(
        text = content,
        promptTokens = usage?.optIntOrNull("prompt_tokens"),
        completionTokens = usage?.optIntOrNull("completion_tokens"),
        status = response.statusCode(),
        ok = true,
      )
    } catch (e: Exception) {
      // The envelope was not JSON. Distinct from a model whose *content* is unparseable —
      // that judgment belongs to the cognition layer, which never sees this case.
      failed(response.statusCode(), "response envelope was not JSON: ${e.message}")
    }
  }

  /**
   * The neutral seam. Two of [RunResult]'s fields are subprocess-shaped and are mapped
   * rather than faked, since a reader who trusts them would otherwise be misled:
   *
   * - [workDir] is IGNORED. There is no process to give a working directory to; the
   *   endpoint has no view of this filesystem at all.
   * - [RunResult.exitCode] carries the HTTP status of a completed exchange (200 on
   *   success). Outcomes with no status reuse the subprocess vocabulary instead of
   *   inventing a second one: [TIMEOUT_CODE] is the 124 that [RunResult] already documents
   *   for a timed-out run, while [CONNECT_FAILURE_CODE] and [TRANSPORT_FAILURE_CODE] mark a
   *   request that got no response — respectively because nothing was listening, or because
   *   something was and the exchange broke. [RunResult.ok] stays the field to branch on.
   * - [RunResult.toolCalls] is null: this wire has no tool-use turn to count.
   */
  override fun execute(promptText: String, workDir: File, appendSystemPrompt: String?): RunResult {
    val turn = chat(systemPrompt = appendSystemPrompt ?: "", userPrompt = promptText)
    return RunResult(
      text = if (turn.ok) turn.text else (turn.error ?: "unknown failure"),
      toolCalls = null,
      exitCode = turn.status,
      ok = turn.ok,
    )
  }

  private fun failed(status: Int, error: String) =
    ChatTurn(text = "", promptTokens = null, completionTokens = null, status = status, ok = false, error = error)

  companion object {
    const val CHAT_COMPLETIONS_PATH = "/v1/chat/completions"
    const val DEFAULT_MAX_TOKENS = 500
    const val DEFAULT_TIMEOUT_SEC = 120
    const val CONNECT_TIMEOUT_SEC = 10L

    /** A run that exceeded its deadline — the value [RunResult] already documents. */
    const val TIMEOUT_CODE = 124

    /**
     * No connection could be established: refused, connect-timed-out, or an unresolvable
     * host. Distinct from [TRANSPORT_FAILURE_CODE] because it is the one outcome that means
     * "nothing is serving this endpoint" — a caller deciding whether the provider is present
     * at all (see the Ollama exit gate) must not confuse it with a fault mid-exchange, which
     * proves something WAS there and misbehaved.
     */
    const val CONNECT_FAILURE_CODE = -2

    /** A fault during an exchange with a reachable endpoint (reset, truncated stream). */
    const val TRANSPORT_FAILURE_CODE = -1

    /** `optInt` cannot say "absent": it returns 0, which is a legitimate token count.
     * Absent usage and zero usage are different facts about the exchange. */
    private fun JSONObject.optIntOrNull(key: String): Int? = if (has(key)) optInt(key) else null
  }
}
