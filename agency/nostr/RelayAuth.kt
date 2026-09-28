package com.geekinasuit.agency.nostr

import java.time.Duration

/** Whether a new relay connection authenticates before anything is sent on it. */
sealed interface RelayAuth {
  /** Use the connection without authenticating. A relay that requires NIP-42 refuses what is sent. */
  object None : RelayAuth

  /**
   * Answer the relay's NIP-42 challenge on each new connection, within [timeout]. A connection that
   * does not authenticate is closed with nothing sent on it.
   */
  data class Nip42(val timeout: Duration) : RelayAuth
}

/** A connection [openConnection] made ready, or why it could not. [Unavailable]'s detail quotes no
 * text the relay sent, though a relay close's status code and a rejected handshake's HTTP status
 * are the relay's numbers, and an authentication refusal's reason is kept to its standard NIP-01
 * or NIP-42 prefix. */
internal sealed interface OpenedConnection {
  class Ready(val connection: RelayConnection) : OpenedConnection

  class Unavailable(val detail: String) : OpenedConnection
}

/**
 * Take a new connection from [newConnection], connect it within [connectTimeout], and authenticate
 * it as [auth] says. A connection that fails either step is closed, which zeroes its key. An
 * exception from [newConnection] is reported by the exception's class alone, because the factory
 * handles key material and its message could carry some. An [InterruptedException] from it also
 * sets the thread's interrupt status again, so the caller still sees the interrupt.
 */
internal fun openConnection(
  newConnection: () -> RelayConnection,
  connectTimeout: Duration,
  auth: RelayAuth,
): OpenedConnection {
  val conn =
    try {
      newConnection()
    } catch (e: Exception) {
      if (e is InterruptedException) Thread.currentThread().interrupt()
      return OpenedConnection.Unavailable("could not create a connection: ${e.javaClass.simpleName}")
    }
  val connected = conn.connect(connectTimeout)
  if (connected is ConnectResult.Failed) {
    conn.close()
    return OpenedConnection.Unavailable("could not connect: ${connected.detail}")
  }
  if (auth is RelayAuth.Nip42) {
    val refusal =
      when (val result = conn.authenticate(auth.timeout)) {
        AuthResult.Authenticated -> null
        is AuthResult.Refused -> relayReasonDetail("relay refused authentication", result.message)
        is AuthResult.Failed -> "could not authenticate: ${result.detail}"
      }
    if (refusal != null) {
      conn.close()
      return OpenedConnection.Unavailable(refusal)
    }
  }
  return OpenedConnection.Ready(conn)
}
