package com.geekinasuit.agency.shared.journal

import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Test

class FoldFaultTest {

  @Test
  fun aPayloadContractRefusalIsShownAfterTheEntrysSeqAndKind() {
    assertEquals(
      "journal fold failed at seq=14 kind='status-written': payload field 'status' is missing",
      foldFaultMessage(
        "journal fold",
        14,
        "status-written",
        PayloadContractException("payload field 'status' is missing"),
      ),
    )
  }

  @Test
  fun anyOtherExceptionIsShownByItsClassNameAlone() {
    // A number conversion's message quotes the text it could not convert.
    assertEquals(
      "journal fold failed at seq=3 kind='effect-done': java.lang.NumberFormatException",
      foldFaultMessage(
        "journal fold",
        3,
        "effect-done",
        NumberFormatException("For input string: \"Qx7\""),
      ),
    )
  }

  @Test
  fun aJournalFoldExceptionShowsAnyOtherCauseByItsClassNameAlone() {
    assertEquals(
      "journal fold failed at seq=1 kind='k': java.lang.NumberFormatException",
      JournalFoldException(1, "k", NumberFormatException("For input string: \"Qx7\"")).message,
    )
  }

  @Test
  fun aKindOutsideTheShownCharsetIsShownByItsLengthAlone() {
    val kinds =
      listOf("Qx7 kind", "Qx7'kind", "Qx7" + Char(0x1B) + "[2J", "Qx7" + Char(0x202E) + "x", "")
    for (kind in kinds) {
      assertEquals(
        "f failed at seq=5 kind=(${kind.length} chars, not shown): r",
        foldFaultMessage("f", 5, kind, PayloadContractException("r")),
      )
    }
  }

  @Test
  fun aKindIsShownUpToSixtyFourCharsAndNotBeyond() {
    val atTheBound = "k".repeat(64)
    assertEquals(
      "f failed at seq=1 kind='$atTheBound': r",
      foldFaultMessage("f", 1, atTheBound, PayloadContractException("r")),
    )
    assertEquals(
      "f failed at seq=1 kind=(65 chars, not shown): r",
      foldFaultMessage("f", 1, "k".repeat(65), PayloadContractException("r")),
    )
  }

  @Test
  fun aPayloadThatDoesNotParseIsRefusedWithoutQuotingIt() {
    val refused =
      assertThrows(PayloadContractException::class.java) {
        payloadObject("{\"status\":Qx7 marker}")
      }
    assertEquals("payload is not valid JSON", refused.message)
    assertNull("the parser's exception, which quotes its input, is not attached", refused.cause)
  }

  @Test
  fun aPayloadThatIsNotAnObjectIsRefused() {
    for (payload in listOf("[1]", "\"Qx7\"", "7", "null")) {
      val refused =
        assertThrows(payload, PayloadContractException::class.java) { payloadObject(payload) }
      assertEquals(payload, "payload is not a JSON object", refused.message)
    }
  }

  @Test
  fun aPayloadThatIsAnObjectParses() {
    assertEquals(buildJsonObject { put("n", 1) }, payloadObject("{\"n\":1}"))
  }
}
