package com.abdulqasim.passwordchecker.breach;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;

//  RangeResponseParserTest
//  What: Checks that breach counts are read correctly from the service's reply,
//  and that unexpected replies are rejected rather than treated as safe.
//
//  Where the test data comes from: The sample replies below follow the format documented by
//  Have I Been Pwned: one "SUFFIX:COUNT" entry per line. 
//  The suffix being searched for is the real ending of the fingerprint of "password".
//  The counts are made up for testing, so these tests never need an internet connection.
//
//  Note: These tests were written with online assistance and reviewed by me.

class RangeResponseParserTest {

    // > The last 35 characters of the SHA-1 fingerprint of "password".
    private static final String PASSWORD_SUFFIX = "1E4C9B93F3F0682250B6CF8331B7EE68FD8";

    private static final String SAMPLE_RESPONSE = """
            003D68EB55068C33ACE09247EE4C639306B:3
            1E4C9B93F3F0682250B6CF8331B7EE68FD8:12345
            1E4C9B93F3F0682250B6CF8331B7EE68FD9:7
            """;

    private final RangeResponseParser parser = new RangeResponseParser();

    @Test
    void returnsCountWhenSuffixIsPresent() {
        assertEquals(12345, parser.findBreachCount(SAMPLE_RESPONSE, PASSWORD_SUFFIX));
    }

    @Test
    void returnsZeroWhenSuffixIsAbsent() {
        String response = "003D68EB55068C33ACE09247EE4C639306B:3\n";
        assertEquals(0, parser.findBreachCount(response, PASSWORD_SUFFIX));
    }

    @Test
    void doesNotMatchSuffixThatDiffersByOneCharacter() {
        String response = "1E4C9B93F3F0682250B6CF8331B7EE68FD9:7\n";
        assertEquals(0, parser.findBreachCount(response, PASSWORD_SUFFIX));
    }

    @Test
    void matchesRegardlessOfLetterCase() {
        assertEquals(12345, parser.findBreachCount(SAMPLE_RESPONSE, PASSWORD_SUFFIX.toLowerCase()));
    }

    @Test
    void handlesWindowsStyleLineEndings() {
        String response = "003D68EB55068C33ACE09247EE4C639306B:3\r\n"
                + "1E4C9B93F3F0682250B6CF8331B7EE68FD8:12345\r\n";
        assertEquals(12345, parser.findBreachCount(response, PASSWORD_SUFFIX));
    }

    @Test
    void treatsPaddingEntryAsNotBreached() {
        String response = "1E4C9B93F3F0682250B6CF8331B7EE68FD8:0\n";
        assertEquals(0, parser.findBreachCount(response, PASSWORD_SUFFIX));
    }

    @Test
    void rejectsResponseThatIsNotInTheExpectedFormat() {
        String response = "<html><body>Please log in to the Wi-Fi</body></html>";
        assertThrows(IllegalArgumentException.class,
                () -> parser.findBreachCount(response, PASSWORD_SUFFIX));
    }

    @Test
    void rejectsResponseWithOneMalformedLine() {
        String response = "003D68EB55068C33ACE09247EE4C639306B:3\n"
                + "this line is broken\n"
                + "1E4C9B93F3F0682250B6CF8331B7EE68FD8:12345\n";
        assertThrows(IllegalArgumentException.class,
                () -> parser.findBreachCount(response, PASSWORD_SUFFIX));
    }

    @Test
    void rejectsEmptyResponse() {
        assertThrows(IllegalArgumentException.class,
                () -> parser.findBreachCount("", PASSWORD_SUFFIX));
    }

    @Test
    void rejectsSuffixOfWrongLength() {
        assertThrows(IllegalArgumentException.class,
                () -> parser.findBreachCount(SAMPLE_RESPONSE, "1E4C9"));
    }
}