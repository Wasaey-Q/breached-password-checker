package com.abdulqasim.passwordchecker.hashing;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

//  Sha1HasherTest
//  Where the expected values come from: Every expected hash in this file comes from an outside source,
//  not from running this program. The tests compare the code against known correct answers,
//  so they cannot pass just by repeating the program's own output.
//
//  'abc': official example from the SHA-1 standard (NIST FIPS 180-4)
//  '': widely published SHA-1 value for empty input
//  'password': reproducible with any SHA-1 tool
//  'café': reproducible with any SHA-1 tool; checks that accented characters are handled as UTF-8.
//       
//  Note: These tests were written with online assistance and reviewed by me.

class Sha1HasherTest {

    private final Sha1Hasher hasher = new Sha1Hasher();

    @Test
    void matchesOfficialSha1StandardExample() {
        assertEquals("A9993E364706816ABA3E25717850C26C9CD0D89D",
                hasher.hash("abc".toCharArray()));
    }

    @Test
    void hashesKnownPasswordToExpectedValue() {
        assertEquals("5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8",
                hasher.hash("password".toCharArray()));
    }

    @Test
    void hashesEmptyInputToKnownValue() {
        assertEquals("DA39A3EE5E6B4B0D3255BFEF95601890AFD80709",
                hasher.hash(new char[0]));
    }

    @Test
    void encodesNonAsciiCharactersAsUtf8() {
        assertEquals("F424452A9673918C6F09B0CDD35B20BE8E6AE7D7",
                hasher.hash("caf\u00e9".toCharArray()));
    }

    @Test
    void producesFortyUppercaseHexCharacters() {
        String hash = hasher.hash("anything".toCharArray());
        assertTrue(hash.matches("[0-9A-F]{40}"), "unexpected hash format: " + hash);
    }

    @Test
    void rejectsNullInput() {
        assertThrows(NullPointerException.class, () -> hasher.hash(null));
    }
}