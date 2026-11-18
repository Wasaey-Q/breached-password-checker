package com.abdulqasim.passwordchecker.strength;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

//  StrengthAnalyserTest
//  What: Ensures passwords receive ratings that are sensible and contextual, and that, depending on the selective weakness,
//  the program suggests an accurate suggestion to strengthen security.
 
// Where the test data comes from: The passwords are each selected to trigger at least one rule,
// and none of them should ever be used as a real password.

//  Note: These tests were written with online assistance and reviewed by me.
// ==============================================================
class StrengthAnalyserTest {

    private final StrengthAnalyser analyser = new StrengthAnalyser();

    private StrengthResult analyse(String password) {
        return analyser.analyse(password.toCharArray());
    }

    @Test
    void ratesMixedTwelveCharacterPasswordAsStrong() {
        StrengthResult result = analyse("Xk9#mQ2!vL7p");
        assertEquals(Strength.STRONG, result.strength());
        assertTrue(result.feedback().isEmpty());
    }

    @Test
    void ratesLongLowercasePassphraseAsStrong() {
        StrengthResult result = analyse("correcthorsebatterystaple");
        assertEquals(Strength.STRONG, result.strength());
        assertTrue(result.feedback().isEmpty());
    }

    @Test
    void ratesShortPasswordAsVeryWeakEvenWithVariety() {
        StrengthResult result = analyse("Ab1!xyz");
        assertEquals(Strength.VERY_WEAK, result.strength());
        assertTrue(result.feedback().contains(StrengthAnalyser.TOO_SHORT));
    }

    @Test
    void ratesCommonPasswordAsVeryWeak() {
        StrengthResult result = analyse("password");
        assertEquals(Strength.VERY_WEAK, result.strength());
        assertTrue(result.feedback().contains(StrengthAnalyser.COMMON_WORD));
    }

    @Test
    void recognisesCommonWordWithSymbolSwaps() {
        StrengthResult result = analyse("P@ssw0rd123!");
        assertNotEquals(Strength.STRONG, result.strength());
        assertTrue(result.feedback().contains(StrengthAnalyser.COMMON_WORD));
    }

    @Test
    void recognisesCommonWordContainingDigits() {
        StrengthResult result = analyse("Abc123Abc123");
        assertTrue(result.feedback().contains(StrengthAnalyser.COMMON_WORD));
    }

    @Test
    void penalisesSequences() {
        StrengthResult result = analyse("Xk9abcdQ!m2z");
        assertEquals(Strength.FAIR, result.strength());
        assertTrue(result.feedback().contains(StrengthAnalyser.SEQUENCE));
    }

    @Test
    void penalisesDescendingSequences() {
        StrengthResult result = analyse("Xk9#mQ4321vL");
        assertTrue(result.feedback().contains(StrengthAnalyser.SEQUENCE));
    }

    @Test
    void penalisesRepeatedCharacters() {
        StrengthResult result = analyse("Zq7!aaaa#Lp2");
        assertEquals(Strength.FAIR, result.strength());
        assertTrue(result.feedback().contains(StrengthAnalyser.REPEATED));
    }

    @Test
    void ratesPasswordWithFewDifferentCharactersAsVeryWeak() {
        StrengthResult result = analyse("abababababababab");
        assertEquals(Strength.VERY_WEAK, result.strength());
        assertTrue(result.feedback().contains(StrengthAnalyser.FEW_DISTINCT));
    }

    @Test
    void suggestsVarietyForShortSimplePassword() {
        StrengthResult result = analyse("sunflowerz");
        assertTrue(result.feedback().contains(StrengthAnalyser.LOW_VARIETY));
    }

    @Test
    void doesNotChangeThePasswordItWasGiven() {
        char[] password = "Xk9#mQ2!vL7p".toCharArray();
        char[] original = password.clone();

        analyser.analyse(password);

        assertArrayEquals(original, password);
    }

    @Test
    void rejectsNullInput() {
        assertThrows(NullPointerException.class, () -> analyser.analyse(null));
    }
}