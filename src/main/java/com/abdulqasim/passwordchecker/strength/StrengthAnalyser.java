package com.abdulqasim.passwordchecker.strength;

import java.nio.CharBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;

//  StrengthAnalyser
//  What: Utilises ratings to assess whether a password would be easily guessable and explains potential solutions to strengthen the password.
//  The check happens entirely locally.

//  Why: Even if a password isn't exposed in any known breach, that doesn't mean it's safe to use, since it can be easy to guess.
//  This check covers this security gap by looking at various attributes of the password,
//  such as length, variety of characters, and the elimination of common patterns.

//  Note: These rules are deliberately simple and easy to explain.

public final class StrengthAnalyser {

    static final String TOO_SHORT = "Use at least 12 characters.";
    static final String LOW_VARIETY =
            "Mix upper and lower case letters, numbers and symbols, or use a longer passphrase.";
    static final String COMMON_WORD = "Avoid common passwords and words, even with letters swapped for symbols.";
    static final String SEQUENCE = "Avoid predictable sequences such as 1234 or abcd.";
    static final String REPEATED = "Avoid repeating the same character several times in a row.";
    static final String FEW_DISTINCT = "Use more different characters.";

    private static final int MIN_LENGTH = 8;
    private static final int GOOD_LENGTH = 12;
    private static final int PASSPHRASE_LENGTH = 16;
    private static final int MIN_DISTINCT = 4;
    private static final int SEQUENCE_LENGTH = 4;
    private static final int REPEAT_LENGTH = 3;

    private static final List<String> COMMON_WORDS = List.of(
            "password", "qwerty", "letmein", "welcome", "admin", "iloveyou",
            "monkey", "dragon", "football", "abc123", "asdf", "zxcv");

    // Scores the password and collects suggestions. Returns the rating and the list of suggestions. An empty list means no obvious weaknesses were found.
    public StrengthResult analyse(char[] password) {
        Objects.requireNonNull(password, "password must not be null");

        char[] lower = toLowerCase(password);
        char[] normalized = undoSymbolSwaps(lower);

        try {
            List<String> feedback = new ArrayList<>();
            int length = password.length;
            int score = lengthPoints(length);

            if (length < GOOD_LENGTH) {
                feedback.add(TOO_SHORT);
            }

            if (characterTypes(password) >= 3) {
                score++;
            } else if (length < PASSPHRASE_LENGTH) {
                feedback.add(LOW_VARIETY);
            }

            // Checked against both copies so that "abc123" and
            // "p@ssw0rd" are both caught.
            if (containsCommonWord(lower) || containsCommonWord(normalized)) {
                score--;
                feedback.add(COMMON_WORD);
            }

            if (hasSequence(lower)) {
                score--;
                feedback.add(SEQUENCE);
            }

            if (hasRepeatedRun(lower)) {
                score--;
                feedback.add(REPEATED);
            }

            boolean fewDistinct = distinctCharacters(password) < MIN_DISTINCT;
            if (fewDistinct) {
                feedback.add(FEW_DISTINCT);
            }

            // Some weaknesses are serious enough that nothing else can make up for them.
            if (length < MIN_LENGTH || fewDistinct) {
                score = 0;
            }

            int index = Math.max(0, Math.min(score, Strength.values().length - 1));
            return new StrengthResult(Strength.values()[index], feedback);
        } finally {
            // Both working copies are wiped, just like in the hasher.
            Arrays.fill(lower, '\0');
            Arrays.fill(normalized, '\0');
        }
    }

    private static int lengthPoints(int length) {
        if (length >= PASSPHRASE_LENGTH) {
            return 3;
        }
        if (length >= GOOD_LENGTH) {
            return 2;
        }
        if (length >= MIN_LENGTH) {
            return 1;
        }
        return 0;
    }

    private static int characterTypes(char[] password) {
        int types = 0;
        if (CharBuffer.wrap(password).chars().anyMatch(Character::isLowerCase)) {
            types++;
        }
        if (CharBuffer.wrap(password).chars().anyMatch(Character::isUpperCase)) {
            types++;
        }
        if (CharBuffer.wrap(password).chars().anyMatch(Character::isDigit)) {
            types++;
        }
        if (CharBuffer.wrap(password).chars().anyMatch(c -> !Character.isLetterOrDigit(c))) {
            types++;
        }
        return types;
    }

    private static long distinctCharacters(char[] password) {
        return CharBuffer.wrap(password).chars().distinct().count();
    }

    private static char[] toLowerCase(char[] password) {
        char[] lower = new char[password.length];
        for (int i = 0; i < password.length; i++) {
            lower[i] = Character.toLowerCase(password[i]);
        }
        return lower;
    }

    // Turns common look-alike swaps back into letters, so that
    // "p@ssw0rd" is recognised as "password".
    private static char[] undoSymbolSwaps(char[] lower) {
        char[] result = new char[lower.length];
        for (int i = 0; i < lower.length; i++) {
            result[i] = switch (lower[i]) {
                case '@', '4' -> 'a';
                case '3' -> 'e';
                case '1', '!' -> 'i';
                case '0' -> 'o';
                case '$', '5' -> 's';
                case '7' -> 't';
                default -> lower[i];
            };
        }
        return result;
    }

    private static boolean containsCommonWord(char[] text) {
        for (String word : COMMON_WORDS) {
            if (contains(text, word)) {
                return true;
            }
        }
        return false;
    }

    private static boolean contains(char[] text, String word) {
        for (int start = 0; start + word.length() <= text.length; start++) {
            boolean match = true;
            for (int i = 0; i < word.length() && match; i++) {
                match = text[start + i] == word.charAt(i);
            }
            if (match) {
                return true;
            }
        }
        return false;
    }

    // Looks for runs like "1234", "abcd", "4321" or "dcba".
    private static boolean hasSequence(char[] lower) {
        for (int start = 0; start + SEQUENCE_LENGTH <= lower.length; start++) {
            if (isRun(lower, start, 1) || isRun(lower, start, -1)) {
                return true;
            }
        }
        return false;
    }

    private static boolean isRun(char[] text, int start, int step) {
        for (int i = start; i < start + SEQUENCE_LENGTH; i++) {
            if (!Character.isLetterOrDigit(text[i])) {
                return false;
            }
            if (i > start && text[i] - text[i - 1] != step) {
                return false;
            }
        }
        return true;
    }

    // Looks for the same character three or more times in a row.
    private static boolean hasRepeatedRun(char[] lower) {
        int run = 1;
        for (int i = 1; i < lower.length; i++) {
            run = (lower[i] == lower[i - 1]) ? run + 1 : 1;
            if (run >= REPEAT_LENGTH) {
                return true;
            }
        }
        return false;
    }
}