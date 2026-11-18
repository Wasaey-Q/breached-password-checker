package com.abdulqasim.passwordchecker.breach;

import java.util.List;
import java.util.Objects;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

//  RangeResponseParser
//  What: Reads the list returned by the 'Have I Been Pwned' source and checks whether,
//  and how many times, a particular password appeared in data breaches.
//
//  Why: It protects the user's privacy by sending only the first 5 characters of the password's fingerprint.
//  Typically, it replies with every fingerprint that matches those first 5 characters,
//  along with how many times it has been breached.
//  This class searches that list for the remaining 35 characters,
//  keeping the real password local and keeping the service in the dark about it.

public final class RangeResponseParser {

    private static final Pattern SUFFIX = Pattern.compile("[0-9A-F]{35}", Pattern.CASE_INSENSITIVE);

    private static final Pattern ENTRY = Pattern.compile("([0-9A-F]{35}):(\\d+)", Pattern.CASE_INSENSITIVE);

    public long findBreachCount(String responseBody, String hashSuffix) {
        Objects.requireNonNull(responseBody, "responseBody must not be null");
        Objects.requireNonNull(hashSuffix, "hashSuffix must not be null");

        if (!SUFFIX.matcher(hashSuffix).matches()) {
            throw new IllegalArgumentException("hashSuffix must be exactly 35 hexadecimal characters");
        }

        List<String> lines = responseBody.lines()
                .map(String::strip)
                .filter(line -> !line.isEmpty())
                .toList();

        //  If a reply is empty, something went wrong during the process.
        if (lines.isEmpty()) {
            throw new IllegalArgumentException("Response contained no entries");
        }

        long count = 0;
        for (int i = 0; i < lines.size(); i++) {
            Matcher entry = ENTRY.matcher(lines.get(i));

            //  Every single line is checked, including the one we want. If there are rejections, we state that exactly.
            if (!entry.matches()) {
                throw new IllegalArgumentException("Malformed entry on line " + (i + 1) + " of response");
            }

            if (entry.group(1).equalsIgnoreCase(hashSuffix)) {
                count = parseCount(entry.group(2), i + 1);
            }
        }

        //  Padded entries are treated as non-breached.
        return count;
    }

    private static long parseCount(String digits, int lineNumber) {
        try {
            return Long.parseLong(digits);
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("Count too large on line " + lineNumber + " of response", e);
        }
    }
}