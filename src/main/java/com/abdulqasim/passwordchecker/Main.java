package com.abdulqasim.passwordchecker;

import com.abdulqasim.passwordchecker.breach.BreachCheckException;
import com.abdulqasim.passwordchecker.breach.BreachChecker;
import com.abdulqasim.passwordchecker.breach.HibpBreachChecker;
import com.abdulqasim.passwordchecker.strength.StrengthAnalyser;
import com.abdulqasim.passwordchecker.strength.StrengthResult;
import java.io.Console;
import java.util.Arrays;

//  Main
//  What: The starting point of the program. It asks for a password, checks it,
//  and prints the result.

//  Why: This main class connects the other classes;
//  all the real work happens outside this file,
//  in their own classes with their own associated tests,
//  keeping main as concise as possible and much easier to update, version, and troubleshoot.

//  Note: The password is typed in without appearing on the screen; afterwards, 

// the password is wiped from the computer's memory as soon as the whole process is finished.

public final class Main {

    private static final int EXIT_CHECK_FAILED = 2;
    private static final int EXIT_USAGE_ERROR = 1;

    // Nobody needs to create a Main object, so this stops it.
    private Main() {
    }

    public static void main(String[] args) {
        Console console = System.console();
        if (console == null) {
            System.err.println("Please run this program in a terminal so the password can be typed in privately.");
            System.exit(EXIT_USAGE_ERROR);
        }

        char[] password = console.readPassword("Enter a password to check: ");
        if (password == null || password.length == 0) {
            System.err.println("No password entered.");
            System.exit(EXIT_USAGE_ERROR);
        }

        StrengthAnalyser analyser = new StrengthAnalyser();
        BreachChecker checker = new HibpBreachChecker();

        try {
            // The strength check runs first because it works offline,
            // so the user still gets it if the breach check fails.
            printStrength(analyser.analyse(password));

            long count = checker.breachCount(password);
            printResult(count);
        } catch (BreachCheckException e) {
            // A failed check is never reported as "safe".
            System.err.println("The breach check could not be completed: " + e.getMessage());
            System.err.println("This does NOT mean the password is safe. Please try again later.");
            System.exit(EXIT_CHECK_FAILED);
        } finally {
            Arrays.fill(password, '\0');
        }
    }

    private static void printStrength(StrengthResult result) {
        System.out.println();
        System.out.println("Strength: " + result.strength().label());

        if (result.feedback().isEmpty()) {
            System.out.println("  No obvious weaknesses found.");
        } else {
            for (String suggestion : result.feedback()) {
                System.out.println("  - " + suggestion);
            }
        }
        System.out.println();
    }

    private static void printResult(long count) {
        if (count > 0) {
            System.out.printf("WARNING: this password has appeared in data breaches %,d times.%n", count);
            System.out.println("It should not be used for any account.");
        } else {
            System.out.println("This password was not found in any known data breach.");
        }
    }
}