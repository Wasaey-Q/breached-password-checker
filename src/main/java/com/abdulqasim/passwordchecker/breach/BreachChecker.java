package com.abdulqasim.passwordchecker.breach;

// BreachChecker
// What: Describes what any breach checker should do by taking a password
// and listing how many times it has appeared in any known data breaches.

// Why: The program depends on the Have I Been Pwned site specifically,
// meaning the real online checker can be swapped around for any different source 
// without having to alter any further code.

public interface BreachChecker {
    // Shows how many times a password appears from the source.
    // In case of 0, it means the password wasn't found.
    long breachCount(char[] password);
}
