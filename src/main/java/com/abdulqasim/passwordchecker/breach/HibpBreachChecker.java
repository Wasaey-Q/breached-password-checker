package com.abdulqasim.passwordchecker.breach;

import com.abdulqasim.passwordchecker.hashing.Sha1Hasher;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Objects;

//  HibpBreachChecker
//  What: Checks the password against the Have I Been Pwned database over the internet.

//  Why: Applies the k-anonymity privacy technique, where the password's fingerprint is split,
//  and the first 5 characters are sent to the service.
//  The remaining up to 35 characters never leave the computer,
//  allowing the service to respond with every possible match that starts with the 5 initial characters;
//  the following code then makes that comparison.

//  Note: The request pads its reply with fake entries so the original reply size gives nothing away to anyone monitoring the network.

public final class HibpBreachChecker implements BreachChecker {

    private static final URI DEFAULT_BASE_URI = URI.create("https://api.pwnedpasswords.com");
    private static final Duration TIMEOUT = Duration.ofSeconds(10);
    private static final int PREFIX_LENGTH = 5;

    private final HttpClient httpClient;
    private final URI baseUri;
    private final Sha1Hasher hasher;
    private final RangeResponseParser parser;

    public HibpBreachChecker() {
        this(HttpClient.newBuilder().connectTimeout(TIMEOUT).build(), DEFAULT_BASE_URI);
    }

    // Lets the tests point the checker at a local stand-in
    // server instead of the real service.
    HibpBreachChecker(HttpClient httpClient, URI baseUri) {
        this.httpClient = Objects.requireNonNull(httpClient, "httpClient must not be null");
        this.baseUri = Objects.requireNonNull(baseUri, "baseUri must not be null");
        this.hasher = new Sha1Hasher();
        this.parser = new RangeResponseParser();
    }

    @Override
    public long breachCount(char[] password) {
        String hash = hasher.hash(password);
        String prefix = hash.substring(0, PREFIX_LENGTH);
        String suffix = hash.substring(PREFIX_LENGTH);

        // Only the 5-character prefix is placed in the request.
        HttpRequest request = HttpRequest.newBuilder(baseUri.resolve("/range/" + prefix))
                .timeout(TIMEOUT)
                .header("Add-Padding", "true")
                .header("User-Agent", "breached-password-checker")
                .GET()
                .build();

        HttpResponse<String> response = send(request);

        if (response.statusCode() != 200) {
            throw new BreachCheckException(
                    "Breach service returned unexpected status " + response.statusCode());
        }

        try {
            return parser.findBreachCount(response.body(), suffix);
        } catch (IllegalArgumentException e) {
            throw new BreachCheckException("Breach service returned an unexpected response", e);
        }
    }

    private HttpResponse<String> send(HttpRequest request) {
        try {
            return httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        } catch (IOException e) {
            throw new BreachCheckException("Could not reach the breach service", e);
        } catch (InterruptedException e) {
            // Restores the "interrupted" signal so the rest of the program can still see that it was cancelled.
            Thread.currentThread().interrupt();
            throw new BreachCheckException("Breach check was interrupted", e);
        }
    }
}