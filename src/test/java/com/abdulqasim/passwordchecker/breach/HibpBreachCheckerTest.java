package com.abdulqasim.passwordchecker.breach;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

//  HibpBreachCheckerTest
//  What: Checks what the breach checker sends over the network and its reaction to different entries,
//  and replies, even failures.

//  Where the test data comes from: These tests never contact the real service;
//  each starts a stand-in server on the computer that monitors request activity,
//  then receives the request and responds, making it possible to prove that only the 5-character prefix is transmitted.

//  Note: These tests were written with online assistance and reviewed by me.

class HibpBreachCheckerTest {

    // The SHA-1 fingerprint of "password", split into the part that is sent and the part that must stay private.
    private static final String PASSWORD_PREFIX = "5BAA6";
    private static final String PASSWORD_SUFFIX = "1E4C9B93F3F0682250B6CF8331B7EE68FD8";

    private HttpServer server;

    private final AtomicReference<String> requestedPath = new AtomicReference<>();
    private final AtomicReference<String> paddingHeader = new AtomicReference<>();

    @AfterEach
    void stopServer() {
        if (server != null) {
            server.stop(0);
        }
    }

    @Test
    void sendsOnlyTheFiveCharacterPrefix() {
        HibpBreachChecker checker = checkerWithReply(200, PASSWORD_SUFFIX + ":42\n");

        checker.breachCount("password".toCharArray());

        assertEquals("/range/" + PASSWORD_PREFIX, requestedPath.get());
        assertFalse(requestedPath.get().contains(PASSWORD_SUFFIX));
    }

    @Test
    void requestsPaddedResponses() {
        HibpBreachChecker checker = checkerWithReply(200, PASSWORD_SUFFIX + ":42\n");

        checker.breachCount("password".toCharArray());

        assertEquals("true", paddingHeader.get());
    }

    @Test
    void returnsBreachCountFromReply() {
        HibpBreachChecker checker = checkerWithReply(200,
                "003D68EB55068C33ACE09247EE4C639306B:3\r\n" + PASSWORD_SUFFIX + ":42\r\n");

        assertEquals(42, checker.breachCount("password".toCharArray()));
    }

    @Test
    void returnsZeroWhenPasswordIsNotInReply() {
        HibpBreachChecker checker = checkerWithReply(200, "003D68EB55068C33ACE09247EE4C639306B:3\n");

        assertEquals(0, checker.breachCount("password".toCharArray()));
    }

    @Test
    void reportsErrorWhenServiceReturnsErrorStatus() {
        HibpBreachChecker checker = checkerWithReply(503, "Service Unavailable");

        assertThrows(BreachCheckException.class,
                () -> checker.breachCount("password".toCharArray()));
    }

    @Test
    void reportsErrorWhenReplyIsNotInExpectedFormat() {
        HibpBreachChecker checker = checkerWithReply(200, "<html>Please log in to the Wi-Fi</html>");

        assertThrows(BreachCheckException.class,
                () -> checker.breachCount("password".toCharArray()));
    }

    @Test
    void reportsErrorWhenServiceCannotBeReached() {
        HibpBreachChecker checker = checkerWithReply(200, "");
        server.stop(0);
        server = null;

        assertThrows(BreachCheckException.class,
                () -> checker.breachCount("password".toCharArray()));
    }

    // Starts the stand-in server and returns a checker that talks to it instead of the real service.
    private HibpBreachChecker checkerWithReply(int status, String body) {
        try {
            server = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        } catch (IOException e) {
            throw new IllegalStateException("Could not start test server", e);
        }

        server.createContext("/", exchange -> {
            requestedPath.set(exchange.getRequestURI().getPath());
            paddingHeader.set(exchange.getRequestHeaders().getFirst("Add-Padding"));

            byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(status, bytes.length == 0 ? -1 : bytes.length);
            try (OutputStream out = exchange.getResponseBody()) {
                out.write(bytes);
            }
        });
        server.start();

        URI baseUri = URI.create("http://localhost:" + server.getAddress().getPort());
        return new HibpBreachChecker(HttpClient.newHttpClient(), baseUri);
    }
}