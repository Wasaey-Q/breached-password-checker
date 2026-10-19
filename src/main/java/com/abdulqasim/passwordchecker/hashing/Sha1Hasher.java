package com.abdulqasim.passwordchecker.hashing;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.Objects;

//  Sha1Hasher
//  What: Utilises the SHA1 hashing algorithm,
//  which takes an input and produces a fixed-length 40-character hash;
//  the same password always produces the same hash, 
//  and you cannot work backwards from the hash to the original input (i.e., a password).
//
//  Why:'Have I Been Pwned' stores passwords that may have been breached as SHA-1 hashes,
//  which we'll call fingerprints.
//  To compare passwords,
//  we hash the password and send only the first 5 characters of the resulting fingerprint over the internet.
//
//  Note: SHA1 is no longer deemed safe for storing passwords,
//  as modern computing power can guess common passwords from their hashed fingerprint easily, in a few tries.
//  The use here is simply due to the 'Have I Been Pwned' service requiring it.
//
public final class Sha1Hasher {

    //  hash(char[] password) 
    //  Returns the SHA1 fingerprint as 40 uppercase letters & digits.

    public String hash(char[] password) {
        Objects.requireNonNull(password, "password must not be null");

        //  The password is converted to bytes with UTF-8 specifically so certain unique characters,
        //  e.g., 'é ', are handled universally through computers.
        ByteBuffer encoded = StandardCharsets.UTF_8.encode(CharBuffer.wrap(password));
        byte[] bytes = new byte[encoded.remaining()];
        encoded.get(bytes);

        try {
            MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
            return HexFormat.of().withUpperCase().formatHex(sha1.digest(bytes));
        } catch (NoSuchAlgorithmException e) {
            //  If the Java installation is incorrect.
            throw new IllegalStateException("SHA-1 is not available in this Java runtime", e);
        } finally {
            //  The copies of the bytes are overwritten with 0s for security,
            //  ensuring that they aren't lingering in the computer's memory after completion. 
            Arrays.fill(bytes, (byte) 0);
            if (encoded.hasArray()) {
                Arrays.fill(encoded.array(), (byte) 0);
            }
        }
    }
}