package com.example.socketchat.encryption;

import com.google.inject.Singleton;

import java.math.BigInteger;
import java.security.SecureRandom;

@Singleton
public final class DiffieHellmanEncryption {

    private static final BigInteger TWO = BigInteger.TWO;
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();
    public static final BigInteger DEFAULT_P = TWO.pow(255).subtract(BigInteger.valueOf(19));
    public static final BigInteger DEFAULT_G = TWO;

    public KeyPair generateKeyPair() {
        return calculate(DEFAULT_G, DEFAULT_P, randomExponent(DEFAULT_P));
    }

    public KeyPair calculate(BigInteger g, BigInteger p, BigInteger x) {
        validateParameters(g, p);
        validateExponent("x", x, p);
        BigInteger y = g.modPow(x, p);
        validatePublicValue("y", y, p);
        return new KeyPair(g, p, x, y);
    }

    public BigInteger randomExponent(BigInteger p) {
        if (p == null || p.compareTo(BigInteger.valueOf(5)) < 0) {
            throw new IllegalArgumentException("P must be at least 5");
        }
        BigInteger maximum = p.subtract(TWO);
        BigInteger value;
        do {
            value = new BigInteger(p.bitLength(), SECURE_RANDOM);
        } while (value.compareTo(TWO) < 0 || value.compareTo(maximum) > 0);
        return value;
    }

    public BigInteger sharedSecret(PublicKey receiver, BigInteger x, BigInteger p, BigInteger g) {
        validatePublicKey(receiver);
        if (!p.equals(receiver.p()) || !g.equals(receiver.g())) {
            throw new IllegalArgumentException("Diffie-Hellman G and P do not match the receiver");
        }
        validateExponent("x", x, p);
        return receiver.y().modPow(x, p);
    }

    public String toSecretKey(PublicKey receiver, BigInteger x, BigInteger p, BigInteger g) {
        String key = sharedSecret(receiver, x, p, g).toString(16);
        int length = key.length() <= 32 ? 32 : key.length() <= 48 ? 48 : 64;
        if (key.length() > length) {
            throw new IllegalArgumentException("Diffie-Hellman K is too large for AES");
        }
        return "0".repeat(length - key.length()) + key;
    }

    private static void validatePublicKey(PublicKey publicKey) {
        if (publicKey == null) {
            throw new IllegalArgumentException("Missing Diffie-Hellman public key");
        }
        validateParameters(publicKey.g(), publicKey.p());
        validatePublicValue("y", publicKey.y(), publicKey.p());
    }

    private static void validateParameters(BigInteger g, BigInteger p) {
        if (p == null || !p.isProbablePrime(80)) {
            throw new IllegalArgumentException("P must be prime");
        }
        validatePublicValue("G", g, p);
    }

    private static void validateExponent(String name, BigInteger value, BigInteger p) {
        if (value == null || value.compareTo(TWO) < 0
                || value.compareTo(p.subtract(TWO)) > 0) {
            throw new IllegalArgumentException(name + " must be between 2 and P - 2");
        }
    }

    private static void validatePublicValue(String name, BigInteger value, BigInteger p) {
        if (value == null || value.compareTo(TWO) < 0
                || value.compareTo(p.subtract(TWO)) > 0) {
            throw new IllegalArgumentException(name + " must be between 2 and P - 2");
        }
    }

    public record PublicKey(BigInteger g, BigInteger p, BigInteger y) {
    }

    public record KeyPair(BigInteger g, BigInteger p, BigInteger x, BigInteger y) {
        public PublicKey publicKey() {
            return new PublicKey(g, p, y);
        }
    }
}
