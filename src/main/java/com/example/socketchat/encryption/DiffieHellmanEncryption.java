package com.example.socketchat.encryption;

import com.google.inject.Singleton;

import java.math.BigInteger;
import java.nio.ByteBuffer;
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
        BigInteger publicValue = g.modPow(x, p);
        validatePublicValue("A", publicValue, p);
        return new KeyPair(g, p, x, publicValue);
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
        if (!p.equals(receiver.p()) || !g.equals(receiver.g())) {
            throw new IllegalArgumentException("Diffie-Hellman G and P do not match the receiver");
        }
        validateExponent("x", x, p);
        return receiver.publicValue().modPow(x, p);
    }

    public String toSecretKey(PublicKey receiver, BigInteger x, BigInteger p, BigInteger g) {
        String key = sharedSecret(receiver, x, p, g).toString(16);
        int length = key.length() <= 32 ? 32 : key.length() <= 48 ? 48 : 64;
        if (key.length() > length) {
            throw new IllegalArgumentException("Diffie-Hellman K is too large for AES");
        }
        return "0".repeat(length - key.length()) + key;
    }

    public byte[] encodePublicKey(KeyPair keyPair) {
        return encodePublicKey(keyPair.publicKey());
    }

    public byte[] encodePublicKey(PublicKey publicKey) {
        validatePublicKey(publicKey);
        byte[][] values = {
                unsigned(publicKey.g()), unsigned(publicKey.p()), unsigned(publicKey.publicValue())
        };
        int size = 3;
        for (byte[] value : values) {
            if (value.length > 255) {
                throw new IllegalArgumentException("Diffie-Hellman value is too large");
            }
            size += value.length;
        }
        if (size > 255) {
            throw new IllegalArgumentException("Diffie-Hellman public key is too large");
        }

        ByteBuffer output = ByteBuffer.allocate(size);
        for (byte[] value : values) {
            output.put((byte) value.length).put(value);
        }
        return output.array();
    }

    public PublicKey decodePublicKey(byte[] encoded) {
        if (encoded == null) {
            throw new IllegalArgumentException("Missing Diffie-Hellman public data");
        }

        ByteBuffer input = ByteBuffer.wrap(encoded);
        PublicKey publicKey = new PublicKey(readValue(input), readValue(input), readValue(input));
        validatePublicKey(publicKey);
        return publicKey;
    }

    private static BigInteger readValue(ByteBuffer input) {
        if (!input.hasRemaining()) {
            throw new IllegalArgumentException("Incomplete Diffie-Hellman public data");
        }
        int length = Byte.toUnsignedInt(input.get());
        if (length == 0 || input.remaining() < length) {
            throw new IllegalArgumentException("Invalid Diffie-Hellman value length");
        }
        byte[] value = new byte[length];
        input.get(value);
        return new BigInteger(1, value);
    }

    private static byte[] unsigned(BigInteger value) {
        byte[] encoded = value.toByteArray();
        if (encoded.length > 1 && encoded[0] == 0) {
            byte[] unsigned = new byte[encoded.length - 1];
            System.arraycopy(encoded, 1, unsigned, 0, unsigned.length);
            return unsigned;
        }
        return encoded;
    }

    private static void validatePublicKey(PublicKey publicKey) {
        if (publicKey == null) {
            throw new IllegalArgumentException("Missing Diffie-Hellman public key");
        }
        validateParameters(publicKey.g(), publicKey.p());
        validatePublicValue("public value", publicKey.publicValue(), publicKey.p());
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

    public record PublicKey(BigInteger g, BigInteger p, BigInteger publicValue) {
    }

    public record KeyPair(BigInteger g, BigInteger p, BigInteger x, BigInteger publicValue) {
        public PublicKey publicKey() {
            return new PublicKey(g, p, publicValue);
        }
    }
}
