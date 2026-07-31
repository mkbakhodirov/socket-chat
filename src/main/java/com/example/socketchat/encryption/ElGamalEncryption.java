package com.example.socketchat.encryption;

import com.google.inject.Singleton;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.HexFormat;

@Singleton
public final class ElGamalEncryption {

    private static final BigInteger TWO = BigInteger.TWO;
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();
    public static final BigInteger DEFAULT_P = TWO.pow(255).subtract(BigInteger.valueOf(19));
    public static final BigInteger DEFAULT_G = TWO;

    private static final int AES_KEY_BYTES = 16;

    public KeyPair generateKeyPair() {
        return calculate(
                DEFAULT_G,
                DEFAULT_P,
                randomExponent(DEFAULT_P),
                randomExponent(DEFAULT_P)
        );
    }

    public KeyPair calculate(BigInteger g,
                             BigInteger p,
                             BigInteger x,
                             BigInteger k) {
        validateParameters(g, p);
        validateExponent("x", x, p);
        validateExponent("k", k, p);
        BigInteger y = g.modPow(x, p);
        BigInteger ephemeral = g.modPow(k, p);
        validatePublicValue("y", y, p);
        validatePublicValue("ephemeral", ephemeral, p);
        return new KeyPair(g, p, x, k, y, ephemeral);
    }

    public BigInteger randomExponent(BigInteger p) {
        return randomValue(p);
    }

    private static BigInteger randomValue(BigInteger p) {
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

    public String toEncryptionKey(PublicKey receiver, BigInteger k) {
        validateExponent("k", k, receiver.p());
        return toAesHexKey(receiver.y().modPow(k, receiver.p()));
    }

    public String toDecryptionKey(PublicKey sender,
                                  BigInteger x,
                                  BigInteger p,
                                  BigInteger g) {
        if (!p.equals(sender.p()) || !g.equals(sender.g())) {
            throw new IllegalArgumentException("ElGamal G and P do not match the sender");
        }
        validateExponent("x", x, p);
        return toAesHexKey(sender.ephemeral().modPow(x, p));
    }

    public byte[] encodePublicKey(KeyPair keyPair) {
        return encodePublicKey(keyPair.publicKey());
    }

    public byte[] encodePublicKey(PublicKey publicKey) {
        validatePublicKey(publicKey);
        byte[][] values = {
                unsigned(publicKey.g()), unsigned(publicKey.p()),
                unsigned(publicKey.y()), unsigned(publicKey.ephemeral())
        };
        int size = 4;
        for (byte[] value : values) {
            if (value.length > 255) {
                throw new IllegalArgumentException("ElGamal value is too large");
            }
            size += value.length;
        }
        if (size > 255) {
            throw new IllegalArgumentException("ElGamal public publicKey is too large");
        }

        ByteBuffer output = ByteBuffer.allocate(size);
        for (byte[] value : values) {
            output.put((byte) value.length).put(value);
        }
        return output.array();
    }

    public PublicKey decodePublicKey(byte[] encoded) {
        if (encoded == null) {
            throw new IllegalArgumentException("Missing ElGamal public data");
        }

        ByteBuffer input = ByteBuffer.wrap(encoded);
        BigInteger g = readValue(input);
        BigInteger p = readValue(input);
        BigInteger y = readValue(input);
        BigInteger ephemeral = readValue(input);
        PublicKey data = new PublicKey(g, p, y, ephemeral);
        validatePublicKey(data);
        return data;
    }

    private static BigInteger readValue(ByteBuffer input) {
        if (!input.hasRemaining()) {
            throw new IllegalArgumentException("Incomplete ElGamal public data");
        }
        int length = Byte.toUnsignedInt(input.get());
        if (length == 0 || input.remaining() < length) {
            throw new IllegalArgumentException("Invalid ElGamal value length");
        }
        byte[] value = new byte[length];
        input.get(value);
        return new BigInteger(1, value);
    }

    private static String toAesHexKey(BigInteger sharedSecret) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest(unsigned(sharedSecret));
            return HexFormat.of().formatHex(Arrays.copyOf(digest, AES_KEY_BYTES));
        } catch (Exception ex) {
            throw new IllegalStateException("Could not derive AES key", ex);
        }
    }

    private static byte[] unsigned(BigInteger value) {
        byte[] encoded = value.toByteArray();
        return encoded.length > 1 && encoded[0] == 0
                ? Arrays.copyOfRange(encoded, 1, encoded.length)
                : encoded;
    }

    private static void validatePublicKey(PublicKey publicKey) {
        if (publicKey == null) {
            throw new IllegalArgumentException("Missing ElGamal public publicKey");
        }
        validateParameters(publicKey.g(), publicKey.p());
        validatePublicValue("y", publicKey.y(), publicKey.p());
        validatePublicValue("ephemeral", publicKey.ephemeral(), publicKey.p());
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

    public record PublicKey(
            BigInteger g,
            BigInteger p,
            BigInteger y,
            BigInteger ephemeral
    ) {
    }

    public record KeyPair(
            BigInteger g,
            BigInteger p,
            BigInteger x,
            BigInteger k,
            BigInteger y,
            BigInteger ephemeral
    ) {
        public PublicKey publicKey() {
            return new PublicKey(g, p, y, ephemeral);
        }
    }
}
