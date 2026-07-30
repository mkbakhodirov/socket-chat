package com.example.socketchat.encryption;

import com.google.inject.Singleton;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;

@Singleton
public final class ElGamalEncryption {

    private static final BigInteger TWO = BigInteger.TWO;
    private static final BigInteger P = TWO.pow(255).subtract(BigInteger.valueOf(19));
    private static final BigInteger G = TWO;
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    private static final int ELGAMAL_BYTES = (P.bitLength() + 7) / 8;
    private static final int IV_BYTES = 12;
    private static final int GCM_TAG_BYTES = 16;
    private static final int MAX_PACKET_PAYLOAD_BYTES = Byte.MAX_VALUE;

    public KeyPair generateKeyPair() {
        BigInteger privateValue = randomExponent();
        BigInteger publicValue = G.modPow(privateValue, P);
        return new KeyPair(
                new PublicKey(publicValue),
                new PrivateKey(privateValue)
        );
    }

    public byte[] encodePublicKey(PublicKey publicKey) {
        return encodeElGamalValue(publicKey.getValue());
    }

    public PublicKey decodePublicKey(byte[] encoded) {
        if (encoded == null || encoded.length != ELGAMAL_BYTES) {
            throw new IllegalArgumentException("Invalid ElGamal public key");
        }

        BigInteger value = new BigInteger(1, encoded);
        validatePublicKeyValue(value);
        return new PublicKey(value);
    }

    public byte[] encrypt(String plainText, byte[] receiverPublicKey) throws Exception {
        return encrypt(plainText, decodePublicKey(receiverPublicKey));
    }

    public byte[] encrypt(String plainText, PublicKey receiverPublicKey) throws Exception {
        KeyPair ephemeralKeyPair = generateKeyPair();
        byte[] ephemeralPublic = encodeElGamalValue(ephemeralKeyPair.getPublic().getValue());
        byte[] key = toAesKey(receiverPublicKey.getValue().modPow(ephemeralKeyPair.getPrivate().getValue(), P));
        byte[] iv = new byte[IV_BYTES];
        SECURE_RANDOM.nextBytes(iv);

        byte[] plaintext = plainText.getBytes(StandardCharsets.UTF_8);
        int maximumPlaintextBytes = MAX_PACKET_PAYLOAD_BYTES
                - 1 - ephemeralPublic.length - IV_BYTES - GCM_TAG_BYTES;
        if (plaintext.length > maximumPlaintextBytes) {
            throw new IllegalArgumentException(
                    "Encrypted message must be at most "
                            + maximumPlaintextBytes + " UTF-8 bytes");
        }

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(
                Cipher.ENCRYPT_MODE,
                new SecretKeySpec(key, "AES"),
                new GCMParameterSpec(GCM_TAG_BYTES * 8, iv)
        );
        cipher.updateAAD(header(ephemeralPublic));

        byte[] ciphertext = cipher.doFinal(plaintext);

        return ByteBuffer.allocate(1 + ephemeralPublic.length + IV_BYTES + ciphertext.length)
                .put((byte) ephemeralPublic.length)
                .put(ephemeralPublic)
                .put(iv)
                .put(ciphertext)
                .array();
    }

    public String decrypt(byte[] encrypted, PrivateKey receiverPrivateKey) throws Exception {
        if (encrypted == null || encrypted.length < 1 + ELGAMAL_BYTES
                + IV_BYTES + GCM_TAG_BYTES) {
            throw new IllegalArgumentException("Invalid encrypted message");
        }
        if (encrypted.length > MAX_PACKET_PAYLOAD_BYTES) {
            throw new IllegalArgumentException("Encrypted message is too large");
        }

        ByteBuffer input = ByteBuffer.wrap(encrypted);

        int publicKeyLength = Byte.toUnsignedInt(input.get());
        if (publicKeyLength != ELGAMAL_BYTES
                || input.remaining() < publicKeyLength + IV_BYTES + GCM_TAG_BYTES) {
            throw new IllegalArgumentException("Invalid encrypted message");
        }

        byte[] ephemeralPublic = new byte[publicKeyLength];
        input.get(ephemeralPublic);
        byte[] iv = new byte[IV_BYTES];
        input.get(iv);
        byte[] ciphertext = new byte[input.remaining()];
        input.get(ciphertext);

        BigInteger ephemeralValue = new BigInteger(1, ephemeralPublic);
        validatePublicKeyValue(ephemeralValue);
        byte[] key = toAesKey(ephemeralValue.modPow(receiverPrivateKey.getValue(), P));

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(
                Cipher.DECRYPT_MODE,
                new SecretKeySpec(key, "AES"),
                new GCMParameterSpec(GCM_TAG_BYTES * 8, iv)
        );
        cipher.updateAAD(header(ephemeralPublic));

        byte[] plaintext = cipher.doFinal(ciphertext);

        return new String(plaintext, StandardCharsets.UTF_8);
    }

    private static BigInteger randomExponent() {
        BigInteger maximum = P.subtract(TWO);
        BigInteger value;
        do {
            value = new BigInteger(P.bitLength(), SECURE_RANDOM);
        } while (value.compareTo(TWO) < 0 || value.compareTo(maximum) > 0);
        return value;
    }

    private static void validatePublicKeyValue(BigInteger value) {
        if (value.compareTo(TWO) < 0 || value.compareTo(P.subtract(TWO)) > 0) {
            throw new IllegalArgumentException("Invalid ElGamal public key");
        }
    }

    private static byte[] toAesKey(BigInteger sharedSecret) throws Exception {
        return MessageDigest.getInstance("SHA-256")
                .digest(encodeElGamalValue(sharedSecret));
    }

    private static byte[] encodeElGamalValue(BigInteger value) {
        byte[] source = value.toByteArray();
        byte[] result = new byte[ELGAMAL_BYTES];
        int sourceOffset = source.length > ELGAMAL_BYTES ? 1 : 0;
        int length = source.length - sourceOffset;
        System.arraycopy(source, sourceOffset, result, result.length - length, length);
        return result;
    }

    private static byte[] header(byte[] ephemeralPublic) {
        return ByteBuffer.allocate(1 + ephemeralPublic.length)
                .put((byte) ephemeralPublic.length)
                .put(ephemeralPublic)
                .array();
    }

    public static final class PublicKey {
        private final BigInteger value;

        private PublicKey(BigInteger value) {
            this.value = value;
        }

        public BigInteger getValue() {
            return value;
        }
    }

    public static final class PrivateKey {
        private final BigInteger value;

        private PrivateKey(BigInteger value) {
            this.value = value;
        }

        public BigInteger getValue() {
            return value;
        }
    }

    public static final class KeyPair {
        private final PublicKey publicKey;
        private final PrivateKey privateKey;

        private KeyPair(PublicKey publicKey, PrivateKey privateKey) {
            this.publicKey = publicKey;
            this.privateKey = privateKey;
        }

        public PublicKey getPublic() {
            return publicKey;
        }

        public PrivateKey getPrivate() {
            return privateKey;
        }
    }
}
