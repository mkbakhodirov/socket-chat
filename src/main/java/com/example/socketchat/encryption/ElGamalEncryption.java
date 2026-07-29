package com.example.socketchat.encryption;

import com.google.inject.Singleton;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.NamedParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.HexFormat;

@Singleton
public final class ElGamalEncryption {

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final NamedParameterSpec X25519 = NamedParameterSpec.X25519;
    private static final byte FORMAT_VERSION = 1;
    private static final int IV_BYTES = 12;
    private static final int GCM_TAG_BYTES = 16;
    private static final int MAX_PUBLIC_KEY_BYTES = 255;
    private static final int MAX_PACKET_PAYLOAD_BYTES = 1400;
    private static final byte[] HKDF_INFO =
            "socket-chat/x25519-aes-gcm/v1".getBytes(StandardCharsets.US_ASCII);

    public KeyPair generateKeyPair() throws GeneralSecurityException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("X25519");
        generator.initialize(X25519, RANDOM);
        return generator.generateKeyPair();
    }

    public byte[] encodePublicKey(PublicKey publicKey) {
        return publicKey.getEncoded().clone();
    }

    public PublicKey decodePublicKey(byte[] encoded) throws GeneralSecurityException {
        if (encoded == null || encoded.length == 0 || encoded.length > MAX_PUBLIC_KEY_BYTES) {
            throw new IllegalArgumentException("Invalid X25519 public key");
        }
        return KeyFactory.getInstance("X25519")
                .generatePublic(new X509EncodedKeySpec(encoded));
    }

    public String publicKeyFingerprint(PublicKey publicKey) throws GeneralSecurityException {
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(publicKey.getEncoded());
        return HexFormat.of().formatHex(Arrays.copyOf(digest, 8));
    }

    public byte[] encrypt(String plainText, PublicKey recipientPublicKey)
            throws GeneralSecurityException {
        if (plainText == null) {
            throw new IllegalArgumentException("Message cannot be null");
        }

        KeyPair ephemeralKeyPair = generateKeyPair();
        byte[] ephemeralPublicKey = encodePublicKey(ephemeralKeyPair.getPublic());
        if (ephemeralPublicKey.length > MAX_PUBLIC_KEY_BYTES) {
            throw new GeneralSecurityException("Encoded X25519 public key is too large");
        }

        byte[] plaintext = plainText.getBytes(StandardCharsets.UTF_8);
        int overhead = 2 + ephemeralPublicKey.length + IV_BYTES + GCM_TAG_BYTES;
        int maximumPlaintextBytes = MAX_PACKET_PAYLOAD_BYTES - overhead;
        if (plaintext.length > maximumPlaintextBytes) {
            throw new IllegalArgumentException(
                    "Encrypted message must be at most " + maximumPlaintextBytes + " UTF-8 bytes");
        }

        byte[] sharedSecret = agree(ephemeralKeyPair.getPrivate(), recipientPublicKey);
        byte[] aesKey = deriveAesKey(sharedSecret, ephemeralPublicKey);
        byte[] iv = new byte[IV_BYTES];
        RANDOM.nextBytes(iv);

        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(aesKey, "AES"),
                    new GCMParameterSpec(GCM_TAG_BYTES * 8, iv));
            cipher.updateAAD(header(ephemeralPublicKey));
            byte[] ciphertext = cipher.doFinal(plaintext);

            return ByteBuffer.allocate(2 + ephemeralPublicKey.length + IV_BYTES + ciphertext.length)
                    .put(FORMAT_VERSION)
                    .put((byte) ephemeralPublicKey.length)
                    .put(ephemeralPublicKey)
                    .put(iv)
                    .put(ciphertext)
                    .array();
        } finally {
            Arrays.fill(sharedSecret, (byte) 0);
            Arrays.fill(aesKey, (byte) 0);
        }
    }

    public byte[] encrypt(String plainText, byte[] encodedRecipientPublicKey)
            throws GeneralSecurityException {
        return encrypt(plainText, decodePublicKey(encodedRecipientPublicKey));
    }

    public String decrypt(byte[] encrypted, PrivateKey recipientPrivateKey)
            throws GeneralSecurityException {
        if (encrypted == null || encrypted.length < 2 + IV_BYTES + GCM_TAG_BYTES + 1) {
            throw new IllegalArgumentException("Invalid encrypted message");
        }
        if (encrypted.length > MAX_PACKET_PAYLOAD_BYTES) {
            throw new IllegalArgumentException("Encrypted message is too large");
        }

        ByteBuffer input = ByteBuffer.wrap(encrypted);
        byte version = input.get();
        if (version != FORMAT_VERSION) {
            throw new IllegalArgumentException("Unsupported encrypted message version");
        }

        int publicKeyLength = Byte.toUnsignedInt(input.get());
        if (publicKeyLength == 0 || input.remaining() < publicKeyLength + IV_BYTES + GCM_TAG_BYTES) {
            throw new IllegalArgumentException("Invalid encrypted message");
        }

        byte[] ephemeralPublicKey = new byte[publicKeyLength];
        input.get(ephemeralPublicKey);
        byte[] iv = new byte[IV_BYTES];
        input.get(iv);
        byte[] ciphertext = new byte[input.remaining()];
        input.get(ciphertext);

        byte[] sharedSecret = agree(recipientPrivateKey, decodePublicKey(ephemeralPublicKey));
        byte[] aesKey = deriveAesKey(sharedSecret, ephemeralPublicKey);

        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(aesKey, "AES"),
                    new GCMParameterSpec(GCM_TAG_BYTES * 8, iv));
            cipher.updateAAD(header(ephemeralPublicKey));
            return new String(cipher.doFinal(ciphertext), StandardCharsets.UTF_8);
        } finally {
            Arrays.fill(sharedSecret, (byte) 0);
            Arrays.fill(aesKey, (byte) 0);
        }
    }

    private static byte[] agree(PrivateKey privateKey, PublicKey publicKey)
            throws GeneralSecurityException {
        KeyAgreement agreement = KeyAgreement.getInstance("X25519");
        agreement.init(privateKey);
        agreement.doPhase(publicKey, true);
        return agreement.generateSecret();
    }

    private static byte[] deriveAesKey(byte[] sharedSecret, byte[] ephemeralPublicKey)
            throws GeneralSecurityException {
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        byte[] salt = sha256.digest(ephemeralPublicKey);

        Mac hmac = Mac.getInstance("HmacSHA256");
        hmac.init(new SecretKeySpec(salt, "HmacSHA256"));
        byte[] pseudorandomKey = hmac.doFinal(sharedSecret);
        try {
            hmac.init(new SecretKeySpec(pseudorandomKey, "HmacSHA256"));
            hmac.update(HKDF_INFO);
            hmac.update((byte) 1);
            return hmac.doFinal();
        } finally {
            Arrays.fill(salt, (byte) 0);
            Arrays.fill(pseudorandomKey, (byte) 0);
        }
    }

    private static byte[] header(byte[] ephemeralPublicKey) {
        return ByteBuffer.allocate(2 + ephemeralPublicKey.length)
                .put(FORMAT_VERSION)
                .put((byte) ephemeralPublicKey.length)
                .put(ephemeralPublicKey)
                .array();
    }
}
