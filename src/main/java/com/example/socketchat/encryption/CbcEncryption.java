package com.example.socketchat.encryption;

import com.google.inject.Singleton;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.HexFormat;

@Singleton
public class CbcEncryption {
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();
    private static final int IV_BYTES = 16;

    public String generateKey() {
        byte[] key = new byte[16];
        SECURE_RANDOM.nextBytes(key);
        return HexFormat.of().formatHex(key);
    }

    public byte[] encrypt(String plainText, String hexKey) throws Exception {
        byte[] key = fromHex(hexKey);

        byte[] iv = new byte[IV_BYTES];
        SECURE_RANDOM.nextBytes(iv);

        Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
        cipher.init(
                Cipher.ENCRYPT_MODE,
                new SecretKeySpec(key, "AES"),
                new IvParameterSpec(iv)
        );

        byte[] ciphertext = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));

        byte[] encrypted = new byte[iv.length + ciphertext.length];
        System.arraycopy(iv, 0, encrypted, 0, iv.length);
        System.arraycopy(ciphertext, 0, encrypted, iv.length, ciphertext.length);

        return encrypted;
    }

    public String decrypt(byte[] encrypted, String hexKey) throws Exception {
        byte[] key = fromHex(hexKey);
        if (encrypted == null || encrypted.length < IV_BYTES + 16) {
            throw new IllegalArgumentException("Invalid AES-GCM message");
        }

        byte[] iv = Arrays.copyOfRange(encrypted, 0, IV_BYTES);
        byte[] ciphertext = Arrays.copyOfRange(encrypted, iv.length, encrypted.length);

        Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
        cipher.init(
                Cipher.DECRYPT_MODE,
                new SecretKeySpec(key, "AES"),
                new IvParameterSpec(iv)
        );

        byte[] plaintext = cipher.doFinal(ciphertext);

        return new String(plaintext, StandardCharsets.UTF_8);
    }

    private byte[] fromHex(String hexKey) {
        String normalizedKey = hexKey.replaceAll("\\s+", "");
        if (!normalizedKey.matches("[0-9a-fA-F]+")) {
            throw new IllegalArgumentException("AES key must contain only hexadecimal characters");
        }

        if (normalizedKey.length() != 32 && normalizedKey.length() != 48 && normalizedKey.length() != 64) {
            throw new IllegalArgumentException("AES key must be 32, 48, or 64 hex characters");
        }

        return HexFormat.of().parseHex(normalizedKey);
    }
}
