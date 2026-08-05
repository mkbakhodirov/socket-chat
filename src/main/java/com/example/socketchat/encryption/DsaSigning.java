package com.example.socketchat.encryption;

import com.google.inject.Singleton;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.SecureRandom;

@Singleton
public final class DsaSigning {

    private static final BigInteger ONE = BigInteger.ONE;
    private static final BigInteger TWO = BigInteger.TWO;
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();
    public static final BigInteger DEFAULT_P = new BigInteger("57896044618658097711785492504343953971211982399463220733430865577518200520441");
    public static final BigInteger DEFAULT_Q = new BigInteger("170141183460469231731687303715884105727");
    public static final BigInteger DEFAULT_G = new BigInteger("17921693093724708385849493981084370599727531480288526891237582100324776016502");

    public KeyPair generateKeyPair() {
        return calculate(DEFAULT_P, DEFAULT_Q, DEFAULT_G, randomValue(DEFAULT_Q));
    }

    public KeyPair calculate(BigInteger p, BigInteger q, BigInteger g, BigInteger x) {
        validateParameters(p, q, g);
        validatePrivateValue(x, q);
        return new KeyPair(p, q, g, x, g.modPow(x, p));
    }

    public BigInteger randomValue(BigInteger q) {
        if (q == null || q.compareTo(TWO) < 0) {
            throw new IllegalArgumentException("Q must be at least 2");
        }
        BigInteger value;
        do {
            value = new BigInteger(q.bitLength(), SECURE_RANDOM);
        } while (value.compareTo(ONE) < 0 || value.compareTo(q) >= 0);
        return value;
    }

    public Signature sign(byte[] message, KeyPair keyPair) {
        validateKeyPair(keyPair);
        BigInteger hash = hash(message);
        BigInteger r;
        BigInteger s;
        do {
            BigInteger k = randomValue(keyPair.q());
            r = keyPair.g().modPow(k, keyPair.p()).mod(keyPair.q());
            s = k.modInverse(keyPair.q()).multiply(hash.add(keyPair.x().multiply(r))).mod(keyPair.q());
        } while (r.signum() == 0 || s.signum() == 0);
        return new Signature(r, s);
    }

    public boolean verify(byte[] message, Signature signature, PublicKey publicKey) {
        validatePublicKey(publicKey);
        if (signature == null || signature.r().compareTo(ONE) < 0 || signature.r().compareTo(publicKey.q()) >= 0
                || signature.s().compareTo(ONE) < 0 || signature.s().compareTo(publicKey.q()) >= 0) {
            return false;
        }
        BigInteger w = signature.s().modInverse(publicKey.q());
        BigInteger u1 = hash(message).multiply(w).mod(publicKey.q());
        BigInteger u2 = signature.r().multiply(w).mod(publicKey.q());
        BigInteger v = publicKey.g().modPow(u1, publicKey.p())
                .multiply(publicKey.y().modPow(u2, publicKey.p()))
                .mod(publicKey.p()).mod(publicKey.q());
        return v.equals(signature.r());
    }

    public PublicKey publicKey(BigInteger p, BigInteger q, BigInteger g, BigInteger y) {
        PublicKey publicKey = new PublicKey(p, q, g, y);
        validatePublicKey(publicKey);
        return publicKey;
    }

    public byte[] encodeSigned(byte[] message, Signature signature) {
        byte[] signatureData = encodeValues(signature.r(), signature.s());
        byte[] data = new byte[signatureData.length + message.length];
        System.arraycopy(signatureData, 0, data, 0, signatureData.length);
        System.arraycopy(message, 0, data, signatureData.length, message.length);
        return data;
    }

    public SignedMessage decodeSigned(byte[] data) {
        try {
            ByteArrayInputStream input = new ByteArrayInputStream(data);
            DataInputStream stream = new DataInputStream(input);
            BigInteger r = readValue(stream);
            BigInteger s = readValue(stream);
            return new SignedMessage(input.readAllBytes(), new Signature(r, s));
        } catch (Exception ex) {
            throw new IllegalArgumentException("Invalid DSA signed message");
        }
    }

    private BigInteger hash(byte[] message) {
        try {
            return new BigInteger(1, MessageDigest.getInstance("SHA-256").digest(message));
        } catch (Exception ex) {
            throw new IllegalStateException(ex);
        }
    }

    private byte[] encodeValues(BigInteger... values) {
        try {
            ByteArrayOutputStream output = new ByteArrayOutputStream();
            DataOutputStream stream = new DataOutputStream(output);
            for (BigInteger value : values) {
                byte[] bytes = value.toByteArray();
                stream.writeByte(bytes.length);
                stream.write(bytes);
            }
            return output.toByteArray();
        } catch (Exception ex) {
            throw new IllegalArgumentException(ex);
        }
    }

    private BigInteger readValue(DataInputStream stream) throws Exception {
        int length = stream.readUnsignedByte();
        if (length == 0 || length > stream.available()) {
            throw new IllegalArgumentException("Invalid DSA value");
        }
        return new BigInteger(stream.readNBytes(length));
    }

    private void validateKeyPair(KeyPair keyPair) {
        if (keyPair == null) {
            throw new IllegalArgumentException("Missing DSA key pair");
        }
        validateParameters(keyPair.p(), keyPair.q(), keyPair.g());
        validatePrivateValue(keyPair.x(), keyPair.q());
        if (!keyPair.g().modPow(keyPair.x(), keyPair.p()).equals(keyPair.y())) {
            throw new IllegalArgumentException("Invalid DSA public value");
        }
    }

    private void validatePublicKey(PublicKey publicKey) {
        if (publicKey == null) {
            throw new IllegalArgumentException("Missing DSA public key");
        }
        validateParameters(publicKey.p(), publicKey.q(), publicKey.g());
        if (publicKey.y() == null || publicKey.y().compareTo(ONE) < 0 || publicKey.y().compareTo(publicKey.p()) >= 0
                || !publicKey.y().modPow(publicKey.q(), publicKey.p()).equals(ONE)) {
            throw new IllegalArgumentException("Invalid DSA public value");
        }
    }

    private void validateParameters(BigInteger p, BigInteger q, BigInteger g) {
        if (p == null || !p.isProbablePrime(80)) {
            throw new IllegalArgumentException("P must be prime");
        }
        if (q == null || !q.isProbablePrime(80) || !p.subtract(ONE).mod(q).equals(BigInteger.ZERO)) {
            throw new IllegalArgumentException("Q must be prime and divide P - 1");
        }
        if (g == null || g.compareTo(ONE) <= 0 || g.compareTo(p) >= 0 || !g.modPow(q, p).equals(ONE)) {
            throw new IllegalArgumentException("G must have order Q modulo P");
        }
    }

    private void validatePrivateValue(BigInteger x, BigInteger q) {
        if (x == null || x.compareTo(ONE) < 0 || x.compareTo(q) >= 0) {
            throw new IllegalArgumentException("x must be between 1 and Q - 1");
        }
    }

    public record PublicKey(BigInteger p, BigInteger q, BigInteger g, BigInteger y) {
    }

    public record KeyPair(BigInteger p, BigInteger q, BigInteger g, BigInteger x, BigInteger y) {
        public PublicKey publicKey() {
            return new PublicKey(p, q, g, y);
        }
    }

    public record Signature(BigInteger r, BigInteger s) {
    }

    public record SignedMessage(byte[] message, Signature signature) {
    }
}
