package org.cybersecurity.crypto;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.Base64;

@Component
public class KeyVaultService {

    private final SecretKey master;

    public KeyVaultService(@Value("${vault.master.base64}") String base64) {
        byte[] key = Base64.getDecoder().decode(base64);
        if (key.length != 32) {
            throw new IllegalArgumentException("vault.master.base64 must be 32 bytes (AES-256) in Base64");
        }
        this.master = new SecretKeySpec(key, "AES");
    }

    /** AES-GCM encrypt (returns blob = [ivLen(4B) | iv | ciphertext+tag]) */
    public byte[] encrypt(byte[] plaintext, byte[] aad) throws Exception {
        byte[] iv = new byte[12];
        new SecureRandom().nextBytes(iv);
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(Cipher.ENCRYPT_MODE, master, new GCMParameterSpec(128, iv));
        if (aad != null) c.updateAAD(aad);
        byte[] ct = c.doFinal(plaintext);

        ByteBuffer bb = ByteBuffer.allocate(4 + iv.length + ct.length);
        bb.putInt(iv.length).put(iv).put(ct);
        return bb.array();
    }

    /** AES-GCM decrypt (expects blob format iz encrypt()) */
    public byte[] decrypt(byte[] blob, byte[] aad) throws Exception {
        ByteBuffer bb = ByteBuffer.wrap(blob);
        int ivLen = bb.getInt();
        byte[] iv = new byte[ivLen]; bb.get(iv);
        byte[] ct = new byte[bb.remaining()]; bb.get(ct);

        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(Cipher.DECRYPT_MODE, master, new GCMParameterSpec(128, iv));
        if (aad != null) c.updateAAD(aad);
        return c.doFinal(ct);
    }
}
