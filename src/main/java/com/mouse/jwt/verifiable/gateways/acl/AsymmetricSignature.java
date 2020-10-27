package com.mouse.jwt.verifiable.gateways.acl;

import com.mouse.jwt.verifiable.domain.JWTSignature;
import com.mouse.jwt.verifiable.domain.Token;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class AsymmetricSignature implements JWTSignature {
    private final Cipher signer;
    private final Cipher verifier;
    private final MessageDigest digest;

    public AsymmetricSignature(Key key, String transformation) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException {
        signer = Cipher.getInstance(transformation);
        signer.init(Cipher.ENCRYPT_MODE, key);
        verifier = Cipher.getInstance(transformation);
        verifier.init(Cipher.DECRYPT_MODE, key);
        digest = MessageDigest.getInstance("SHA-256");
    }

    @Override
    public void sign(Token token) {
        String content = token.getSignContent();
        try {
            token.sign(digest.digest(signer.doFinal(content.getBytes(StandardCharsets.UTF_8))));
        } catch (IllegalBlockSizeException | BadPaddingException e) {
            e.printStackTrace();
        }
    }

    @Override
    public boolean verify(Token token) {
        return false;
    }
}
