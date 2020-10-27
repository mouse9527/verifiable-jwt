package com.mouse.jwt.verifiable.domain;

import java.nio.charset.StandardCharsets;
import java.security.*;

public class JWTSignature {
    private final Signature signer;
    private final Signature verifier;

    public JWTSignature(KeyPair keyPair, String algorithm) throws InvalidKeyException, NoSuchAlgorithmException {
        signer = Signature.getInstance(algorithm);
        signer.initSign(keyPair.getPrivate());
        verifier = Signature.getInstance(algorithm);
        verifier.initVerify(keyPair.getPublic());
    }

    public void sign(Token token) {
        synchronized (signer) {
            try {
                signer.update(token.getSignContent().getBytes(StandardCharsets.UTF_8));
                token.sign(signer.sign());
            } catch (SignatureException e) {
                // do nothing;
                throw new RuntimeException(e);
            }
        }
    }

    public boolean verify(Token token) {
        synchronized (verifier) {
            try {
                verifier.update(token.getSignContent().getBytes(StandardCharsets.UTF_8));
                return verifier.verify(Serializer.getInstance().base64Decode(token.getSignature()));
            } catch (SignatureException e) {
                throw new RuntimeException(e);
                // do nothing;
            }
        }
    }
}
