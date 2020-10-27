package com.mouse.jwt.verifiable.gateways.acl;

import com.mouse.jwt.verifiable.domain.JWTSignature;
import com.mouse.jwt.verifiable.domain.Serializer;
import com.mouse.jwt.verifiable.domain.Token;

import java.nio.charset.StandardCharsets;
import java.security.*;

public class SymmetricSignature implements JWTSignature {
    private final Signature signer;
    private final Signature verifier;

    public SymmetricSignature(KeyPair keyPair, String algorithm) throws InvalidKeyException, NoSuchAlgorithmException {
        signer = Signature.getInstance(algorithm);
        signer.initSign(keyPair.getPrivate());
        verifier = Signature.getInstance(algorithm);
        verifier.initVerify(keyPair.getPublic());
    }

    @Override
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

    @Override
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
