package com.mouse.jwt.verifiable.gateways.acl;

import com.mouse.jwt.verifiable.domain.Serializer;
import com.mouse.jwt.verifiable.domain.Token;

import java.nio.charset.StandardCharsets;
import java.security.*;

public class DefaultSignature implements com.mouse.jwt.verifiable.domain.Signature {
    private final Signature signer;
    private final Signature verifier;

    public DefaultSignature(KeyPair keyPair, String algorithm) throws InvalidKeyException, NoSuchAlgorithmException {
        signer = Signature.getInstance(algorithm);
        signer.initSign(keyPair.getPrivate());
        verifier = Signature.getInstance(algorithm);
        verifier.initVerify(keyPair.getPublic());
    }

    @Override
    public void sign(Token token) throws SignatureException {
        synchronized (signer) {
            signer.update(token.getSignContent().getBytes(StandardCharsets.UTF_8));
            token.sign(signer.sign());
        }
    }

    @Override
    public boolean verify(Token token) throws SignatureException {
        synchronized (verifier) {
            verifier.update(token.getSignContent().getBytes(StandardCharsets.UTF_8));
            return verifier.verify(Serializer.getInstance().base64Decode(token.getSignature()));
        }
    }
}
