package com.mouse.jwt.verifiable.gateways.acl;

import com.mouse.jwt.verifiable.domain.Token;

import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.Signature;
import java.security.SignatureException;
import java.util.Base64;

public class DefaultSignature implements com.mouse.jwt.verifiable.domain.Signature {
    private final Signature signature;
    private final KeyPair keyPair;

    public DefaultSignature(KeyPair keyPair, Signature signature) {
        this.keyPair = keyPair;
        this.signature = signature;
    }

    @Override
    public void sign(Token token) throws SignatureException, InvalidKeyException {
        signature.initSign(keyPair.getPrivate());
        signature.update(token.getSignContent().getBytes(StandardCharsets.UTF_8));
        token.sign(signature.sign());
    }

    @Override
    public boolean verify(Token token) throws InvalidKeyException, SignatureException {
        signature.initVerify(keyPair.getPublic());
        signature.update(token.getSignContent().getBytes(StandardCharsets.UTF_8));
        return signature.verify(Base64.getDecoder().decode(token.getSignature()));
    }
}
