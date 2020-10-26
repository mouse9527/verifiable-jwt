package com.mouse.jwt.verifiable.gateways.acl;

import com.mouse.jwt.verifiable.domain.*;

import java.security.InvalidKeyException;
import java.security.SignatureException;

public class VerifiableJWTServer<P extends Payload> implements JWTServer<P> {

    private final Signature signature;

    public VerifiableJWTServer(Signature signature) {
        this.signature = signature;
    }

    @Override
    public Token<Header, Payload> sign(P payload) throws SignatureException, InvalidKeyException {
        Token<Header, Payload> token = new Token<>(RSAHeader.DEFAULT, payload);
        signature.sign(token);
        return token;
    }

    @Override
    public boolean verify(String tokenString) throws SignatureException, InvalidKeyException {
        return signature.verify(tokenString);
    }
}
