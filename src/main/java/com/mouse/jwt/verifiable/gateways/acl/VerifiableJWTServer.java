package com.mouse.jwt.verifiable.gateways.acl;

import com.mouse.jwt.verifiable.domain.JWTServer;
import com.mouse.jwt.verifiable.domain.Payload;
import com.mouse.jwt.verifiable.domain.Signature;
import com.mouse.jwt.verifiable.domain.Token;

import java.security.InvalidKeyException;
import java.security.SignatureException;

public class VerifiableJWTServer implements JWTServer {

    private final Signature signature;

    public VerifiableJWTServer(Signature signature) {
        this.signature = signature;
    }

    @Override
    public Token sign(Payload payload) throws SignatureException, InvalidKeyException {
        Token token = new Token(DefaultHeader.RS512, payload);
        signature.sign(token);
        return token;
    }

    @Override
    public boolean verify(String tokenString) throws SignatureException, InvalidKeyException {
        Token token = new Token(tokenString);
        return signature.verify(token);
    }
}
