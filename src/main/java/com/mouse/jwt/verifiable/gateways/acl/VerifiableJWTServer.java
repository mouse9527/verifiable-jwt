package com.mouse.jwt.verifiable.gateways.acl;

import com.mouse.jwt.verifiable.domain.JWTServer;
import com.mouse.jwt.verifiable.domain.Payload;
import com.mouse.jwt.verifiable.domain.JWTSignature;
import com.mouse.jwt.verifiable.domain.Token;

public class VerifiableJWTServer implements JWTServer {
    private final JWTSignature JWTSignature;

    public VerifiableJWTServer(JWTSignature JWTSignature) {
        this.JWTSignature = JWTSignature;
    }

    @Override
    public Token sign(Payload payload) {
        Token token = new Token(DefaultHeader.RS512, payload);
        JWTSignature.sign(token);
        return token;
    }

    @Override
    public boolean verify(Token token) {
        return JWTSignature.verify(token);
    }
}
