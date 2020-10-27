package com.mouse.jwt.verifiable.domain;

import com.mouse.jwt.verifiable.gateways.acl.DefaultHeader;

public class JWTServer {
    private final JWTSignature JWTSignature;

    public JWTServer(JWTSignature JWTSignature) {
        this.JWTSignature = JWTSignature;
    }

    public Token sign(Payload payload) {
        Token token = new Token(DefaultHeader.RS512, payload);
        JWTSignature.sign(token);
        return token;
    }

    public boolean verify(Token token) {
        return JWTSignature.verify(token);
    }
}
