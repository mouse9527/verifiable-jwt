package com.mouse.jwt.verifiable.domain;

public interface JWTSignature {
    void sign(Token token);

    boolean verify(Token token);
}
