package com.mouse.jwt.verifiable.domain;

public interface JWTServer {
    Token sign(Payload payload);

    boolean verify(Token token);
}
