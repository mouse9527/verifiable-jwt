package com.mouse.jwt.verifiable.domain;

public interface JWTServer<T> {
    String sign(T payload);
}
