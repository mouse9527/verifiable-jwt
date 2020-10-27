package com.mouse.jwt.verifiable.domain;

public class IllegalJWTTokenException extends IllegalArgumentException {
    public IllegalJWTTokenException(String message) {
        super(message);
    }
}
