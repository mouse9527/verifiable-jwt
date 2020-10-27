package com.mouse.jwt.verifiable.domain;

import java.security.InvalidKeyException;
import java.security.SignatureException;

public interface JWTServer {
    Token sign(Payload payload) throws SignatureException, InvalidKeyException;

    boolean verify(String tokenString) throws SignatureException, InvalidKeyException;
}
