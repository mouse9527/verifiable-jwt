package com.mouse.jwt.verifiable.domain;

import java.security.InvalidKeyException;
import java.security.SignatureException;

public interface JWTServer<P extends Payload> {
    Token<Header, Payload> sign(P payload) throws SignatureException, InvalidKeyException;
}
