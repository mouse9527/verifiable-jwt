package com.mouse.jwt.verifiable.domain;

import java.security.InvalidKeyException;
import java.security.SignatureException;

public interface Signature {
    void sign(Token<Header, Payload> token) throws SignatureException, InvalidKeyException;

    boolean verify(String rawString, String jwtToken);
}
