package com.mouse.jwt.verifiable.domain;

import java.security.InvalidKeyException;
import java.security.SignatureException;

public interface Signature {
    void sign(Token token) throws SignatureException, InvalidKeyException;

    boolean verify(Token token) throws InvalidKeyException, SignatureException;
}
