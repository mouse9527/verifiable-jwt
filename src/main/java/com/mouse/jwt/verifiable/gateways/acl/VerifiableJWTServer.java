package com.mouse.jwt.verifiable.gateways.acl;

import com.mouse.jwt.verifiable.domain.JWTServer;

public class VerifiableJWTServer<T> implements JWTServer<T> {

    @Override
    public String sign(T payload) {
        return null;
    }
}
