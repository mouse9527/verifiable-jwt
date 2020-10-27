package com.mouse.jwt.verifiable.gateways.acl;

import com.mouse.jwt.verifiable.domain.Payload;

import java.time.Instant;

public class DefaultPayload implements Payload {
    private String id;
    private String type;
    private Instant iat;
    private Instant exp;

    public DefaultPayload(String id, String type, Instant iat, Instant exp) {
        this.id = id;
        this.type = type;
        this.iat = iat;
        this.exp = exp;
    }

    public DefaultPayload() {
    }

    @Override
    public String getId() {
        return id;
    }

    @Override
    public String getType() {
        return type;
    }

    @Override
    public Instant getIat() {
        return iat;
    }

    @Override
    public Instant getExp() {
        return exp;
    }
}
