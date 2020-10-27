package com.mouse.jwt.verifiable.domain;

import java.time.Instant;

class TestPayload implements Payload {
    private String id = "mock-token-id";
    private String type = "user";
    private String iat = Instant.now().toString();
    private String exp = Instant.now().toString();

    @Override
    public String getId() {
        return id;
    }

    @Override
    public String getType() {
        return type;
    }

    @Override
    public String getIat() {
        return iat;
    }

    @Override
    public String getExp() {
        return exp;
    }
}
