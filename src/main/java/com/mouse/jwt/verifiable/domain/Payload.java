package com.mouse.jwt.verifiable.domain;

public interface Payload {
    String getId();

    String getType();

    String getIat();

    String getExp();
}
