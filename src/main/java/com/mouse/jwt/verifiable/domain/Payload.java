package com.mouse.jwt.verifiable.domain;

import java.time.Instant;

public interface Payload {
    String getId();

    String getType();

    Instant getIat();

    Instant getExp();
}
