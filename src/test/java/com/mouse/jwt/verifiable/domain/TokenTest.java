package com.mouse.jwt.verifiable.domain;

import com.mouse.jwt.verifiable.gateways.acl.DefaultHeader;
import com.mouse.jwt.verifiable.gateways.acl.DefaultPayload;
import com.mouse.jwt.verifiable.gateways.acl.DefaultSerializer;
import org.junit.jupiter.api.Test;

import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;

class TokenTest {
    private static final String JWT_TOKEN = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzUxMiJ9.eyJpZCI6Im1vY2stdG9rZW4taWQiLCJ0eXBlIjoidXNlciIsImlhdCI6IjIwMjAtMTAtMjdUMDA6MDA6MDBaIiwiZXhwIjoiMjAyMC0xMC0yOFQwMDowMDowMFoifQ==.eU8CXF/Uvs4yjKLM9kkXcnjUlUlYfaJCPFCMJ0BECuTb2USd3EP/3rCg5GkKF5+InBc63diMiw7xCxYaak3HB+UDpXFEvVru6vRZ1EpeyJIA62XnoxzTI0z1e0XeiCH04v4k8IlxNTd7rcufq5i5vtVHU/wlz7tI13ggkWx1mDtnXi6D5wBtln/2dH6NmV+DJTIfZViEmv9/UJ4HIjzQd9VlUI0F/i6SnAR+pE3IHcDLta8HC3BL6fFgqCoMYQMkg9cRVVW0ha63NhsEOkB9UkCxyOUJASroVWaY4I8th/k0HVws7NzWn54RCAqokMeYJj4KVrj8z6t0AYGlqftqZg==";

    @Test
    void shouldBeAbleToCreateWithJWTToken() {
        Serializer.resetSerializer(new DefaultSerializer());

        Token token = new Token(JWT_TOKEN);

        assertThat(token.getPayload(DefaultPayload.class).getId()).isEqualTo("mock-token-id");
        assertThat(token.getPayload(DefaultPayload.class).getType()).isEqualTo("user");
        assertThat(token.getPayload(DefaultPayload.class).getIat()).isEqualTo(Instant.parse("2020-10-27T00:00:00Z"));
        assertThat(token.getPayload(DefaultPayload.class).getExp()).isEqualTo(Instant.parse("2020-10-28T00:00:00Z"));
        assertThat(token.getHeader(DefaultHeader.class).getTyp()).isEqualTo("JWT");
        assertThat(token.getHeader(DefaultHeader.class).getAlg()).isEqualTo("RS512");
        assertThat(token.getSignature()).isEqualTo("eU8CXF/Uvs4yjKLM9kkXcnjUlUlYfaJCPFCMJ0BECuTb2USd3EP/3rCg5GkKF5+InBc63diMiw7xCxYaak3HB+UDpXFEvVru6vRZ1EpeyJIA62XnoxzTI0z1e0XeiCH04v4k8IlxNTd7rcufq5i5vtVHU/wlz7tI13ggkWx1mDtnXi6D5wBtln/2dH6NmV+DJTIfZViEmv9/UJ4HIjzQd9VlUI0F/i6SnAR+pE3IHcDLta8HC3BL6fFgqCoMYQMkg9cRVVW0ha63NhsEOkB9UkCxyOUJASroVWaY4I8th/k0HVws7NzWn54RCAqokMeYJj4KVrj8z6t0AYGlqftqZg==");
    }
}