package com.mouse.jwt.verifiable.domain;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.util.Base64;

public class Token<HEADER, PAYLOAD> {
    private static final Base64.Encoder ENCODER = Base64.getEncoder();
    private final ObjectMapper objectMapper = new ObjectMapper();
    private final HEADER header;
    private final PAYLOAD payload;
    private final String headerString;
    private final String payloadString;
    private String signature;

    public Token(HEADER header, PAYLOAD payload) {
        this.header = header;
        this.headerString = toBase64String(header);
        this.payload = payload;
        this.payloadString = toBase64String(payload);
    }

    public void sign(byte[] signature) {
        this.signature = ENCODER.encodeToString(signature);
    }

    private String toBase64String(Object obj) {
        try {
            return ENCODER.encodeToString(objectMapper.writeValueAsBytes(obj));
        } catch (JsonProcessingException e) {
            throw new RuntimeException(e);
        }
    }

    public String toString() {
        return String.format("%s.%s.%s", headerString, payloadString, signature);
    }

    public String getSignContent() {
        return String.format("%s.%s", headerString, payloadString);
    }
}
