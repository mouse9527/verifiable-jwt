package com.mouse.jwt.verifiable.domain;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.util.Base64;

public class Token {
    private static final Base64.Encoder ENCODER = Base64.getEncoder();
    private final ObjectMapper objectMapper = new ObjectMapper();
    private final String headerString;
    private final String payloadString;
    private Header header;
    private Payload payload;
    private String signature;

    public Token(Header header, Payload payload) {
        this.header = header;
        this.headerString = toBase64String(header);
        this.payload = payload;
        this.payloadString = toBase64String(payload);
    }

    public Token(String jwtToken) {
        String[] split = jwtToken.split("\\.");
        this.headerString = split[0];
        this.payloadString = split[1];
        this.signature = split[2];
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

    public Payload getPayload(Class<? extends Payload> clazz) throws IOException {
        if (payload == null) {
            payload = objectMapper.readValue(Base64.getDecoder().decode(payloadString), clazz);
        }
        return payload;
    }

    public Header getHeader(Class<? extends Header> clazz) throws IOException {
        if (header == null) {
            header = objectMapper.readValue(Base64.getDecoder().decode(headerString), clazz);
        }
        return header;
    }

    public String getSignature() {
        return signature;
    }
}
