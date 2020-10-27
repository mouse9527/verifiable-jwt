package com.mouse.jwt.verifiable.domain;

import java.util.function.Supplier;

public class Token {
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

    public Token(String jwt) {
        Supplier<IllegalJWTTokenException> supplier = () -> new IllegalJWTTokenException("Illegal JWT");
        if (jwt == null || jwt.isEmpty()) {
            throw supplier.get();
        }
        String[] parts = jwt.split("\\.");
        if (parts.length != 3) {
            throw supplier.get();
        }
        this.headerString = parts[0];
        this.payloadString = parts[1];
        this.signature = parts[2];
    }

    public void sign(byte[] signature) {
        this.signature = Serializer.getInstance().base64Encode(signature);
    }

    private String toBase64String(Object obj) {
        return Serializer.getInstance().writeValueToBase64(obj);
    }

    public String toString() {
        return String.format("%s.%s.%s", headerString, payloadString, signature);
    }

    public String getSignContent() {
        return String.format("%s.%s", headerString, payloadString);
    }

    public Payload getPayload(Class<? extends Payload> clazz) {
        if (payload == null) {
            payload = Serializer.getInstance().readValueFromBase64(payloadString, clazz);
        }
        return payload;
    }

    public Header getHeader(Class<? extends Header> clazz) {
        if (header == null) {
            header = Serializer.getInstance().readValueFromBase64(headerString, clazz);
        }
        return header;
    }

    public String getSignature() {
        return signature;
    }
}
