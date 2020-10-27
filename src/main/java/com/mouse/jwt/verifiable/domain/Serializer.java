package com.mouse.jwt.verifiable.domain;

public abstract class Serializer {
    private static Serializer instance;

    static void resetSerializer(Serializer serializer) {
        Serializer.instance = serializer;
    }

    static Serializer getInstance() {
        return instance;
    }

    protected abstract String base64Encode(byte[] src);

    protected abstract byte[] base64Decode(byte[] base64);

    protected abstract <T> T readValueFromBase64(String base64, Class<T> clazz);

    protected abstract String writeValueToBase64(Object src);
}
