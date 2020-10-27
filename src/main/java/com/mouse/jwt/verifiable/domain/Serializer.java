package com.mouse.jwt.verifiable.domain;

public abstract class Serializer {
    private static Serializer instance;

    public static void resetSerializer(Serializer serializer) {
        Serializer.instance = serializer;
    }

    public static Serializer getInstance() {
        if (instance == null) {
            throw new RuntimeException("Serializer not initialized");
        }
        return instance;
    }

    public abstract String base64Encode(byte[] src);

    public abstract byte[] base64Decode(String base64);

    public abstract <T> T readValueFromBase64(String base64, Class<T> clazz);

    public abstract String writeValueToBase64(Object src);
}
