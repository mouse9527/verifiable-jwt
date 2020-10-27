package com.mouse.jwt.verifiable.gateways.acl;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.mouse.jwt.verifiable.domain.Serializer;

import java.io.IOException;
import java.util.Base64;

public class DefaultSerializer extends Serializer {
    private final ObjectMapper objectMapper;
    private final Base64.Encoder encoder;
    private final Base64.Decoder decoder;

    public DefaultSerializer() {
        objectMapper = new ObjectMapper().registerModule(new JavaTimeModule());
        objectMapper.configure(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS, false);
        encoder = Base64.getEncoder();
        decoder = Base64.getDecoder();
    }

    @Override
    protected String base64Encode(byte[] src) {
        return encoder.encodeToString(src);
    }

    @Override
    protected byte[] base64Decode(byte[] base64) {
        return decoder.decode(base64);
    }

    @Override
    protected <T> T readValueFromBase64(String base64, Class<T> clazz) {
        try {
            return objectMapper.readValue(decoder.decode(base64), clazz);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    protected String writeValueToBase64(Object src) {
        try {
            return base64Encode(objectMapper.writeValueAsBytes(src));
        } catch (JsonProcessingException e) {
            throw new RuntimeException(e);
        }
    }
}
