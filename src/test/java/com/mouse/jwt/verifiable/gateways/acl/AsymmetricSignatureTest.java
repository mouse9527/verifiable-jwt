package com.mouse.jwt.verifiable.gateways.acl;

import com.jayway.jsonpath.JsonPath;
import com.mouse.jwt.verifiable.domain.JWTSignature;
import com.mouse.jwt.verifiable.domain.Serializer;
import com.mouse.jwt.verifiable.domain.Token;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;

class AsymmetricSignatureTest {
    private JWTSignature signature;
    private Token token;


    @BeforeAll
    static void beforeAll() {
        Serializer.resetSerializer(new DefaultSerializer());
    }

    @BeforeEach
    void setUp() throws NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException {
        KeyGenerator generator = KeyGenerator.getInstance("AES");
        generator.init(256);
        Key key = generator.generateKey();
        signature = new AsymmetricSignature(key, "AES");
        token = new Token(new DefaultHeader(), new DefaultPayload("mock-token-id", "mock-type", Instant.parse("2020-10-27T00:00:00Z"), Instant.parse("2020-10-28T00:00:00Z")));
    }

    @Test
    void shouldBeAbleToSignWithAES() {
        signature.sign(token);

        String jwt = token.toString();
        System.out.println(jwt);
        assertThat(jwt.split("\\.")).hasSize(3);
        String payload = new String(Base64.getDecoder().decode(jwt.split("\\.")[1]));
        assertThat(JsonPath.compile("$.id").<String>read(payload)).isEqualTo("mock-token-id");
        assertThat(JsonPath.compile("$.type").<String>read(payload)).isEqualTo("mock-type");
        assertThat(JsonPath.compile("$.iat").<String>read(payload)).isEqualTo("2020-10-27T00:00:00Z");
        assertThat(JsonPath.compile("$.exp").<String>read(payload)).isEqualTo("2020-10-28T00:00:00Z");
    }

    @Test
    void shouldBeAbleToVerifyWithAES() {
        signature.sign(token);

        assertThat(signature.verify(token)).isTrue();
    }
}