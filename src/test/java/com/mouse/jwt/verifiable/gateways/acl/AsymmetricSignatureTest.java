package com.mouse.jwt.verifiable.gateways.acl;

import com.jayway.jsonpath.JsonPath;
import com.mouse.jwt.verifiable.domain.JWTSignature;
import com.mouse.jwt.verifiable.domain.Serializer;
import com.mouse.jwt.verifiable.domain.Token;
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

    @Test
    void shouldBeAbleToSignWithAES() throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException {
        Serializer.resetSerializer(new DefaultSerializer());
        KeyGenerator generator = KeyGenerator.getInstance("AES");
        generator.init(256);
        Key key = generator.generateKey();
        JWTSignature signature = new AsymmetricSignature(key, "AES");
        Token token = new Token(new DefaultHeader(), new DefaultPayload("mock-token-id", "mock-type", Instant.parse("2020-10-27T00:00:00Z"), Instant.parse("2020-10-28T00:00:00Z")));

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
}