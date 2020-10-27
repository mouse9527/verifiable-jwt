package com.mouse.jwt.verifiable.domain;

import com.jayway.jsonpath.JsonPath;
import com.mouse.jwt.verifiable.gateways.acl.DefaultPayload;
import com.mouse.jwt.verifiable.gateways.acl.DefaultSerializer;
import com.mouse.jwt.verifiable.gateways.acl.DefaultSignature;
import com.mouse.jwt.verifiable.gateways.acl.VerifiableJWTServer;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.security.*;
import java.time.Instant;
import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;

public class TokenServerTest {
    private JWTServer jwtServer;

    @BeforeEach
    void setUp() throws InvalidKeyException, NoSuchAlgorithmException {
        jwtServer = new VerifiableJWTServer(createSignature());
        Serializer.resetSerializer(new DefaultSerializer());
    }

    private Signature createSignature() throws NoSuchAlgorithmException, InvalidKeyException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair keyPair = generator.genKeyPair();
        return new DefaultSignature(keyPair, "SHA1withRSA");
    }

    @Test
    void shouldBeAbleToSignToJWT() throws SignatureException, InvalidKeyException {
        DefaultPayload raw = new DefaultPayload("mock-token-id", "user", Instant.parse("2020-10-27T00:00:00Z"), Instant.parse("2020-10-28T00:00:00Z"));

        Token token = jwtServer.sign(raw);

        String jwtToken = token.toString();
        System.out.println(jwtToken);
        assertThat(jwtToken).isNotEmpty();
        assertThat(jwtToken.split("\\.")).hasSize(3);
        String payload = new String(Base64.getDecoder().decode(jwtToken.split("\\.")[1]));
        assertThat(JsonPath.compile("$.id").<String>read(payload)).isEqualTo("mock-token-id");
        assertThat(JsonPath.compile("$.type").<String>read(payload)).isEqualTo("user");
        assertThat(JsonPath.compile("$.iat").<String>read(payload)).isEqualTo("2020-10-27T00:00:00Z");
        assertThat(JsonPath.compile("$.exp").<String>read(payload)).isEqualTo("2020-10-28T00:00:00Z");
    }

    @Test
    void shouldBeAbleToVerifiableJWT() throws SignatureException, InvalidKeyException {
        DefaultPayload payload = new DefaultPayload();
        Token token = jwtServer.sign(payload);

        String jwtToken = token.toString();
        assertThat(jwtServer.verify(new Token(jwtToken))).isTrue();
        assertThat(jwtServer.verify(new Token(jwtToken.replace("A", "B")))).isFalse();
    }

}
