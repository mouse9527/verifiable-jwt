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
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import static org.assertj.core.api.Assertions.assertThat;

public class TokenServerTest {
    private static final Instant IAT = Instant.parse("2020-10-27T00:00:00Z");
    private static final Instant EXP = Instant.parse("2020-10-28T00:00:00Z");
    private JWTServer jwtServer;
    private DefaultPayload raw;

    @BeforeEach
    void setUp() throws InvalidKeyException, NoSuchAlgorithmException {
        jwtServer = new VerifiableJWTServer(createSignature());
        Serializer.resetSerializer(new DefaultSerializer());
        raw = new DefaultPayload("mock-token-id", "user", IAT, EXP);
    }

    private Signature createSignature() throws NoSuchAlgorithmException, InvalidKeyException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair keyPair = generator.genKeyPair();
        return new DefaultSignature(keyPair, "SHA1withRSA");
    }

    @Test
    void shouldBeAbleToSignToJWT() throws SignatureException, InvalidKeyException {
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


    @Test
    void shouldBeAbleToAsyncSign() throws InterruptedException, SignatureException, InvalidKeyException {
        Map<Payload, Token> tokens = new ConcurrentHashMap<>();
        for (int i = 0; i < 100; i++) {
            new Thread(new Job(new DefaultPayload(String.valueOf(i), String.valueOf(i), IAT, EXP), tokens)).start();
        }

        Thread.sleep(2000);
        for (Token token : tokens.values()) {
            assertThat(jwtServer.verify(token)).isTrue();
        }
    }

    class Job implements Runnable {
        private final Payload payload;
        private final Map<Payload, Token> tokens;

        Job(Payload payload, Map<Payload, Token> tokens) {
            this.payload = payload;
            this.tokens = tokens;
        }

        @Override
        public void run() {
            try {
                Token token = jwtServer.sign(payload);
                tokens.put(payload, token);
            } catch (SignatureException | InvalidKeyException e) {
                e.printStackTrace();
            }
        }
    }
}
