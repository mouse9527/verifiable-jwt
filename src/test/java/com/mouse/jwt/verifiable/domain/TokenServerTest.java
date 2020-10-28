package com.mouse.jwt.verifiable.domain;

import com.jayway.jsonpath.JsonPath;
import com.mouse.jwt.verifiable.gateways.acl.DefaultPayload;
import com.mouse.jwt.verifiable.gateways.acl.DefaultSerializer;
import com.mouse.jwt.verifiable.gateways.acl.SymmetricSignature;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
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

    @BeforeAll
    static void beforeAll() {
        Serializer.resetSerializer(new DefaultSerializer());
    }

    @BeforeEach
    void setUp() throws InvalidKeyException, NoSuchAlgorithmException {
        jwtServer = new JWTServer(createSignature());
        raw = new DefaultPayload("mock-token-id", "user", IAT, EXP);
    }

    private JWTSignature createSignature() throws NoSuchAlgorithmException, InvalidKeyException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(1024);
        KeyPair keyPair = generator.genKeyPair();
        return new SymmetricSignature(keyPair, "SHA1withRSA");
    }

    @Test
    void shouldBeAbleToSignToJWT() {
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
    void shouldBeAbleToVerifiableJWT() {
        DefaultPayload payload = new DefaultPayload();
        Token token = jwtServer.sign(payload);

        String jwtToken = token.toString();
        assertThat(jwtServer.verify(new Token(jwtToken))).isTrue();
        assertThat(jwtServer.verify(new Token(jwtToken.replace("A", "B")))).isFalse();
    }

    @Test
    void shouldBeAbleToAsyncSign() throws InterruptedException {
        Map<Payload, Token> tokens = new ConcurrentHashMap<>();
        for (int i = 0; i < 100; i++) {
            DefaultPayload payload = new DefaultPayload(String.valueOf(i), String.valueOf(i), IAT, EXP);
            new Thread(new Job(payload, tokens)).start();
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
            Token token = jwtServer.sign(payload);
            tokens.put(payload, token);
        }
    }
}
