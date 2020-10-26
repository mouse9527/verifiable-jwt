package com.mouse.jwt.verifiable.domain;

import com.mouse.jwt.verifiable.gateways.acl.VerifiableJWTServer;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;

public class TokenServerTest {
    private JWTServer<TestToken> jwtServer;

    @BeforeEach
    void setUp() {
        jwtServer = new VerifiableJWTServer<>();
    }

    @Test
    @Disabled
    void shouldBeAbleToSignToJWT() {
        TestToken token = new TestToken("mock-token-id");
        String jwtString = jwtServer.sign(token);

        assertThat(jwtString).isNotEmpty();
        assertThat(jwtString).matches("^[A-Za-z0-9]*\\.[A-Za-z0-9]*\\.[A-Za-z0-9]$");
        assertThat(Arrays.toString(Base64.getDecoder().decode(jwtString.split("\\.")[1]))).isEqualTo("{tokenId: mock-token-id}");
    }

    static class TestToken {
        private final String tokenId;

        TestToken(String tokenId) {
            this.tokenId = tokenId;
        }

        public String getTokenId() {
            return tokenId;
        }
    }
}
