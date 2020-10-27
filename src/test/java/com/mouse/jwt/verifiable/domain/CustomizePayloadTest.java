package com.mouse.jwt.verifiable.domain;

import com.jayway.jsonpath.JsonPath;
import com.mouse.jwt.verifiable.gateways.acl.DefaultSerializer;
import com.mouse.jwt.verifiable.gateways.acl.SymmetricSignature;
import org.junit.jupiter.api.Test;

import java.security.InvalidKeyException;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;

public class CustomizePayloadTest {
    @Test
    void shouldBeAbleToSignCustomizeJWT() throws NoSuchAlgorithmException, InvalidKeyException {
        Serializer.resetSerializer(new DefaultSerializer());

        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(1024);
        JWTServer jwtServer = new JWTServer(new SymmetricSignature(generator.genKeyPair(), "SHA1withRSA"));

        CustomizePayload payload = new CustomizePayload();
        payload.admin = true;
        payload.exp = Instant.now();
        payload.iat = Instant.now();
        payload.id = "mock-id";
        payload.type = "user";
        Token token = jwtServer.sign(payload);

        String jwt = token.toString();
        System.out.println(jwt);
        assertThat(jwt).isNotEmpty();
        assertThat(jwt.split("\\.")).hasSize(3);
        String payloadJson = new String(Base64.getDecoder().decode(jwt.split("\\.")[1]));
        assertThat(JsonPath.compile("$.admin").<Boolean>read(payloadJson)).isTrue();
        assertThat(new Token(jwt).getPayload(CustomizePayload.class)).isNotNull();
        assertThat(new Token(jwt).getPayload(CustomizePayload.class)).isInstanceOf(CustomizePayload.class);
        assertThat(((CustomizePayload) new Token(jwt).getPayload(CustomizePayload.class)).getAdmin()).isTrue();
    }

    private static class CustomizePayload implements Payload {
        private Instant exp;
        private String id;
        private String type;
        private Instant iat;
        private Boolean admin;

        @Override
        public String getId() {
            return id;
        }

        @Override
        public String getType() {
            return type;
        }

        @Override
        public Instant getIat() {
            return iat;
        }

        @Override
        public Instant getExp() {
            return exp;
        }

        public Boolean getAdmin() {
            return admin;
        }
    }
}
