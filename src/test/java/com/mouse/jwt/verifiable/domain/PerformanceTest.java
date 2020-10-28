package com.mouse.jwt.verifiable.domain;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.mouse.jwt.verifiable.gateways.acl.AsymmetricSignature;
import com.mouse.jwt.verifiable.gateways.acl.DefaultPayload;
import com.mouse.jwt.verifiable.gateways.acl.DefaultSerializer;
import com.mouse.jwt.verifiable.gateways.acl.SymmetricSignature;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

@SuppressWarnings("deprecation")
public class PerformanceTest {
    private static final Instant IAT = Instant.parse("2020-10-27T00:00:00Z");
    private static final Instant EXP = Instant.parse("2020-10-28T00:00:00Z");
    private KeyPair keyPair;

    @BeforeAll
    static void beforeAll() {
        Serializer.resetSerializer(new DefaultSerializer());
    }

    @BeforeEach
    void setUp() throws NoSuchAlgorithmException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(1024);
        keyPair = generator.genKeyPair();
    }

    @Test
    void symmetricPerformanceTest() throws InterruptedException, NoSuchAlgorithmException, InvalidKeyException {
        JWTServer jwtServer = new JWTServer(new SymmetricSignature(keyPair, "SHA1withRSA"));
        List<Token> tokens = Collections.synchronizedList(new ArrayList<>());
        Thread thread = new Thread(() -> {
            int num = 0;
            while (true) {
                num++;
                Token token = jwtServer.sign(new DefaultPayload(String.valueOf(num), String.valueOf(num), IAT, EXP));
                tokens.add(token);
            }
        });
        thread.start();
        Thread.sleep(10000);
        thread.stop();

        List<Token> verified = Collections.synchronizedList(new ArrayList<>());
        Thread verify = new Thread(() -> {
            for (Token token : tokens) {
                jwtServer.verify(token);
                verified.add(token);
            }
        });
        verify.start();
        Thread.sleep(200);
        verify.stop();

        System.out.printf("Sign: %s per/sec%nVerify: %s per/sec%n", tokens.size() / 10, verified.size() * 5);
    }

    @Test
    void asymmetricPerformanceTest() throws InterruptedException, NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException {
        KeyGenerator generator = KeyGenerator.getInstance("AES");
        generator.init(256);
        Key key = generator.generateKey();
        JWTServer jwtServer = new JWTServer(new AsymmetricSignature(key, "AES"));
        List<Token> tokens = Collections.synchronizedList(new ArrayList<>());
        Thread thread = new Thread(() -> {
            int num = 0;
            while (true) {
                num++;
                Token token = jwtServer.sign(new DefaultPayload(String.valueOf(num), String.valueOf(num), IAT, EXP));
                tokens.add(token);
            }
        });
        thread.start();
        Thread.sleep(10000);
        thread.stop();

        List<Token> verified = Collections.synchronizedList(new ArrayList<>());
        Thread verify = new Thread(() -> {
            for (Token token : tokens) {
                jwtServer.verify(token);
                verified.add(token);
            }
        });
        verify.start();
        Thread.sleep(200);
        verify.stop();

        System.out.printf("Sign: %s per/sec%nVerify: %s per/sec%n", tokens.size() / 10, verified.size() * 5);
    }

    @Test
    void auth0JWTPerformanceTest() throws InterruptedException {
        Algorithm algorithm = Algorithm.RSA512((RSAPublicKey) keyPair.getPublic(), (RSAPrivateKey) keyPair.getPrivate());
        List<String> tokens = Collections.synchronizedList(new ArrayList<>());
        Thread thread = new Thread(() -> {
            int num = 0;
            while (true) {
                num++;
                String token = JWT.create()
                        .withClaim("id", String.valueOf(num))
                        .withClaim("type", String.valueOf(num))
                        .sign(algorithm);
                tokens.add(token);
            }
        });
        thread.start();
        Thread.sleep(10000);
        thread.stop();

        JWTVerifier verifier = JWT.require(algorithm).build();

        List<String> verified = Collections.synchronizedList(new ArrayList<>());
        Thread verify = new Thread(() -> {
            for (String token : tokens) {
                verifier.verify(token);
                verified.add(token);
            }
        });
        verify.start();
        Thread.sleep(200);
        verify.stop();

        System.out.printf("Sign: %s per/sec%nVerify: %s per/sec%n", tokens.size() / 10, verified.size() * 5);
    }
}
