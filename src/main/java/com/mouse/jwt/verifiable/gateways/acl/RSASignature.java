package com.mouse.jwt.verifiable.gateways.acl;

import com.mouse.jwt.verifiable.domain.Header;
import com.mouse.jwt.verifiable.domain.KeyPariProperties;
import com.mouse.jwt.verifiable.domain.Payload;
import com.mouse.jwt.verifiable.domain.Token;

import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class RSASignature implements com.mouse.jwt.verifiable.domain.Signature {
    private final Signature signature = Signature.getInstance("SHA1withRSA");
    private final PrivateKey privateKey;
    private final PublicKey publicKey;

    public RSASignature(KeyPariProperties keyPariProperties) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException {
        KeyFactory factory = KeyFactory.getInstance("RSA");
        KeySpec privateKeySpec = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(keyPariProperties.getPrivateKey()));
        privateKey = factory.generatePrivate(privateKeySpec);
        KeySpec publicKeySpec = new X509EncodedKeySpec(Base64.getDecoder().decode(keyPariProperties.getPublicKey()));
        publicKey = factory.generatePublic(publicKeySpec);
    }

    @Override
    public void sign(Token<Header, Payload> token) throws SignatureException, InvalidKeyException {
        signature.initSign(privateKey);
        signature.update(token.getSignContent().getBytes(StandardCharsets.UTF_8));
        byte[] signed = signature.sign();
        token.sign(signed);
    }

    @Override
    public boolean verify(String rawString, String jwtToken) {
        return false;
    }
}
