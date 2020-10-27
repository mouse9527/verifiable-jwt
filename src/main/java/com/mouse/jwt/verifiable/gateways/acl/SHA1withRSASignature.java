package com.mouse.jwt.verifiable.gateways.acl;

import com.mouse.jwt.verifiable.domain.Header;
import com.mouse.jwt.verifiable.domain.Payload;
import com.mouse.jwt.verifiable.domain.Token;

import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Base64;

public class SHA1withRSASignature implements com.mouse.jwt.verifiable.domain.Signature {
    private final Signature signature;
    private final KeyPair keyPair;

    public SHA1withRSASignature(KeyPair keyPair) throws NoSuchAlgorithmException {
        this.keyPair = keyPair;
        this.signature = Signature.getInstance("SHA1withRSA");
    }

    @Override
    public void sign(Token<Header, Payload> token) throws SignatureException, InvalidKeyException {
        signature.initSign(keyPair.getPrivate());
        signature.update(token.getSignContent().getBytes(StandardCharsets.UTF_8));
        byte[] signed = signature.sign();
        token.sign(signed);
    }

    @Override
    public boolean verify(String jwtToken) throws InvalidKeyException, SignatureException {
        String[] split = jwtToken.split("\\.");
        this.signature.initVerify(keyPair.getPublic());
        this.signature.update(String.format("%s.%s", split[0], split[1]).getBytes(StandardCharsets.UTF_8));
        return this.signature.verify(Base64.getDecoder().decode(split[2]));
    }
}
