package com.mouse.jwt.verifiable.gateways.acl;

import com.mouse.jwt.verifiable.domain.Header;

public class RSAHeader implements Header {
    public static final RSAHeader DEFAULT = new RSAHeader();

    @Override
    public String getTyp() {
        return "JWT";
    }

    @Override
    public String getAlg() {
        return "RS512";
    }
}
