package com.mouse.jwt.verifiable.gateways.acl;

import com.mouse.jwt.verifiable.domain.Header;

public class DefaultHeader implements Header {
    public static final DefaultHeader RS512 = new DefaultHeader("JWT", "RS512");
    private String typ;
    private String alg;

    public DefaultHeader() {
    }

    public DefaultHeader(String typ, String alg) {
        this.typ = typ;
        this.alg = alg;
    }

    @Override
    public String getTyp() {
        return typ;
    }

    @Override
    public String getAlg() {
        return alg;
    }
}
