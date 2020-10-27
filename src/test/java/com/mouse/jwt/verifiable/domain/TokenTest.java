package com.mouse.jwt.verifiable.domain;

import com.mouse.jwt.verifiable.gateways.acl.DefaultHeader;
import com.mouse.jwt.verifiable.gateways.acl.DefaultPayload;
import org.junit.jupiter.api.Test;

import java.io.IOException;

import static org.assertj.core.api.Assertions.assertThat;

class TokenTest {

    private static final String JWT_TOKEN = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzUxMiJ9.eyJpYXQiOiIyMDIwLTEwLTI3VDAxOjMzOjUzLjQ1NVoiLCJleHAiOiIyMDIwLTEwLTI3VDAxOjMzOjUzLjQ2NFoiLCJpZCI6Im1vY2stdG9rZW4taWQiLCJ0eXBlIjoidXNlciJ9.XtZRL2009YIgr0UXOHMJDGN9F3NjQetk0/aKRW93FfAJPL4Xrv54L2tx+C2GOg7de7eu88vUFn3D+XlSQs2Cqp86ISlB40UQ2MnzqdLwFQrcOBexpj7zeethANy9YGSa3o5oYR3rwdKc0f9nJ+lCs7U1/sirGp7HE/SuDJdl4n1c9neYPEnUXouBQCVTfD+CP4yHlbmpkDRZHfwdYwnQSK7DF/bU/1138fBp6msBiJwgjdXrMN3Gp6NAPsEJAaKy/oT8xZgGv7/E8wBk80ykZibcCXAIn4nteeSFFzHDn0MROAkd8l05qZbs8/gSHJbZrBbCVBLZQChPIEgyhe0uSQ==";

    @Test
    void shouldBeAbleToCreateWithJWTToken() throws IOException {
        Token token = new Token(JWT_TOKEN);

        assertThat(token.getPayload(DefaultPayload.class).getId()).isEqualTo("mock-token-id");
        assertThat(token.getPayload(DefaultPayload.class).getType()).isEqualTo("user");
        assertThat(token.getPayload(DefaultPayload.class).getIat()).isNotNull();
        assertThat(token.getPayload(DefaultPayload.class).getExp()).isNotNull();
        assertThat(token.getHeader(DefaultHeader.class).getTyp()).isEqualTo("JWT");
        assertThat(token.getHeader(DefaultHeader.class).getAlg()).isEqualTo("RS512");
        assertThat(token.getSignature()).isEqualTo("XtZRL2009YIgr0UXOHMJDGN9F3NjQetk0/aKRW93FfAJPL4Xrv54L2tx+C2GOg7de7eu88vUFn3D+XlSQs2Cqp86ISlB40UQ2MnzqdLwFQrcOBexpj7zeethANy9YGSa3o5oYR3rwdKc0f9nJ+lCs7U1/sirGp7HE/SuDJdl4n1c9neYPEnUXouBQCVTfD+CP4yHlbmpkDRZHfwdYwnQSK7DF/bU/1138fBp6msBiJwgjdXrMN3Gp6NAPsEJAaKy/oT8xZgGv7/E8wBk80ykZibcCXAIn4nteeSFFzHDn0MROAkd8l05qZbs8/gSHJbZrBbCVBLZQChPIEgyhe0uSQ==");
    }
}