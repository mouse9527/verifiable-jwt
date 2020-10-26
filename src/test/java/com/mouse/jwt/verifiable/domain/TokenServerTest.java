package com.mouse.jwt.verifiable.domain;

import com.jayway.jsonpath.JsonPath;
import com.mouse.jwt.verifiable.gateways.acl.RS256Signature;
import com.mouse.jwt.verifiable.gateways.acl.VerifiableJWTServer;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.time.Instant;
import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;

public class TokenServerTest {
    private JWTServer<TestPayload> jwtServer;

    @BeforeEach
    void setUp() throws NoSuchAlgorithmException, InvalidKeySpecException {
        KeyPariProperties keyPari = new MockKeyPairProperties();
        Signature signature = new RS256Signature(keyPari);
        jwtServer = new VerifiableJWTServer<>(signature);
    }

    @Test
    void shouldBeAbleToSignToJWT() throws SignatureException, InvalidKeyException {
        TestPayload raw = new TestPayload();

        Token<Header, Payload> token = jwtServer.sign(raw);

        String jwtString = token.toString();
        assertThat(jwtString).isNotEmpty();
        assertThat(jwtString.split("\\.")).hasSize(3);
        String payload = new String(Base64.getDecoder().decode(jwtString.split("\\.")[1]));
        assertThat(JsonPath.compile("$.id").<String>read(payload)).isEqualTo("mock-token-id");
        assertThat(JsonPath.compile("$.type").<String>read(payload)).isEqualTo("user");
        assertThat(JsonPath.compile("$.iat").<String>read(payload)).isNotEmpty();
        assertThat(JsonPath.compile("$.exp").<String>read(payload)).isNotEmpty();
    }

    @Test
    void shouldBeAbleToVerifiableJWT() throws SignatureException, InvalidKeyException {
        TestPayload payload = new TestPayload();
        Token<Header, Payload> token = jwtServer.sign(payload);

        String jwtToken = token.toString();
        assertThat(jwtServer.verify(jwtToken)).isTrue();
        assertThat(jwtServer.verify(jwtToken.replace("A", "B"))).isFalse();
    }

    private static class TestPayload implements Payload {
        @Override
        public String getId() {
            return "mock-token-id";
        }

        @Override
        public String getType() {
            return "user";
        }

        @Override
        public String getIat() {
            return Instant.now().toString();
        }

        @Override
        public String getExp() {
            return Instant.now().toString();
        }
    }

    private static class MockKeyPairProperties implements KeyPariProperties {
        @Override
        public String getPrivateKey() {
            return "MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCVtEcFtqLwgdR8cfBv++o/TUprh85UlPqSQJePkw8kmIRVBu4rIe1saR6iwJAkbw1FXIskc7+0SjgdhuD1BGtoF3Bz/VtNK8MOSB/C0+ycJQlX4eciHl5k/OPRkfLUA/jwSVO6I01HLKuxBkyqqoSgVqiKXkFf+K6iO1DKLfSccJwq+zpgVmRrgmL2+gIrakPG28wQ5+cyYyah2cAM2l3iWn3cZlOJLFLxoR198JLDGrd7ApxKS5ARaYUVM7eBAFdr4Y1NBaAlePUc0wVtYC6iMfMhxw22EdKJ6aDE+xS7LHqpqs9E7CGNofQ8JWrf/Rex6QAwjoUwsLGxYucFLkWtAgMBAAECggEAIwnV0a2Eh3wrqpDUcLFqizRg5bgcf8l6uD5r+su1sKAN4QTFO80uD8CuzfL6Cb0AQyq82mRJCz6P0cFe55oINY2+4Tb8ZpyGg9I3tNb7OzSj8jDKcz7eYw6Zl9RsHFltq3fOI/PdQ3peGQnbadqNPiXqPrB+5qKC5S+y4g9NgEuzOTkjO+xkKpOmZgyT9VOneDDF6qsSqN/TnktqKkn27ph89VWvGWmIN8KRasZt0kpLxHuZqfa2n6elJUPdVJhAEw0sn9qdXvM/IkjPLmy3hSmsRduyrTelKGChkLdVvpPBLeBK42WhtJ73vwpssCLHlfv5r8T5q/vxWNWg9ij1NQKBgQDRULUpASjtVwNxiNa6oe4K+lv4qVgu7CvOnxxfQQ3+JWOg2SL27EOfzoa1ngcGfhGV6aMmo7OSDRVgUarH4O25dOcQzsvRz/kujYl01QKRXdVkc96WS1Z7++7RDxn1VL2JYyNgRwaLLBhz2ej6bgImot3eo4E0/ZcdHHMupIRqYwKBgQC3F/O23Rsje6PTxy01pcOBjQZw/vf09Uff9hJnQoZw/FgNu3iPg6WymSJ/SMZfi+n4jH5Q5B8eASc4BmSPSTG7VU2jgzqJXRUg39TuUcVXI8wRt18aZCJSmUx5Viq3MUTfUuNYsycTQ6KQHyzFuBoFqFO4GCocqcTCSAPVnwAErwKBgFgf6qXA30JNiB2cxwr8cgQdM+uVIJNgy3DKfF9+PC3r/+4QfTAIeNAnW3/LcJnDKhQ7sXzrHwc2ivFqcMSGZo/WMBJbfmRvczGuVVji9ZnOL7GDNwt/3IGGqB1MhllLvCDDpHk8bfzaK9FaxUPqXO13VIIPxK5StfSDrdrNWRKRAoGASi3yF8xNCns1TMANmQanxv0T9wPWAfC+Rga0PhG91ljmc+nYVozHvSw9xcP+Wwecq46APtWtpcJh2Vj9tO+6rmNJKU4pkS2dOcx1wHhws3VVYHgil9ap8T0atq4qcD4N4Uz7vxwWYL+uRSXcRd7o7BHemV9w8Fv3057JrurUXxECgYBC07v99knGsNkfYfivGcpwMqDMaBzGFxbFM9S3VjBRcCglbFvKXiyPC98sLqO1npDHgHOg/YsNJ23pddzJitGsQHrd9hcQHXbAaqCa+J4NNZkPY8liO9lOL1LUzDCUis6aWSah+srKkZxziQZ2hMHXRppXjBUUKBnKHgQFuci2ng==";
        }

        @Override
        public String getPublicKey() {
            return "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAlbRHBbai8IHUfHHwb/vqP01Ka4fOVJT6kkCXj5MPJJiEVQbuKyHtbGkeosCQJG8NRVyLJHO/tEo4HYbg9QRraBdwc/1bTSvDDkgfwtPsnCUJV+HnIh5eZPzj0ZHy1AP48ElTuiNNRyyrsQZMqqqEoFaoil5BX/iuojtQyi30nHCcKvs6YFZka4Ji9voCK2pDxtvMEOfnMmMmodnADNpd4lp93GZTiSxS8aEdffCSwxq3ewKcSkuQEWmFFTO3gQBXa+GNTQWgJXj1HNMFbWAuojHzIccNthHSiemgxPsUuyx6qarPROwhjaH0PCVq3/0XsekAMI6FMLCxsWLnBS5FrQIDAQAB";
        }
    }
}
