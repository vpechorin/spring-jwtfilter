package net.pechorina.config.web;

import net.pechorina.config.JWTConfigurer;
import net.pechorina.config.TokenProvider;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.web.server.LocalServerPort;
import org.springframework.test.context.ActiveProfiles;

import java.util.Arrays;

import static io.restassured.RestAssured.given;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ActiveProfiles({"test"})
public class ControllerTest {

    private final Logger log = LoggerFactory.getLogger(ControllerTest.class);

    @LocalServerPort
    private Integer port;

    @Value("${server.address:localhost}")
    private String host;

    @Autowired
    private TokenProvider tokenProvider;

    @Test
    @DisplayName("When auth not supplied status 401 should be returned for the secured endpoint")
    public void noAuthProvidedTest() {
        given()
                .baseUri("http://" + host)
                .port(port)
                .when()
                .get("/api/test1").then().statusCode(401);
    }

    @Test
    @DisplayName("Status 200 should be returned for the public endpoint")
    public void checkPublicEndpointTest() {
        given()
                .baseUri("http://" + host)
                .port(port)
                .when()
                .get("/public1").then().statusCode(200);
    }

    @Test
    @DisplayName("When auth was supplied status 200 should be returned for the secured endpoint")
    public void withAuthProvidedTest() {
        String token = tokenProvider.createToken("user@localhost.localdomain", Arrays.asList("OP_TESTROLE1"), 600);

        given()
                .baseUri("http://" + host)
                .port(port)
                .header(JWTConfigurer.AUTHORIZATION_HEADER, "Bearer " + token)
                .when()
                .get("/api/test1")
                .then().statusCode(200);
    }
}
