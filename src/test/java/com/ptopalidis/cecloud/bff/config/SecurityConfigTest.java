package com.ptopalidis.cecloud.bff.config;


import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.tomakehurst.wiremock.WireMockServer;
import com.ptopalidis.cecloud.bff.KeycloakContainer;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.reactive.AutoConfigureWebTestClient;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.reactive.server.EntityExchangeResult;
import org.springframework.test.web.reactive.server.FluxExchangeResult;
import org.springframework.test.web.reactive.server.WebTestClient;

import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.nio.charset.StandardCharsets;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static com.github.tomakehurst.wiremock.client.WireMock.get;


@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureWebTestClient
@Testcontainers
public class SecurityConfigTest {

    @LocalServerPort
    private int port;

    @Autowired
    private WebTestClient webTestClient;



    @Container
    private static final KeycloakContainer keycloakContainer = new KeycloakContainer();

    private static WireMockServer wireMockServer;

    @BeforeAll
     static void beforeAll() {
        wireMockServer = new WireMockServer(0); // 0 => random port
        wireMockServer.start();

        wireMockServer.stubFor(get(urlEqualTo("/api/secured"))
                .willReturn(aResponse().withStatus(200).withBody("Mocked data!")));
    }
    @AfterAll
    static void afterAll() {
        wireMockServer.stop();
    }
    /**
     * 3) Dynamically set your Keycloak Issuer URI to the container’s real host/port at runtime.
     *    Adjust the property name to match your `application.yml` or how you configure Keycloak in your app.
     */
    @DynamicPropertySource
    static void overrideKeycloakIssuer(DynamicPropertyRegistry registry){

        registry.add("spring.security.oauth2.client.registration.keycloak.provider", ()-> "keycloak");
        registry.add("spring.security.oauth2.client.registration.keycloak.authorization-grant-type", ()-> "authorization_code");
        registry.add("spring.security.oauth2.client.registration.keycloak.client-id", ()-> "ceclouv2-bff");
        registry.add("spring.security.oauth2.client.registration.keycloak.client-secret", ()-> "SbzOidx8kTh1rRpbWVJhhBBkNbzfSkS7");

        registry.add("spring.security.oauth2.client.registration.keycloak.scope", ()-> "openid");
               //   spring.security.oauth2.client.provider.keycloak.issuer-uri
        //   should match your realm’s URL: http://<host>:<randomPort>/realms/<realmName>
        registry.add("spring.security.oauth2.client.provider.keycloak.issuer-uri", () ->
                "http://" + keycloakContainer.getHost() + ":" + keycloakContainer.getHttpPort() + "/realms/cecloudv2"
        );
    }


    @Test
    void whenNoToken_thenRedirectToKeycloak() throws JsonProcessingException {
        // 1. Obtain a token from the running Keycloak container
        String accessToken = "asdasd"; //getAccessToken("test", "test");

        // 2. Call the secured endpoint with the Bearer token
        FluxExchangeResult<byte[]> redirectResult = webTestClient
                .get()
                .uri("http://localhost:" + wireMockServer.port() +"/api/secured")
                .header("Authorization", "Bearer " + accessToken)
                .exchange()
                .expectStatus().is3xxRedirection()
                .returnResult(byte[].class);

        String redirectLocation = redirectResult.getResponseHeaders()
                .getLocation().toString(); // e.g. Keycloak login page with query params

// Now call that URL
        FluxExchangeResult<byte[]> loginPageResult = webTestClient
                .get()
                .uri(redirectLocation)
                .exchange()
                .expectStatus().is3xxRedirection()
                .returnResult(byte[].class);

        String loginHtml = new String(loginPageResult.getResponseBodyContent(), StandardCharsets.UTF_8);

        FluxExchangeResult<byte[]> res1 = WebTestClient.bindToServer()
                .baseUrl("http://" + keycloakContainer.getHost() + ":" + keycloakContainer.getHttpPort())
                .build()
                .get()
                .uri(loginPageResult.getResponseHeaders().getLocation().toString()) // gleaned from HTML form
                .exchange()
                .returnResult(byte[].class);
    }

    @Test
    void whenValidToken_thenReturn200Ok() throws JsonProcessingException {
        // 1. Obtain a token from the running Keycloak container
        String accessToken = getAccessToken("test", "test");

        // 2. Call the secured endpoint with the Bearer token
        FluxExchangeResult<byte[]> redirectResult = webTestClient
                .get()
                .uri("http://localhost:" + wireMockServer.port() +"/api/secured")
                .header("Authorization", "Bearer " + accessToken)
                .exchange()
                .expectStatus().is3xxRedirection()
                .returnResult(byte[].class);

        String redirectLocation = redirectResult.getResponseHeaders()
                .getLocation().toString(); // e.g. Keycloak login page with query params

// Now call that URL
        FluxExchangeResult<byte[]> loginPageResult = webTestClient
                .get()
                .uri(redirectLocation)
                .header("Authorization", "Bearer " + accessToken)
                .exchange()
                .expectStatus().is3xxRedirection()
                .returnResult(byte[].class);

        String loginHtml = new String(loginPageResult.getResponseBodyContent(), StandardCharsets.UTF_8);

        FluxExchangeResult<byte[]> res1 = WebTestClient.bindToServer()
                .baseUrl("http://" + keycloakContainer.getHost() + ":" + keycloakContainer.getHttpPort())
                .build()
                .get()
                .uri(loginPageResult.getResponseHeaders().getLocation().toString()) // gleaned from HTML form
                .exchange()
                .returnResult(byte[].class);
// parse hidden fields, csrf tokens, etc. Then:
    }

    /**
     * Example: Get a token from Keycloak container with Resource Owner Password Flow.
     * In real usage, you might prefer code grant or client credentials.
     */
    private String getAccessToken(String username, String password) throws JsonProcessingException {
        // We assume Keycloak realm 'cecloudv2' has user 'testuser' with password 'testpassword'
        ObjectMapper objectMapper = new ObjectMapper();

        byte[] responseBodyAsBytes = WebTestClient.bindToServer()
                .baseUrl("http://" + keycloakContainer.getHost() + ":" + keycloakContainer.getHttpPort())
                .build()
                .post()
                .uri("/realms/cecloudv2/protocol/openid-connect/token")
                .bodyValue(
                        "grant_type=password&client_id=ceclouv2-bff"
                                + "&client_secret=SbzOidx8kTh1rRpbWVJhhBBkNbzfSkS7"
                                + "&username=" + username
                                + "&password=" + password
                )
                .header("Content-Type", "application/x-www-form-urlencoded")
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .returnResult()
                .getResponseBodyContent();  // Returns the raw bytes of the response

// Convert bytes to String
        String responseBodyAsString = new String(responseBodyAsBytes, StandardCharsets.UTF_8);

// Parse JSON and extract the token
        JsonNode node = objectMapper.readTree(responseBodyAsString);
        String accessToken = node.get("access_token").asText();

        return accessToken;
    }
}
