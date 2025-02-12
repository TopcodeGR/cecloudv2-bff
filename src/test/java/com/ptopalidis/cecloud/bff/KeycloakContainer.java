package com.ptopalidis.cecloud.bff;


import net.bytebuddy.utility.dispatcher.JavaDispatcher;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.utility.DockerImageName;
import org.testcontainers.utility.MountableFile;


public class KeycloakContainer extends GenericContainer<KeycloakContainer> {

    private static final int KEYCLOAK_HTTP_PORT = 8080;

    public KeycloakContainer() {
        super("quay.io/keycloak/keycloak:25.0.1");

        // Expose the Keycloak port
        this.addExposedPort(KEYCLOAK_HTTP_PORT);

        // Copy your realm JSON into the container
        this.withCopyFileToContainer(
                MountableFile.forClasspathResource("realm.json"), // from src/test/resources
                "/opt/keycloak/data/import/realm.json"
        );

        // For Keycloak 17+ "quay.io/keycloak/keycloak:latest":
        // Run Keycloak in development mode with an admin user
        this.withCommand("start-dev --http-relative-path=/ --import-realm");
        this.addEnv("KEYCLOAK_ADMIN", "admin");
        this.addEnv("KEYCLOAK_ADMIN_PASSWORD", "admin");
    }

    public Integer getHttpPort() {
        return this.getMappedPort(KEYCLOAK_HTTP_PORT);
    }

    public String getAuthServerUrl() {
        return "http://" + getHost() + ":" + getHttpPort() + "/realms/cecloudv2";
    }
}