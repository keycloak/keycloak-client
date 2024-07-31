package org.keycloak.client.testsuite;

import dasniko.testcontainers.keycloak.KeycloakContainer;
import org.jboss.logging.Logger;
import org.keycloak.admin.client.Keycloak;

/**
 * Providing Keycloak server based on testcontainers
 *
 * For now, starting server before each test-class and stop after each test-class TODO: Improve...
 *
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class KeycloakContainersTestsuiteContext implements TestsuiteContext {

    private static final String KEYCLOAK_IMAGE = "quay.io/keycloak/keycloak";
    private static final String KEYCLOAK_VERSION = "nightly"; // "25.0"; // TODO: Retrive from the configuration to be able to test with more Keycloak versions

    private volatile KeycloakContainer keycloakContainer;
    private Keycloak adminClient;


    private static final Logger logger = Logger.getLogger(KeycloakContainersTestsuiteContext.class);

    @Override
    public void startKeycloakServer() {
        if (keycloakContainer == null) {
            synchronized (this) {
                if (keycloakContainer == null) {
                    String dockerImage = KEYCLOAK_IMAGE + ":" + KEYCLOAK_VERSION;
                    logger.infof("Starting Keycloak server based on testcontainers. Docker image %s", dockerImage);

                    keycloakContainer = new KeycloakContainer(dockerImage).useTls();
                    keycloakContainer.start();
                    logger.infof("Started Keycloak server on URL %s", keycloakContainer.getAuthServerUrl());

                    adminClient = keycloakContainer.getKeycloakAdminClient();
                }
            }
        }
    }

    @Override
    public void stopKeycloakServer() {
        if (keycloakContainer == null) {
            throw new IllegalStateException("Incorrect usage. Calling stopKeycloakServer before Keycloak server started.");
        }
        logger.info("Going to stop Keycloak server");
        adminClient.close();
        keycloakContainer.stop();
        logger.info("Stopped Keycloak server");
    }

    @Override
    public String getAuthServerUrl() {
        if (keycloakContainer == null) {
            throw new IllegalStateException("Incorrect usage. Calling getAuthServerUrl before Keycloak server started.");
        }
        return keycloakContainer.getAuthServerUrl();
    }

    @Override
    public Keycloak getKeycloakAdminClient() {
        if (adminClient == null) {
            throw new IllegalStateException("Incorrect usage. Calling getKeycloakAdminClient before Keycloak server started.");
        }
        return adminClient;
    }
}
