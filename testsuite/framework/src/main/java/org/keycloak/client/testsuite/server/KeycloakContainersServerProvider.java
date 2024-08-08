package org.keycloak.client.testsuite.server;

import dasniko.testcontainers.keycloak.KeycloakContainer;
import org.jboss.logging.Logger;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.client.testsuite.TestConstants;
import org.testcontainers.containers.wait.strategy.LogMessageWaitStrategy;

/**
 * Providing Keycloak server based on testcontainers
 *
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class KeycloakContainersServerProvider implements KeycloakServerProvider {

    private static final String KEYCLOAK_IMAGE = "quay.io/keycloak/keycloak";

    private volatile KeycloakContainer keycloakContainer;

    private static final Logger logger = Logger.getLogger(KeycloakContainersServerProvider.class);

    @Override
    public void startKeycloakServer() {
        if (keycloakContainer == null) {
            synchronized (this) {
                if (keycloakContainer == null) {
                    String keycloakVersion = System.getProperty(TestConstants.PROPERTY_KEYCLOAK_VERSION, TestConstants.KEYCLOAK_VERSION_DEFAULT);
                    String dockerImage = KEYCLOAK_IMAGE + ":" + keycloakVersion;
                    logger.infof("Starting Keycloak server based on testcontainers. Docker image: %s", dockerImage);

                    keycloakContainer = new KeycloakContainer(dockerImage).useTls();

                    if (keycloakVersion.startsWith("24.0")) {
                        // Health probe like https://localhost:37267/health/started reset connections by default on Keycloak 24. So fallback to use the log message
                        keycloakContainer.waitingFor(new LogMessageWaitStrategy()
                                .withRegEx(".*Profile dev activated.*\\s"));
                    }

                    keycloakContainer.start();
                    logger.infof("Started Keycloak server on URL %s", keycloakContainer.getAuthServerUrl());
                }
            }
        }
    }

    @Override
    public void stopKeycloakServer() {
        if (keycloakContainer != null) {
            logger.info("Going to stop Keycloak server");
            keycloakContainer.stop();
            logger.info("Stopped Keycloak server");
        }
    }

    @Override
    public String getAuthServerUrl() {
        if (keycloakContainer == null) {
            throw new IllegalStateException("Incorrect usage. Calling getAuthServerUrl before Keycloak server started.");
        }
        return keycloakContainer.getAuthServerUrl();
    }

    @Override
    public Keycloak createAdminClient() {
        return keycloakContainer.getKeycloakAdminClient();
    }
}
