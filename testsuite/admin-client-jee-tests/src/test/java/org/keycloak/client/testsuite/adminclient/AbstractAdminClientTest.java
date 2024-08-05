package org.keycloak.client.testsuite.adminclient;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.client.testsuite.KeycloakContainersTestsuiteContext;
import org.keycloak.client.testsuite.RemoteTestsuiteContext;
import org.keycloak.client.testsuite.TestConstants;
import org.keycloak.client.testsuite.TestsuiteContext;

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public abstract class AbstractAdminClientTest {

    private static TestsuiteContext testsuiteContext;
    protected static Keycloak adminClient;

    @BeforeAll
    public static void beforeAll() {
        String keycloakLifecycle = System.getProperty(TestConstants.PROPERTY_KEYCLOAK_LIFECYCLE);
        testsuiteContext = "remote".equalsIgnoreCase(keycloakLifecycle) ? new RemoteTestsuiteContext() : new KeycloakContainersTestsuiteContext();

        testsuiteContext.startKeycloakServer();
        adminClient = testsuiteContext.getKeycloakAdminClient();
    }

    @AfterAll
    public static void afterAll() {
        testsuiteContext.stopKeycloakServer();
    }


}
