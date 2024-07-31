package org.keycloak.client.testsuite;

import org.keycloak.admin.client.Keycloak;

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public interface TestsuiteContext {

    void startKeycloakServer();

    void stopKeycloakServer();

    String getAuthServerUrl();

    /**
     * Can be called multiple times during the test, so ideally should re-use same instance and return it instead of always creating new admin client instance
     *
     * @return admin-client
     */
    Keycloak getKeycloakAdminClient();

}
