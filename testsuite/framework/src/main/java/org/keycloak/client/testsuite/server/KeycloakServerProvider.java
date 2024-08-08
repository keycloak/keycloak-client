package org.keycloak.client.testsuite.server;

import org.keycloak.admin.client.Keycloak;

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public interface KeycloakServerProvider {

    void startKeycloakServer();

    void stopKeycloakServer();

    String getAuthServerUrl();

    /**
     * @return admin-client
     */
    Keycloak createAdminClient();

}
