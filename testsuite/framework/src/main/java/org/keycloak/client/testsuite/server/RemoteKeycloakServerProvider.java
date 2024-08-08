package org.keycloak.client.testsuite.server;

import org.jboss.logging.Logger;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.client.testsuite.TestConstants;

/**
 * This class can be used when Keycloak server is already started on current laptop and hence start/stop of the Keycloak
 * server won't be provided by this test itself. It is the responsibility of the admin to start/stop the server and deploy corresponding providers to it.
 *
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class RemoteKeycloakServerProvider implements KeycloakServerProvider {

    private static final Logger logger = Logger.getLogger(RemoteKeycloakServerProvider.class);

    @Override
    public void startKeycloakServer() {
        logger.infof("Ignored start of Keycloak server as it is externally managed. Using Keycloak server on %s", getAuthServerUrl());
    }

    @Override
    public void stopKeycloakServer() {
        logger.infof("Ignored stop of Keycloak server as it is externally managed");
    }

    @Override
    public String getAuthServerUrl() {
        // Hardcoded for now...
        return "http://localhost:8080";
    }

    @Override
    public Keycloak createAdminClient() {
//        if (useTls) {
//            return Keycloak.getInstance(keycloakContainer.getAuthServerUrl(), MASTER_REALM, keycloakContainer.getAdminUsername(),
//                    keycloakContainer.getAdminPassword(), ADMIN_CLI_CLIENT, keycloakContainer.buildSslContext());
//        }
        return Keycloak.getInstance(getAuthServerUrl(), TestConstants.MASTER_REALM, "admin", "admin", TestConstants.ADMIN_CLI_CLIENT);
    }
}
