package org.keycloak.client.testsuite.server;

import java.security.NoSuchAlgorithmException;
import javax.net.ssl.SSLContext;
import org.jboss.logging.Logger;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.client.testsuite.TestConstants;
import org.keycloak.testsuite.util.AdminClientUtil;

/**
 * This class can be used when Keycloak server is already started on current laptop and hence start/stop of the Keycloak
 * server won't be provided by this test itself. It is the responsibility of the admin to start/stop the server and deploy corresponding providers to it.
 *
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class RemoteKeycloakServerProvider implements KeycloakServerProvider {

    private static final Logger logger = Logger.getLogger(RemoteKeycloakServerProvider.class);
    private static final String AUTH_SERVER_URL = System.getProperty(TestConstants.PROPERTY_KEYCLOAK_REMOTE_URL, "http://localhost:8080");

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
        return AUTH_SERVER_URL;
    }

    @Override
    public Keycloak createAdminClient() {
        return Keycloak.getInstance(getAuthServerUrl(), TestConstants.MASTER_REALM, "admin", "admin",
                TestConstants.ADMIN_CLI_CLIENT, createSSLContext());
    }

    @Override
    public SSLContext createSSLContext() {
        try {
            String trustStore = System.getProperty(TestConstants.PROPERTY_KEYCLOAK_REMOTE_TRUSTSTORE);
            String trustStorePassword = System.getProperty(TestConstants.PROPERTY_KEYCLOAK_REMOTE_TRUSTSTORE_PASSWORD, "changeit");
            return trustStore != null
                    ? AdminClientUtil.buildSslContext(trustStore, trustStorePassword)
                    : SSLContext.getDefault();
        } catch (NoSuchAlgorithmException e) {
            return null;
        }
    }
}
