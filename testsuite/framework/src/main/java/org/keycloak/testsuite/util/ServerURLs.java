package org.keycloak.testsuite.util;

import java.net.MalformedURLException;
import java.net.URL;

import org.keycloak.client.testsuite.framework.TestRegistry;
import org.keycloak.client.testsuite.server.KeycloakServerProvider;

/**
 * Fork of ServerURLs class from Keycloak
 */
public class ServerURLs {

    public static final String AUTH_SERVER_URL = TestRegistry.INSTANCE.getOrCreateProvider(KeycloakServerProvider.class).getAuthServerUrl();

    public static final boolean AUTH_SERVER_SSL_REQUIRED = AUTH_SERVER_URL.startsWith("https");
    public static final String AUTH_SERVER_PORT = getAuthServerPort();
    public static final String AUTH_SERVER_SCHEME = AUTH_SERVER_SSL_REQUIRED ? "https" : "http";

    private static String getAuthServerPort() {
        try {
            int port = new URL(AUTH_SERVER_URL).getPort();
            return String.valueOf(port);
        } catch (MalformedURLException mue) {
            throw new RuntimeException(mue);
        }
    }
}
