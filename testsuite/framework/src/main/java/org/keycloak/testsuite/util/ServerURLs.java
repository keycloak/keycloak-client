package org.keycloak.testsuite.util;

import java.net.MalformedURLException;
import java.net.URL;

import org.keycloak.client.testsuite.framework.TestRegistry;
import org.keycloak.client.testsuite.server.KeycloakServerProvider;

import static java.lang.Integer.parseInt;

/**
 * Fork of ServerURLs class from Keycloak
 */
public class ServerURLs {

    public static final String AUTH_SERVER_URL = TestRegistry.INSTANCE.getOrCreateProvider(KeycloakServerProvider.class).getAuthServerUrl();
    public static final String AUTH_SERVER_HOST = getAuthServerHost();
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

    private static String getAuthServerHost() {
        try {
            return new URL(AUTH_SERVER_URL).getHost();
        } catch (MalformedURLException mue) {
            throw new RuntimeException(mue);
        }
    }

    public static String getAuthServerContextRoot() {
        return getAuthServerContextRoot(0);
    }

    public static String getAuthServerContextRoot(int clusterPortOffset) {
        return removeDefaultPorts(String.format("%s://%s:%s", AUTH_SERVER_SCHEME, AUTH_SERVER_HOST, parseInt(AUTH_SERVER_PORT) + clusterPortOffset));
    }

    public static String removeDefaultPorts(String url) {
        return url != null ? url.replaceFirst("(.*)(:80)(\\/.*)?$", "$1$3").replaceFirst("(.*)(:443)(\\/.*)?$", "$1$3") : null;
    }
}
