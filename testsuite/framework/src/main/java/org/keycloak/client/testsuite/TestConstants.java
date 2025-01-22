package org.keycloak.client.testsuite;

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class TestConstants {

    public static final String PROPERTY_KEYCLOAK_LIFECYCLE = "keycloak.lifecycle";
    public static final String KEYCLOAK_LIFECYCLE_REMOTE = "remote";
    public static final String PROPERTY_KEYCLOAK_VERSION = "keycloak.version.docker.image";
    public static final String KEYCLOAK_VERSION_DEFAULT = "nightly";
    public static final String PROPERTY_KEYCLOAK_REMOTE_URL = "keycloak.remote.url";
    public static final String PROPERTY_KEYCLOAK_REMOTE_TRUSTSTORE = "keycloak.remote.trustStore";
    public static final String PROPERTY_KEYCLOAK_REMOTE_TRUSTSTORE_PASSWORD = "keycloak.remote.trustStorePassword";

    public static final boolean IS_LIFECYCLE_REMOTE = KEYCLOAK_LIFECYCLE_REMOTE.equalsIgnoreCase(System.getProperty(PROPERTY_KEYCLOAK_LIFECYCLE));

    public static final String MASTER_REALM = "master";
    public static final String ADMIN_CLI_CLIENT = "admin-cli";
}
