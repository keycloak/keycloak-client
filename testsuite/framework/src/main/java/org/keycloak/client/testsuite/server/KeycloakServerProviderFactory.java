package org.keycloak.client.testsuite.server;

import org.keycloak.client.testsuite.TestConstants;
import org.keycloak.client.testsuite.framework.LifeCycle;
import org.keycloak.client.testsuite.framework.TestProviderFactory;
import org.keycloak.client.testsuite.framework.TestRegistry;

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class KeycloakServerProviderFactory implements TestProviderFactory<KeycloakServerProvider> {

    @Override
    public LifeCycle getLifeCycle() {
        return LifeCycle.GLOBAL;
    }

    @Override
    public Class<KeycloakServerProvider> getProviderClass() {
        return KeycloakServerProvider.class;
    }

    @Override
    public KeycloakServerProvider createProvider(TestRegistry registry) {
        String keycloakLifecycle = System.getProperty(TestConstants.PROPERTY_KEYCLOAK_LIFECYCLE);
        KeycloakServerProvider kcServer = "remote".equalsIgnoreCase(keycloakLifecycle) ? new RemoteKeycloakServerProvider() : new KeycloakContainersServerProvider();
        kcServer.startKeycloakServer();
        return kcServer;
    }

    @Override
    public void closeProvider(KeycloakServerProvider keycloakServerProvider) {
        keycloakServerProvider.stopKeycloakServer();
    }
}
