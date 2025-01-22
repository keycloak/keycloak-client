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
        KeycloakServerProvider kcServer = TestConstants.IS_LIFECYCLE_REMOTE ? new RemoteKeycloakServerProvider() : new KeycloakContainersServerProvider();
        kcServer.startKeycloakServer();
        return kcServer;
    }

    @Override
    public void closeProvider(KeycloakServerProvider keycloakServerProvider) {
        keycloakServerProvider.stopKeycloakServer();
    }
}
