package org.keycloak.client.testsuite.common;

import org.keycloak.admin.client.Keycloak;
import org.keycloak.client.testsuite.framework.LifeCycle;
import org.keycloak.client.testsuite.framework.TestProviderFactory;
import org.keycloak.client.testsuite.framework.TestRegistry;
import org.keycloak.client.testsuite.server.KeycloakServerProvider;

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class AdminClientFactory implements TestProviderFactory<Keycloak> {

    @Override
    public LifeCycle getLifeCycle() {
        return LifeCycle.CLASS;
    }

    @Override
    public Class<Keycloak> getProviderClass() {
        return Keycloak.class;
    }

    @Override
    public Keycloak createProvider(TestRegistry registry) {
        KeycloakServerProvider kcServer = registry.getOrCreateProvider(KeycloakServerProvider.class);
        return kcServer.createAdminClient();
    }

    @Override
    public void closeProvider(Keycloak adminClient) {
        adminClient.close();
    }
}
