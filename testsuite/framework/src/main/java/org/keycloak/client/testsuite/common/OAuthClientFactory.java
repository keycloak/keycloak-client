package org.keycloak.client.testsuite.common;

import org.apache.http.impl.client.CloseableHttpClient;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.client.testsuite.framework.LifeCycle;
import org.keycloak.client.testsuite.framework.TestProviderFactory;
import org.keycloak.client.testsuite.framework.TestRegistry;

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class OAuthClientFactory implements TestProviderFactory<OAuthClient> {

    @Override
    public LifeCycle getLifeCycle() {
        return LifeCycle.CLASS;
    }

    @Override
    public Class<OAuthClient> getProviderClass() {
        return OAuthClient.class;
    }

    @Override
    public OAuthClient createProvider(TestRegistry registry) {
        CloseableHttpClient httpClient = registry.getOrCreateProvider(CloseableHttpClient.class);
        return new OAuthClient(httpClient);
    }

    @Override
    public void closeProvider(OAuthClient provider) {

    }
}
