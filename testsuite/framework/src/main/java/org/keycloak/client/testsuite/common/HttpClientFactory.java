package org.keycloak.client.testsuite.common;

import java.io.IOException;
import java.io.UncheckedIOException;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.keycloak.client.testsuite.framework.LifeCycle;
import org.keycloak.client.testsuite.framework.TestProviderFactory;
import org.keycloak.client.testsuite.framework.TestRegistry;
import org.keycloak.testsuite.util.AdminClientUtil;

/**
 * Creates Apache HttpClient, which is OK to be used against started KeycloakServer based on the containers
 *
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class HttpClientFactory implements TestProviderFactory<CloseableHttpClient> {

    @Override
    public LifeCycle getLifeCycle() {
        return LifeCycle.CLASS;
    }

    @Override
    public Class<CloseableHttpClient> getProviderClass() {
        return CloseableHttpClient.class;
    }

    @Override
    public CloseableHttpClient createProvider(TestRegistry registry) {
        return HttpClientBuilder.create()
                .setSSLContext(AdminClientUtil.buildSslContext())
                .build();
    }

    @Override
    public void closeProvider(CloseableHttpClient provider) {
        try {
            provider.close();
        } catch (IOException ioe) {
            throw new UncheckedIOException(ioe);
        }
    }
}
