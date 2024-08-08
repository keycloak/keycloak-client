package org.keycloak.client.testsuite.common;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.SecureRandom;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.keycloak.client.testsuite.framework.LifeCycle;
import org.keycloak.client.testsuite.framework.TestProviderFactory;
import org.keycloak.client.testsuite.framework.TestRegistry;

/**
 * Creates Apache HttpClient, which is OK to be used against started KeycloakServer based on the containers
 *
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class HttpClientFactory implements TestProviderFactory<CloseableHttpClient> {

    private static final String TLS_KEYSTORE_FILENAME = "tls.jks";
    private static final String TLS_KEYSTORE_PASSWORD = "changeit";

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
                .setSSLContext(buildSslContext())
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

    private SSLContext buildSslContext() {
        SSLContext sslContext;
        try {
            KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            keyStore.load(loadResourceAsStream(TLS_KEYSTORE_FILENAME), TLS_KEYSTORE_PASSWORD.toCharArray());

            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(keyStore);
            sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, tmf.getTrustManagers(), new SecureRandom());
        } catch (GeneralSecurityException | IOException e) {
            sslContext = null;
        }
        return sslContext;
    }

    private InputStream loadResourceAsStream(String filename) {
        return HttpClientFactory.class.getClassLoader().getResourceAsStream(filename);
    }
}
