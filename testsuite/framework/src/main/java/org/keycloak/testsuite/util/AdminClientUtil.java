/*
 * Copyright 2016 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.keycloak.testsuite.util;

import org.apache.http.HttpHost;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.conn.HttpClientConnectionManager;
import org.apache.http.impl.conn.PoolingHttpClientConnectionManager;
import org.jboss.resteasy.client.jaxrs.ClientHttpEngine;
import org.jboss.resteasy.client.jaxrs.ResteasyClientBuilder;
import org.jboss.resteasy.client.jaxrs.engines.ClientHttpEngineBuilder43;
import org.keycloak.OAuth2Constants;
import org.keycloak.models.Constants;
import org.keycloak.testsuite.client.Keycloak;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.SecureRandom;

import static org.keycloak.testsuite.util.ServerURLs.getAuthServerContextRoot;


public class AdminClientUtil {

    public static final int NUMBER_OF_CONNECTIONS = 10;

    private static final String TLS_KEYSTORE_FILENAME = "tls.jks";
    private static final String TLS_KEYSTORE_PASSWORD = "changeit";

    public static Keycloak createAdminClient(boolean ignoreUnknownProperties, String authServerContextRoot) throws Exception {
        return createAdminClient(ignoreUnknownProperties, authServerContextRoot, "master", "admin", "admin",
            Constants.ADMIN_CLI_CLIENT_ID, null, null);

    }

    public static Keycloak createAdminClient(boolean ignoreUnknownProperties, String realmName, String username,
        String password, String clientId, String clientSecret) {
        return createAdminClient(ignoreUnknownProperties, getAuthServerContextRoot(), realmName, username, password,
            clientId, clientSecret, null);
    }

    public static Keycloak createAdminClient(boolean ignoreUnknownProperties, String authServerContextRoot, String realmName,
        String username, String password, String clientId, String clientSecret, String scope) {
        return Keycloak.getInstance(authServerContextRoot, realmName, username, password, clientId, clientSecret, buildSslContext());
    }

    public static Keycloak createAdminClientWithClientCredentials(String realmName, String clientId, String clientSecret, String scope) {
        return Keycloak.getInstance(getAuthServerContextRoot(), realmName, null, null, OAuth2Constants.CLIENT_CREDENTIALS, clientId, clientSecret, buildSslContext(), null, false, null, scope);
    }

    public static Keycloak createAdminClient() throws Exception {
        return createAdminClient(false, getAuthServerContextRoot());
    }

    public static Keycloak createAdminClient(boolean ignoreUnknownProperties) throws Exception {
        return createAdminClient(ignoreUnknownProperties, getAuthServerContextRoot());
    }

    private static SSLContext buildSslContext() {
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

    private static InputStream loadResourceAsStream(String filename) {
        return AdminClientUtil.class.getClassLoader().getResourceAsStream(filename);
    }

    public static ClientHttpEngine getCustomClientHttpEngine(ResteasyClientBuilder resteasyClientBuilder, int validateAfterInactivity, Boolean followRedirects) {
        return new CustomClientHttpEngineBuilder43(validateAfterInactivity, followRedirects).resteasyClientBuilder(resteasyClientBuilder).build();
    }

    /**
     * Adds a possibility to pass validateAfterInactivity parameter into underlying ConnectionManager. The parameter affects how
     * long the connection is being used without testing if it became stale, default value is 2000ms
     */
    private static class CustomClientHttpEngineBuilder43 extends ClientHttpEngineBuilder43 {

        private final int validateAfterInactivity;
        private final Boolean followRedirects;

        private CustomClientHttpEngineBuilder43(int validateAfterInactivity, Boolean followRedirects) {
            this.validateAfterInactivity = validateAfterInactivity;
            this.followRedirects = followRedirects;
        }

        @Override
        protected ClientHttpEngine createEngine(final HttpClientConnectionManager cm, final RequestConfig.Builder rcBuilder,
                final HttpHost defaultProxy, final int responseBufferSize, final HostnameVerifier verifier, final SSLContext theContext) {
            final ClientHttpEngine engine;
            if (cm instanceof PoolingHttpClientConnectionManager) {
                PoolingHttpClientConnectionManager pcm = (PoolingHttpClientConnectionManager) cm;
                pcm.setValidateAfterInactivity(validateAfterInactivity);
                engine = super.createEngine(pcm, rcBuilder, defaultProxy, responseBufferSize, verifier, theContext);
            } else {
                engine = super.createEngine(cm, rcBuilder, defaultProxy, responseBufferSize, verifier, theContext);
            }
            if (followRedirects != null) {
                engine.setFollowRedirects(followRedirects);
            }
            return engine;
        }
    }

}
