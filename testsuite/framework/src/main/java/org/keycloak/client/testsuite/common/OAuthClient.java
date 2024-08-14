package org.keycloak.client.testsuite.common;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;

import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.UriBuilder;
import org.apache.commons.io.IOUtils;
import org.apache.http.Header;
import org.apache.http.NameValuePair;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.message.BasicNameValuePair;
import org.keycloak.OAuth2Constants;
import org.keycloak.client.testsuite.framework.TestRegistry;
import org.keycloak.client.testsuite.server.KeycloakServerProvider;
import org.keycloak.common.util.KeycloakUriBuilder;
import org.keycloak.testsuite.util.ServerURLs;
import org.keycloak.util.BasicAuthHelper;
import org.keycloak.util.JsonSerialization;
import org.keycloak.util.TokenUtil;

import static org.junit.jupiter.api.Assertions.fail;

/**
 * @author <a href="mailto:sthorger@redhat.com">Stian Thorgersen</a>
 * @author Stan Silvert ssilvert@redhat.com (C) 2016 Red Hat Inc.
 */
public class OAuthClient {

    private String realm;
    private String clientId;
    private boolean openid = true;
    private String scope = "";

    private final CloseableHttpClient httpClient;

    public OAuthClient(CloseableHttpClient httpClient) {
        this.httpClient = httpClient;
    }

    public OAuthClient realm(String realm) {
        this.realm = realm;
        return this;
    }

    public OAuthClient clientId(String clientId) {
        this.clientId = clientId;
        return this;
    }

    public AccessTokenResponse doGrantAccessTokenRequest(String clientSecret, String username, String password) {
        return doGrantAccessTokenRequest(realm, username, password, null, clientId, clientSecret);
    }

    public AccessTokenResponse doGrantAccessTokenRequest(String clientSecret, String username, String password, String otp) {
        return doGrantAccessTokenRequest(realm, username, password, otp, clientId, clientSecret);
    }

    public AccessTokenResponse doGrantAccessTokenRequest(String realm, String username, String password, String totp,
                                                         String clientId, String clientSecret) {
        return doGrantAccessTokenRequest(realm, username, password, totp, clientId, clientSecret, null);
    }

    public AccessTokenResponse doGrantAccessTokenRequest(String realm, String username, String password, String totp,
                                                         String clientId, String clientSecret, String userAgent) {
        HttpPost post = new HttpPost(getResourceOwnerPasswordCredentialGrantUrl(realm));

        post.addHeader("Accept", MediaType.APPLICATION_JSON);

//            if (requestHeaders != null) {
//                for (Map.Entry<String, String> header : requestHeaders.entrySet()) {
//                    post.addHeader(header.getKey(), header.getValue());
//                }
//            }
//            if (dpopProof != null) {
//                post.addHeader(TokenUtil.TOKEN_TYPE_DPOP, dpopProof);
//            }

        List<NameValuePair> parameters = new LinkedList<>();
        parameters.add(new BasicNameValuePair(OAuth2Constants.GRANT_TYPE, OAuth2Constants.PASSWORD));
        parameters.add(new BasicNameValuePair("username", username));
        parameters.add(new BasicNameValuePair("password", password));
        if (totp != null) {
            parameters.add(new BasicNameValuePair("otp", totp));

        }
        if (clientSecret != null) {
            String authorization = BasicAuthHelper.createHeader(clientId, clientSecret);
            post.setHeader("Authorization", authorization);
        } else {
            parameters.add(new BasicNameValuePair("client_id", clientId));
        }

//            if (origin != null) {
//                post.addHeader("Origin", origin);
//            }
//
//            if (clientSessionState != null) {
//                parameters.add(new BasicNameValuePair(AdapterConstants.CLIENT_SESSION_STATE, clientSessionState));
//            }
//            if (clientSessionHost != null) {
//                parameters.add(new BasicNameValuePair(AdapterConstants.CLIENT_SESSION_HOST, clientSessionHost));
//            }

        String scopeParam = openid ? TokenUtil.attachOIDCScope(scope) : scope;
        if (scopeParam != null && !scopeParam.isEmpty()) {
            parameters.add(new BasicNameValuePair(OAuth2Constants.SCOPE, scopeParam));
        }

        if (userAgent != null) {
            post.addHeader("User-Agent", userAgent);
        }

//            if (customParameters != null) {
//                customParameters.keySet().stream()
//                        .forEach(paramName -> parameters.add(new BasicNameValuePair(paramName, customParameters.get(paramName))));
//            }

        UrlEncodedFormEntity formEntity;
        try {
            formEntity = new UrlEncodedFormEntity(parameters, "UTF-8");
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException(e);
        }
        post.setEntity(formEntity);

        try {
            return new AccessTokenResponse(httpClient.execute(post));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

    }

    public String getResourceOwnerPasswordCredentialGrantUrl(String realmName) {
        return KeycloakUriBuilder.fromUri(ServerURLs.AUTH_SERVER_URL + "/realms/{realmName}/protocol/openid-connect/token")
                .build(realmName)
                .toString();
    }

    public LogoutUrlBuilder getLogoutUrl() {
        return new LogoutUrlBuilder();
    }

    public CloseableHttpResponse doLogout(String refreshToken, String clientSecret) {
        try {
            return doLogout(refreshToken, clientSecret, httpClient);
        } catch (IOException ex) {
            throw new RuntimeException(ex);
        }
    }

    // KEYCLOAK-6771 Certificate Bound Token
    public CloseableHttpResponse doLogout(String refreshToken, String clientSecret, CloseableHttpClient client) throws IOException {
        HttpPost post = new HttpPost(getLogoutUrl().build());

        List<NameValuePair> parameters = new LinkedList<>();
        if (refreshToken != null) {
            parameters.add(new BasicNameValuePair(OAuth2Constants.REFRESH_TOKEN, refreshToken));
        }
        if (clientId != null && clientSecret != null) {
            String authorization = BasicAuthHelper.createHeader(clientId, clientSecret);
            post.setHeader("Authorization", authorization);
        } else if (clientId != null) {
            parameters.add(new BasicNameValuePair(OAuth2Constants.CLIENT_ID, clientId));
        }
//        if (origin != null) {
//            post.addHeader("Origin", origin);
//        }

        UrlEncodedFormEntity formEntity;
        try {
            formEntity = new UrlEncodedFormEntity(parameters, "UTF-8");
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException(e);
        }
        post.setEntity(formEntity);

        return client.execute(post);
    }


    public static class AccessTokenResponse {
        private int statusCode;

        private String idToken;
        private String accessToken;
        private String issuedTokenType;
        private String tokenType;
        private int expiresIn;
        private int refreshExpiresIn;
        private String refreshToken;
        // OIDC Financial API Read Only Profile : scope MUST be returned in the response from Token Endpoint
        private String scope;
        private String sessionState;

        private String error;
        private String errorDescription;

        private Map<String, String> headers;

        private Map<String, Object> otherClaims;

        public AccessTokenResponse(CloseableHttpResponse response) throws Exception {
            try {
                statusCode = response.getStatusLine().getStatusCode();

                headers = new HashMap<>();

                for (Header h : response.getAllHeaders()) {
                    headers.put(h.getName(), h.getValue());
                }

                Header[] contentTypeHeaders = response.getHeaders("Content-Type");
                String contentType = (contentTypeHeaders != null && contentTypeHeaders.length > 0) ? contentTypeHeaders[0].getValue() : null;
                if (!"application/json".equals(contentType)) {
                    fail("Invalid content type. Status: " + statusCode + ", contentType: " + contentType);
                }

                String s = IOUtils.toString(response.getEntity().getContent(), StandardCharsets.UTF_8);
                @SuppressWarnings("unchecked")
                Map<String, Object> responseJson = JsonSerialization.readValue(s, Map.class);

                if (statusCode == 200) {
                    otherClaims = new HashMap<>();

                    for (Map.Entry<String, Object> entry : responseJson.entrySet()) {
                        switch (entry.getKey()) {
                            case OAuth2Constants.ID_TOKEN:
                                idToken = (String) entry.getValue();
                                break;
                            case OAuth2Constants.ACCESS_TOKEN:
                                accessToken = (String) entry.getValue();
                                break;
                            case OAuth2Constants.ISSUED_TOKEN_TYPE:
                                issuedTokenType = (String) entry.getValue();
                                break;
                            case OAuth2Constants.TOKEN_TYPE:
                                tokenType = (String) entry.getValue();
                                break;
                            case OAuth2Constants.EXPIRES_IN:
                                expiresIn = (Integer) entry.getValue();
                                break;
                            case "refresh_expires_in":
                                refreshExpiresIn = (Integer) entry.getValue();
                                break;
                            case OAuth2Constants.SESSION_STATE:
                                sessionState = (String) entry.getValue();
                                break;
                            case OAuth2Constants.SCOPE:
                                scope = (String) entry.getValue();
                                break;
                            case OAuth2Constants.REFRESH_TOKEN:
                                refreshToken = (String) entry.getValue();
                                break;
                            default:
                                otherClaims.put(entry.getKey(), entry.getValue());
                                break;
                        }
                    }
                } else {
                    error = (String) responseJson.get(OAuth2Constants.ERROR);
                    errorDescription = responseJson.containsKey(OAuth2Constants.ERROR_DESCRIPTION) ? (String) responseJson.get(OAuth2Constants.ERROR_DESCRIPTION) : null;
                }
            } finally {
                response.close();
            }
        }

        public String getIdToken() {
            return idToken;
        }

        public String getAccessToken() {
            return accessToken;
        }

        public String getError() {
            return error;
        }

        public String getErrorDescription() {
            return errorDescription;
        }

        public int getExpiresIn() {
            return expiresIn;
        }

        public int getRefreshExpiresIn() {
            return refreshExpiresIn;
        }

        public int getStatusCode() {
            return statusCode;
        }

        public String getRefreshToken() {
            return refreshToken;
        }

        public String getIssuedTokenType() {
            return issuedTokenType;
        }

        public String getTokenType() {
            return tokenType;
        }

        // OIDC Financial API Read Only Profile : scope MUST be returned in the response from Token Endpoint
        public String getScope() {
            return scope;
        }

        public String getSessionState() {
            return sessionState;
        }

        public Map<String, String> getHeaders() {
            return headers;
        }

        public Map<String, Object> getOtherClaims() {
            return otherClaims;
        }
    }

    public class LogoutUrlBuilder {
        private KeycloakUriBuilder b = KeycloakUriBuilder.fromUri(ServerURLs.AUTH_SERVER_URL + "/realms/{realmName}/protocol/openid-connect/logout");

        public LogoutUrlBuilder clientId(String clientId) {
            if (clientId != null) {
                b.queryParam(OAuth2Constants.CLIENT_ID, clientId);
            }
            return this;
        }

        public LogoutUrlBuilder idTokenHint(String idTokenHint) {
            if (idTokenHint != null) {
                b.queryParam(OAuth2Constants.ID_TOKEN_HINT, idTokenHint);
            }
            return this;
        }

        public LogoutUrlBuilder postLogoutRedirectUri(String redirectUri) {
            if (redirectUri != null) {
                b.queryParam(OAuth2Constants.POST_LOGOUT_REDIRECT_URI, redirectUri);
            }
            return this;
        }

//        @Deprecated // Use only in backwards compatibility tests
//        public LogoutUrlBuilder redirectUri(String redirectUri) {
//            if (redirectUri != null) {
//                b.queryParam(OAuth2Constants.REDIRECT_URI, redirectUri);
//            }
//            return this;
//        }

        public LogoutUrlBuilder state(String state) {
            if (state != null) {
                b.queryParam(OAuth2Constants.STATE, state);
            }
            return this;
        }

        public LogoutUrlBuilder uiLocales(String uiLocales) {
            if (uiLocales != null) {
                b.queryParam(OAuth2Constants.UI_LOCALES_PARAM, uiLocales);
            }
            return this;
        }

//        public LogoutUrlBuilder initiatingIdp(String initiatingIdp) {
//            if (initiatingIdp != null) {
//                b.queryParam(AuthenticationManager.INITIATING_IDP_PARAM, initiatingIdp);
//            }
//            return this;
//        }

        public String build() {
            return b.build(realm).toString();
        }
    }
}
