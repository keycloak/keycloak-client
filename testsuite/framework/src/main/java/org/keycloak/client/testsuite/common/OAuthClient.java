package org.keycloak.client.testsuite.common;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import jakarta.ws.rs.core.MediaType;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import org.apache.commons.io.IOUtils;
import org.apache.http.Header;
import org.apache.http.NameValuePair;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.utils.URLEncodedUtils;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.util.EntityUtils;
import org.junit.jupiter.api.Assertions;
import org.keycloak.OAuth2Constants;
import org.keycloak.TokenVerifier;
import org.keycloak.common.VerificationException;
import org.keycloak.common.util.KeycloakUriBuilder;
import org.keycloak.crypto.Algorithm;
import org.keycloak.crypto.AsymmetricSignatureVerifierContext;
import org.keycloak.crypto.KeyUse;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.jose.jwk.JSONWebKeySet;
import org.keycloak.jose.jwk.JWK;
import org.keycloak.jose.jwk.JWKParser;
import org.keycloak.jose.jwk.OKPPublicJWK;
import org.keycloak.representations.JsonWebToken;
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
    private String redirectUri;
    private boolean openid = true;
    private String scope = "";

    private final CloseableHttpClient httpClient;

    private Map<String, JSONWebKeySet> publicKeys = new HashMap<>();

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

    public String getRedirectUri() {
        return redirectUri;
    }

    public OAuthClient redirectUri(String redirectUri) {
        this.redirectUri = redirectUri;
        return this;
    }

    public OAuthClient scope(String scope) {
        this.scope = scope;
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

    private static final Pattern ACTION_PATTERN = Pattern.compile(
            "<form .*action=\"(" + Pattern.quote(ServerURLs.AUTH_SERVER_URL) + "[^\"]*)\".*>",
            Pattern.CASE_INSENSITIVE);

    // Just a simple regex to locate the action in the login html. Maybe we can
    // do something better, using JSoup or similar to parse html.
    private String locateLoginActionForm(String html) {
        Matcher m = ACTION_PATTERN.matcher(html);
        if (m.find()) {
            return m.group(1);
        }
        return null;
    }

    public AuthorizationEndpointResponse doLogin(String username, String password) throws IOException {
        String url = getLoginUrlForCode();
        HttpGet get = new HttpGet(url);
        try (CloseableHttpResponse getRes = httpClient.execute(get)) {
            Assertions.assertEquals(200, getRes.getStatusLine().getStatusCode(), "Invalid login page response");
            String action = locateLoginActionForm(EntityUtils.toString(getRes.getEntity(), StandardCharsets.UTF_8));
            Assertions.assertNotNull("No login form action in the html page", action);

            HttpPost post = new HttpPost(action);
            List<NameValuePair> parameters = new LinkedList<>();
            parameters.add(new BasicNameValuePair("username", username));
            parameters.add(new BasicNameValuePair("password", password));
            UrlEncodedFormEntity data = new UrlEncodedFormEntity(parameters, StandardCharsets.UTF_8);
            post.setEntity(data);

            try (CloseableHttpResponse postRes = httpClient.execute(post)) {
                Assertions.assertEquals(302, postRes.getStatusLine().getStatusCode(), "Login response is not a redirect");
                Header location = postRes.getFirstHeader("Location");
                Assertions.assertNotNull(location, "Location header not returned");
                return new AuthorizationEndpointResponse(location.getValue());
            }
        }
    }

    public AccessTokenResponse doAccessTokenRequest(String code, String password) {
        HttpPost post = new HttpPost(getResourceOwnerPasswordCredentialGrantUrl(realm));

        List<NameValuePair> parameters = new LinkedList<>();
        parameters.add(new BasicNameValuePair(OAuth2Constants.GRANT_TYPE, OAuth2Constants.AUTHORIZATION_CODE));

        if (code != null) {
            parameters.add(new BasicNameValuePair(OAuth2Constants.CODE, code));
        }
        if (redirectUri != null) {
            parameters.add(new BasicNameValuePair(OAuth2Constants.REDIRECT_URI, redirectUri));
        }
        if (clientId != null && password != null) {
            String authorization = BasicAuthHelper.createHeader(clientId, password);
            post.setHeader("Authorization", authorization);
        } else if (clientId != null) {
            parameters.add(new BasicNameValuePair(OAuth2Constants.CLIENT_ID, clientId));
        }

        UrlEncodedFormEntity formEntity = new UrlEncodedFormEntity(parameters, StandardCharsets.UTF_8);
        post.setEntity(formEntity);

        try (CloseableHttpResponse res = httpClient.execute(post)) {
            return new AccessTokenResponse(res);
        } catch (Exception e) {
            throw new RuntimeException("Failed to retrieve access token", e);
        }
    }

    public AccessTokenResponse doRefreshTokenRequest(String refreshToken, String password) {
        HttpPost post = new HttpPost(getResourceOwnerPasswordCredentialGrantUrl(realm));

        List<NameValuePair> parameters = new LinkedList<>();
        parameters.add(new BasicNameValuePair(OAuth2Constants.GRANT_TYPE, OAuth2Constants.REFRESH_TOKEN));

        if (refreshToken != null) {
            parameters.add(new BasicNameValuePair(OAuth2Constants.REFRESH_TOKEN, refreshToken));
        }
        if (scope != null) {
            parameters.add(new BasicNameValuePair(OAuth2Constants.SCOPE, scope));
        }
        if (clientId != null && password != null) {
            String authorization = BasicAuthHelper.createHeader(clientId, password);
            post.setHeader("Authorization", authorization);
        } else if (clientId != null) {
            parameters.add(new BasicNameValuePair(OAuth2Constants.CLIENT_ID, clientId));
        }

        UrlEncodedFormEntity formEntity = new UrlEncodedFormEntity(parameters, StandardCharsets.UTF_8);
        post.setEntity(formEntity);

        try (CloseableHttpResponse res = httpClient.execute(post)) {
            return new AccessTokenResponse(res);
        } catch (Exception e) {
            throw new RuntimeException("Failed to retrieve access token", e);
        }
    }

    public String introspectTokenWithClientCredential(String realm, String clientId, String clientSecret, String tokenType, String tokenToIntrospect) {
        HttpPost post = new HttpPost(getTokenIntrospectionUrl(realm));

        String authorization = BasicAuthHelper.createHeader(clientId, clientSecret);
        post.setHeader("Authorization", authorization);

        List<NameValuePair> parameters = new LinkedList<>();

        parameters.add(new BasicNameValuePair("token", tokenToIntrospect));
        parameters.add(new BasicNameValuePair("token_type_hint", tokenType));

        UrlEncodedFormEntity formEntity = new UrlEncodedFormEntity(parameters, StandardCharsets.UTF_8);
        post.setEntity(formEntity);

        try (CloseableHttpResponse response = httpClient.execute(post)) {
            return EntityUtils.toString(response.getEntity(), StandardCharsets.UTF_8);
        } catch (Exception e) {
            throw new RuntimeException("Failed to retrieve access token", e);
        }
    }

    private String getTokenIntrospectionUrl(String realmName) {
        return KeycloakUriBuilder.fromUri(ServerURLs.AUTH_SERVER_URL + "/realms/{realmName}/protocol/openid-connect/token/introspect")
                .build(realmName)
                .toString();
    }

    private String getLoginUrlForCode() {
        KeycloakUriBuilder b = KeycloakUriBuilder.fromUri(ServerURLs.AUTH_SERVER_URL + "/realms/{realmName}/protocol/openid-connect/auth");
        b.queryParam(OAuth2Constants.RESPONSE_TYPE, "code");
        b.queryParam("response_mode", "query");
        b.queryParam(OAuth2Constants.CLIENT_ID, clientId);
        b.queryParam(OAuth2Constants.REDIRECT_URI, redirectUri);
        b.queryParam(OAuth2Constants.SCOPE, scope);

        return b.build(realm).toString();
    }

    public static class AuthorizationEndpointResponse {

        private String code;
        private String state;
        private String error;
        private String errorDescription;

        private String sessionState;

        // Just during OIDC implicit or hybrid flow
        private String accessToken;
        private String idToken;
        private String tokenType;
        private String expiresIn;

        // Just during FAPI JARM response mode JWT
        private String response;

        private String issuer;

        public AuthorizationEndpointResponse(String location) {
            init(location);
        }

        private void init(String location) {
            Map<String, String> params = URLEncodedUtils.parse(location, StandardCharsets.UTF_8)
                    .stream().collect(Collectors.toMap(NameValuePair::getName, NameValuePair::getValue));

            code = params.get(OAuth2Constants.CODE);
            state = params.get(OAuth2Constants.STATE);
            error = params.get(OAuth2Constants.ERROR);
            errorDescription = params.get(OAuth2Constants.ERROR_DESCRIPTION);
            sessionState = params.get(OAuth2Constants.SESSION_STATE);
            accessToken = params.get(OAuth2Constants.ACCESS_TOKEN);
            idToken = params.get(OAuth2Constants.ID_TOKEN);
            tokenType = params.get(OAuth2Constants.TOKEN_TYPE);
            expiresIn = params.get(OAuth2Constants.EXPIRES_IN);
            response = params.get(OAuth2Constants.RESPONSE);
            issuer = params.get(OAuth2Constants.ISSUER);
        }

        public String getCode() {
            return code;
        }

        public String getState() {
            return state;
        }

        public String getError() {
            return error;
        }

        public String getErrorDescription() {
            return errorDescription;
        }

        public String getSessionState() {
            return sessionState;
        }

        public String getAccessToken() {
            return accessToken;
        }

        public String getIdToken() {
            return idToken;
        }

        public String getTokenType() {
            return tokenType;
        }

        public String getExpiresIn() {
            return expiresIn;
        }

        public String getResponse() {
            return response;
        }

        public String getIssuer() {
            return issuer;
        }
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

    public <T extends JsonWebToken> T verifyToken(String token, Class<T> clazz) {
        try {
            TokenVerifier<T> verifier = TokenVerifier.create(token, clazz);
            String kid = verifier.getHeader().getKeyId();
            String algorithm = verifier.getHeader().getAlgorithm().name();
            KeyWrapper key = getRealmPublicKey(realm, algorithm, kid);
            AsymmetricSignatureVerifierContext verifierContext;
            switch (algorithm) {
                case Algorithm.ES256:
                case Algorithm.ES384:
                default:
                    verifierContext = new AsymmetricSignatureVerifierContext(key);
            }
            verifier.verifierContext(verifierContext);
            verifier.verify();
            return verifier.getToken();
        } catch (VerificationException e) {
            throw new RuntimeException("Failed to decode token", e);
        }
    }

    private KeyWrapper getRealmPublicKey(String realm, String algorithm, String kid) {
        boolean loadedKeysFromServer = false;
        JSONWebKeySet jsonWebKeySet = publicKeys.get(realm);
        if (jsonWebKeySet == null) {
            jsonWebKeySet = getRealmKeys(realm);
            publicKeys.put(realm, jsonWebKeySet);
            loadedKeysFromServer = true;
        }

        KeyWrapper key = findKey(jsonWebKeySet, algorithm, kid);

        if (key == null && !loadedKeysFromServer) {
            jsonWebKeySet = getRealmKeys(realm);
            publicKeys.put(realm, jsonWebKeySet);

            key = findKey(jsonWebKeySet, algorithm, kid);
        }

        if (key == null) {
            throw new RuntimeException("Public key for realm:" + realm + ", algorithm: " + algorithm + " not found");
        }

        return key;
    }

    private JSONWebKeySet getRealmKeys(String realm) {
        String certUrl = ServerURLs.AUTH_SERVER_URL + "/realms/" + realm + "/protocol/openid-connect/certs";


        HttpGet get = new HttpGet(certUrl);
        try (CloseableHttpResponse response = httpClient.execute(get)) {
            return JsonSerialization.readValue(response.getEntity().getContent(), JSONWebKeySet.class);
        } catch (IOException ex) {
            throw new RuntimeException(ex);
        }
    }

    private KeyWrapper findKey(JSONWebKeySet jsonWebKeySet, String algorithm, String kid) {
        for (JWK k : jsonWebKeySet.getKeys()) {
            if (k.getKeyId().equals(kid) && k.getAlgorithm().equals(algorithm)) {
                PublicKey publicKey = JWKParser.create(k).toPublicKey();

                KeyWrapper key = new KeyWrapper();
                key.setKid(k.getKeyId());
                key.setAlgorithm(k.getAlgorithm());
                if (k.getOtherClaims().get(OKPPublicJWK.CRV) != null) {
                    key.setCurve((String) k.getOtherClaims().get(OKPPublicJWK.CRV));
                }
                key.setPublicKey(publicKey);
                key.setUse(KeyUse.SIG);

                return key;
            }
        }
        return null;
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
