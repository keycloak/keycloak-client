/*
 * Copyright 2017 Red Hat, Inc. and/or its affiliates
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
package org.keycloak.client.testsuite.authz;

import jakarta.ws.rs.core.Response;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.function.Supplier;
import java.util.stream.Collectors;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.admin.client.resource.AuthorizationResource;
import org.keycloak.admin.client.resource.ClientResource;
import org.keycloak.admin.client.resource.ClientsResource;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.admin.client.resource.ResourceResource;
import org.keycloak.admin.client.resource.ScopePermissionsResource;
import org.keycloak.authorization.client.AuthorizationDeniedException;
import org.keycloak.authorization.client.AuthzClient;
import org.keycloak.authorization.client.Configuration;
import org.keycloak.authorization.client.representation.TokenIntrospectionResponse;
import org.keycloak.authorization.client.util.HttpResponseException;
import org.keycloak.client.testsuite.common.OAuthClient;
import org.keycloak.client.testsuite.events.EventType;
import org.keycloak.client.testsuite.framework.PairwiseHttpServerExtension;
import org.keycloak.common.util.Base64Url;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.AccessToken.Authorization;
import org.keycloak.representations.AccessTokenResponse;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.representations.idm.EventRepresentation;
import org.keycloak.representations.idm.ProtocolMapperRepresentation;
import org.keycloak.representations.idm.RealmRepresentation;
import org.keycloak.representations.idm.authorization.AuthorizationRequest;
import org.keycloak.representations.idm.authorization.AuthorizationRequest.Metadata;
import org.keycloak.representations.idm.authorization.AuthorizationResponse;
import org.keycloak.representations.idm.authorization.DecisionStrategy;
import org.keycloak.representations.idm.authorization.JSPolicyRepresentation;
import org.keycloak.representations.idm.authorization.Permission;
import org.keycloak.representations.idm.authorization.PermissionRequest;
import org.keycloak.representations.idm.authorization.PermissionResponse;
import org.keycloak.representations.idm.authorization.PermissionTicketRepresentation;
import org.keycloak.representations.idm.authorization.ResourcePermissionRepresentation;
import org.keycloak.representations.idm.authorization.ResourceRepresentation;
import org.keycloak.representations.idm.authorization.ResourceServerRepresentation;
import org.keycloak.representations.idm.authorization.ScopePermissionRepresentation;
import org.keycloak.representations.idm.authorization.ScopeRepresentation;
import org.keycloak.representations.idm.authorization.UserPolicyRepresentation;
import org.keycloak.testsuite.util.ApiUtil;
import org.keycloak.testsuite.util.ClientBuilder;
import org.keycloak.testsuite.util.KeycloakModelUtils;
import org.keycloak.testsuite.util.RealmBuilder;
import org.keycloak.testsuite.util.RoleBuilder;
import org.keycloak.testsuite.util.RolesBuilder;
import org.keycloak.testsuite.util.ServerURLs;
import org.keycloak.testsuite.util.UserBuilder;
import org.keycloak.util.JsonSerialization;
import org.testcontainers.shaded.org.hamcrest.MatcherAssert;
import org.testcontainers.shaded.org.hamcrest.Matchers;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
@ExtendWith(PairwiseHttpServerExtension.class)
public class EntitlementAPITest extends AbstractAuthzTest {

    private static final String RESOURCE_SERVER_TEST = "resource-server-test";
    private static final String TEST_CLIENT = "test-client";
    private static final String AUTHZ_CLIENT_CONFIG = "/authorization-test/default-keycloak.json";
    private static final String PAIRWISE_RESOURCE_SERVER_TEST = "pairwise-resource-server-test";
    private static final String PAIRWISE_TEST_CLIENT = "test-client-pairwise";
    private static final String PAIRWISE_AUTHZ_CLIENT_CONFIG = "/authorization-test/default-keycloak-pairwise.json";
    private static final String PUBLIC_TEST_CLIENT = "test-public-client";
    private static final String PUBLIC_TEST_CLIENT_CONFIG = "/authorization-test/default-keycloak-public-client.json";

    @Override
    public List<RealmRepresentation> getRealmsForImport() {
        List<RealmRepresentation> testRealms = new ArrayList<>();

        testRealms.add(RealmBuilder.create().name("authz-test")
                .events(EventType.PERMISSION_TOKEN_ERROR)
                .roles(RolesBuilder.create().realmRole(RoleBuilder.create().name("uma_authorization").build()))
                .user(UserBuilder.create().username("marta").password("password").addRoles("uma_authorization"))
                .user(UserBuilder.create().username("kolo").password("password"))
                .user(UserBuilder.create().username("offlineuser").password("password").addRoles("offline_access"))
                .client(ClientBuilder.create().clientId(RESOURCE_SERVER_TEST)
                        .secret("secret")
                        .authorizationServicesEnabled(true)
                        .redirectUris("http://localhost/resource-server-test")
                        .defaultRoles("uma_protection")
                        .directAccessGrants())
                .client(ClientBuilder.create().clientId(PAIRWISE_RESOURCE_SERVER_TEST)
                        .secret("secret")
                        .authorizationServicesEnabled(true)
                        .redirectUris("http://localhost/resource-server-test")
                        .defaultRoles("uma_protection")
                        .protocolMapper(createPairwiseMapper(PairwiseHttpServerExtension.HTTP_URL))
                        .directAccessGrants())
                .client(ClientBuilder.create().clientId(TEST_CLIENT)
                        .secret("secret")
                        .authorizationServicesEnabled(true)
                        .redirectUris("http://localhost/test-client")
                        .directAccessGrants())
                .client(ClientBuilder.create().clientId(PAIRWISE_TEST_CLIENT)
                        .secret("secret")
                        .authorizationServicesEnabled(true)
                        .redirectUris("http://localhost/test-client")
                        .protocolMapper(createPairwiseMapper(PairwiseHttpServerExtension.HTTP_URL))
                        .directAccessGrants())
                .client(ClientBuilder.create().clientId(PUBLIC_TEST_CLIENT)
                        .secret("secret")
                        .redirectUris("http://localhost:8180/auth/realms/master/app/auth/*", "https://localhost:8543/auth/realms/master/app/auth/*")
                        .publicClient())
                .build());
        return testRealms;
    }

    @BeforeEach
    public void configureAuthorization() throws Exception {
        configureAuthorization(RESOURCE_SERVER_TEST);
        configureAuthorization(PAIRWISE_RESOURCE_SERVER_TEST);
    }

    @AfterEach
    public void removeAuthorization() throws Exception {
        removeAuthorization(RESOURCE_SERVER_TEST);
        removeAuthorization(PAIRWISE_RESOURCE_SERVER_TEST);
    }

    @Test
    public void testRptRequestWithoutResourceName() {
        testRptRequestWithoutResourceName(AUTHZ_CLIENT_CONFIG);
    }

    @Test
    public void testRptRequestWithoutResourceNamePairwise() {
        testRptRequestWithoutResourceName(PAIRWISE_AUTHZ_CLIENT_CONFIG);
    }

    public void testRptRequestWithoutResourceName(String configFile) {
        Metadata metadata = new Metadata();

        metadata.setIncludeResourceName(false);

        assertResponse(metadata, () -> {
            AuthorizationRequest request = new AuthorizationRequest();

            request.setMetadata(metadata);
            request.addPermission("Resource 1");

            return getAuthzClient(configFile).authorization("marta", "password").authorize(request);
        });
    }

    @Test
    public void testRptRequestWithResourceName() {
        testRptRequestWithResourceName(AUTHZ_CLIENT_CONFIG);
    }

    @Test
    public void testRptRequestWithResourceNamePairwise() {
        testRptRequestWithResourceName(PAIRWISE_AUTHZ_CLIENT_CONFIG);
    }

    @Test
    public void testInvalidRequestWithClaimsFromConfidentialClient() throws IOException {
        AuthorizationRequest request = new AuthorizationRequest();

        request.addPermission("Resource 13");
        HashMap<Object, Object> obj = new HashMap<>();

        obj.put("claim-a", "claim-a");

        request.setClaimToken(Base64Url.encode(JsonSerialization.writeValueAsBytes(obj)));

        assertResponse(new Metadata(), () -> getAuthzClient(AUTHZ_CLIENT_CONFIG).authorization("marta", "password").authorize(request));
    }

    @Test
    public void testInvalidRequestWithClaimsFromPublicClient() throws IOException {
        oauth.realm("authz-test");
        oauth.clientId(PUBLIC_TEST_CLIENT);
        oauth.scope("openid");
        oauth.redirectUri("https://localhost:8543/auth/realms/master/app/auth/");
        OAuthClient.AuthorizationEndpointResponse res = oauth.doLogin("marta", "password");

        // Token request
        OAuthClient.AccessTokenResponse response = oauth.doAccessTokenRequest(res.getCode(), null);

        AuthorizationRequest request = new AuthorizationRequest();

        request.addPermission("Resource 13");
        HashMap<Object, Object> obj = new HashMap<>();

        obj.put("claim-a", "claim-a");

        request.setClaimToken(Base64Url.encode(JsonSerialization.writeValueAsBytes(obj)));

        AuthorizationDeniedException ex = Assertions.assertThrows(AuthorizationDeniedException.class,
                () -> getAuthzClient(AUTHZ_CLIENT_CONFIG).authorization(response.getAccessToken()).authorize(request));
        MatcherAssert.assertThat(ex.getCause(), Matchers.allOf(Matchers.instanceOf(HttpResponseException.class), Matchers.hasProperty("statusCode", Matchers.is(403))));
        MatcherAssert.assertThat(ex.getMessage(), Matchers.containsString("Public clients are not allowed to send claims"));

        oauth.doLogout(response.getRefreshToken(), null);
    }

    @Test
    public void testRequestWithoutClaimsFromPublicClient() throws IOException {
        oauth.realm("authz-test");
        oauth.clientId(PUBLIC_TEST_CLIENT);
        oauth.scope("openid");
        oauth.redirectUri("https://localhost:8543/auth/realms/master/app/auth/");
        OAuthClient.AuthorizationEndpointResponse res = oauth.doLogin("marta", "password");

        // Token request
        OAuthClient.AccessTokenResponse response = oauth.doAccessTokenRequest(res.getCode(), null);

        AuthorizationRequest request = new AuthorizationRequest();

        request.addPermission("Resource 13");

        assertResponse(new Metadata(), () -> getAuthzClient(AUTHZ_CLIENT_CONFIG).authorization(response.getAccessToken()).authorize(request));

        oauth.doLogout(response.getRefreshToken(), null);
    }

    @Test
    public void testPermissionLimit() {
        testPermissionLimit(AUTHZ_CLIENT_CONFIG);
    }

    @Test
    public void testPermissionLimitPairwise() {
        testPermissionLimit(PAIRWISE_AUTHZ_CLIENT_CONFIG);
    }

    public void testPermissionLimit(String configFile) {
        AuthorizationRequest request = new AuthorizationRequest();

        for (int i = 1; i <= 10; i++) {
            request.addPermission("Resource " + i);
        }

        Metadata metadata = new Metadata();

        metadata.setLimit(10);

        request.setMetadata(metadata);

        AuthorizationResponse response = getAuthzClient(configFile).authorization("marta", "password").authorize(request);
        AccessToken rpt = toAccessToken(response.getToken());

        List<Permission> permissions = new ArrayList<>(rpt.getAuthorization().getPermissions());

        Assertions.assertEquals(10, permissions.size());

        for (int i = 0; i < 10; i++) {
            Assertions.assertEquals("Resource " + (i + 1), permissions.get(i).getResourceName());
        }

        request = new AuthorizationRequest();

        for (int i = 11; i <= 15; i++) {
            request.addPermission("Resource " + i);
        }

        request.setMetadata(metadata);
        request.setRpt(response.getToken());

        response = getAuthzClient(configFile).authorization("marta", "password").authorize(request);
        rpt = toAccessToken(response.getToken());

        permissions = new ArrayList<>(rpt.getAuthorization().getPermissions());

        Assertions.assertEquals(10, permissions.size());

        for (int i = 0; i < 10; i++) {
            if (i < 5) {
                Assertions.assertEquals("Resource " + (i + 11), permissions.get(i).getResourceName());
            } else {
                Assertions.assertEquals("Resource " + (i - 4), permissions.get(i).getResourceName());
            }
        }

        request = new AuthorizationRequest();

        for (int i = 16; i <= 18; i++) {
            request.addPermission("Resource " + i);
        }

        request.setMetadata(metadata);
        request.setRpt(response.getToken());

        response = getAuthzClient(configFile).authorization("marta", "password").authorize(request);
        rpt = toAccessToken(response.getToken());

        permissions = new ArrayList<>(rpt.getAuthorization().getPermissions());

        Assertions.assertEquals(10, permissions.size());
        Assertions.assertEquals("Resource 16", permissions.get(0).getResourceName());
        Assertions.assertEquals("Resource 17", permissions.get(1).getResourceName());
        Assertions.assertEquals("Resource 18", permissions.get(2).getResourceName());
        Assertions.assertEquals("Resource 11", permissions.get(3).getResourceName());
        Assertions.assertEquals("Resource 12", permissions.get(4).getResourceName());
        Assertions.assertEquals("Resource 13", permissions.get(5).getResourceName());
        Assertions.assertEquals("Resource 14", permissions.get(6).getResourceName());
        Assertions.assertEquals("Resource 15", permissions.get(7).getResourceName());
        Assertions.assertEquals("Resource 1", permissions.get(8).getResourceName());
        Assertions.assertEquals("Resource 2", permissions.get(9).getResourceName());

        request = new AuthorizationRequest();

        metadata.setLimit(5);
        request.setMetadata(metadata);
        request.setRpt(response.getToken());

        response = getAuthzClient(configFile).authorization("marta", "password").authorize(request);
        rpt = toAccessToken(response.getToken());

        permissions = new ArrayList<>(rpt.getAuthorization().getPermissions());

        Assertions.assertEquals(5, permissions.size());
        Assertions.assertEquals("Resource 16", permissions.get(0).getResourceName());
        Assertions.assertEquals("Resource 17", permissions.get(1).getResourceName());
        Assertions.assertEquals("Resource 18", permissions.get(2).getResourceName());
        Assertions.assertEquals("Resource 11", permissions.get(3).getResourceName());
        Assertions.assertEquals("Resource 12", permissions.get(4).getResourceName());
    }

    @Test
    public void testResourceServerAsAudience() throws Exception {
        testResourceServerAsAudience(
                TEST_CLIENT,
                RESOURCE_SERVER_TEST,
                AUTHZ_CLIENT_CONFIG);
    }

    @Test
    public void testResourceServerAsAudienceWithPairwiseClient() throws Exception {
        testResourceServerAsAudience(
                PAIRWISE_TEST_CLIENT,
                RESOURCE_SERVER_TEST,
                AUTHZ_CLIENT_CONFIG);
    }

    @Test
    public void testPairwiseResourceServerAsAudience() throws Exception {
        testResourceServerAsAudience(
                TEST_CLIENT,
                PAIRWISE_RESOURCE_SERVER_TEST,
                PAIRWISE_AUTHZ_CLIENT_CONFIG);
    }

    @Test
    public void testPairwiseResourceServerAsAudienceWithPairwiseClient() throws Exception {
        testResourceServerAsAudience(
                PAIRWISE_TEST_CLIENT,
                PAIRWISE_RESOURCE_SERVER_TEST,
                PAIRWISE_AUTHZ_CLIENT_CONFIG);
    }

    @Test
    public void testObtainAllEntitlements() throws Exception {
        ClientResource client = getClient(getRealm(), RESOURCE_SERVER_TEST);
        AuthorizationResource authorization = client.authorization();

        JSPolicyRepresentation policy = new JSPolicyRepresentation();

        policy.setName("Only Owner Policy");
        policy.setType("script-scripts/only-owner-policy.js");

        authorization.policies().js().create(policy).close();

        ResourceRepresentation resource = new ResourceRepresentation();

        resource.setName("Marta Resource");
        resource.setOwner("marta");
        resource.setOwnerManagedAccess(true);

        try (Response response = authorization.resources().create(resource)) {
            resource = response.readEntity(ResourceRepresentation.class);
        }

        ResourcePermissionRepresentation permission = new ResourcePermissionRepresentation();

        permission.setName("Marta Resource Permission");
        permission.addResource(resource.getId());
        permission.addPolicy(policy.getName());

        authorization.permissions().resource().create(permission).close();

        Assertions.assertTrue(hasPermission("marta", "password", resource.getId()));
        Assertions.assertFalse(hasPermission("kolo", "password", resource.getId()));

        String accessToken = oauth.realm("authz-test").clientId(RESOURCE_SERVER_TEST).doGrantAccessTokenRequest("secret", "kolo", "password").getAccessToken();
        AuthzClient authzClient = getAuthzClient(AUTHZ_CLIENT_CONFIG);
        PermissionResponse permissionResponse = authzClient.protection().permission().create(new PermissionRequest(resource.getId()));
        AuthorizationRequest request = new AuthorizationRequest();

        request.setTicket(permissionResponse.getTicket());

        try {
            authzClient.authorization(accessToken).authorize(request);
        } catch (AuthorizationDeniedException ignore) {

        }

        List<PermissionTicketRepresentation> tickets = authzClient.protection().permission().findByResource(resource.getId());

        Assertions.assertEquals(1, tickets.size());

        PermissionTicketRepresentation ticket = tickets.get(0);

        ticket.setGranted(true);

        authzClient.protection().permission().update(ticket);

        Assertions.assertTrue(hasPermission("kolo", "password", resource.getId()));

        resource.addScope("Scope A");

        authorization.resources().resource(resource.getId()).update(resource);

        // the addition of a new scope still grants access to resource and any scope
        Assertions.assertFalse(hasPermission("kolo", "password", resource.getId()));

        accessToken = oauth.realm("authz-test").clientId(RESOURCE_SERVER_TEST).doGrantAccessTokenRequest("secret", "kolo", "password").getAccessToken();
        permissionResponse = authzClient.protection().permission().create(new PermissionRequest(resource.getId(), "Scope A"));
        request = new AuthorizationRequest();

        request.setTicket(permissionResponse.getTicket());

        try {
            authzClient.authorization(accessToken).authorize(request);
        } catch (AuthorizationDeniedException ignore) {

        }

        tickets = authzClient.protection().permission().find(resource.getId(), "Scope A", null, null, false, false, null, null);

        Assertions.assertEquals(1, tickets.size());

        ticket = tickets.get(0);

        ticket.setGranted(true);

        authzClient.protection().permission().update(ticket);

        Assertions.assertTrue(hasPermission("kolo", "password", resource.getId(), "Scope A"));

        resource.addScope("Scope B");

        authorization.resources().resource(resource.getId()).update(resource);

        Assertions.assertTrue(hasPermission("kolo", "password", resource.getId()));
        Assertions.assertTrue(hasPermission("kolo", "password", resource.getId(), "Scope A"));
        Assertions.assertFalse(hasPermission("kolo", "password", resource.getId(), "Scope B"));

        resource.setScopes(new HashSet<>());

        authorization.resources().resource(resource.getId()).update(resource);

        Assertions.assertTrue(hasPermission("kolo", "password", resource.getId()));
        Assertions.assertFalse(hasPermission("kolo", "password", resource.getId(), "Scope A"));
        Assertions.assertFalse(hasPermission("kolo", "password", resource.getId(), "Scope B"));
    }

    @Test
    public void testObtainAllEntitlementsWithLimit() throws Exception {
        org.keycloak.authorization.client.resource.AuthorizationResource authorizationResource = getAuthzClient(AUTHZ_CLIENT_CONFIG).authorization("marta", "password");
        AuthorizationResponse response = authorizationResource.authorize();
        AccessToken accessToken = toAccessToken(response.getToken());
        Authorization authorization = accessToken.getAuthorization();

        Assertions.assertTrue(authorization.getPermissions().size() >= 20);

        AuthorizationRequest request = new AuthorizationRequest();
        Metadata metadata = new Metadata();

        metadata.setLimit(10);

        request.setMetadata(metadata);

        response = authorizationResource.authorize(request);
        accessToken = toAccessToken(response.getToken());
        authorization = accessToken.getAuthorization();

        Assertions.assertEquals(10, authorization.getPermissions().size());

        metadata.setLimit(1);

        request.setMetadata(metadata);

        response = authorizationResource.authorize(request);
        accessToken = toAccessToken(response.getToken());
        authorization = accessToken.getAuthorization();

        Assertions.assertEquals(1, authorization.getPermissions().size());
    }

    @Test
    public void testObtainAllEntitlementsInvalidResource() throws Exception {
        ClientResource client = getClient(getRealm(), RESOURCE_SERVER_TEST);

        AuthorizationResource authorization = client.authorization();

        JSPolicyRepresentation policy = new JSPolicyRepresentation();

        policy.setName(KeycloakModelUtils.generateId());
        policy.setType("script-scripts/default-policy.js");

        authorization.policies().js().create(policy).close();

        ResourceRepresentation resource = new ResourceRepresentation();

        resource.setName("Sensors");
        resource.addScope("sensors:view", "sensors:update", "sensors:delete");

        authorization.resources().create(resource).close();

        ScopePermissionRepresentation permission = new ScopePermissionRepresentation();

        permission.setName("View Sensor");
        permission.addScope("sensors:view");
        permission.addPolicy(policy.getName());

        authorization.permissions().scope().create(permission).close();

        String accessToken = oauth.realm("authz-test").clientId(RESOURCE_SERVER_TEST).doGrantAccessTokenRequest("secret", "kolo", "password").getAccessToken();
        AuthzClient authzClient = getAuthzClient(AUTHZ_CLIENT_CONFIG);
        AuthorizationRequest request = new AuthorizationRequest();

        request.addPermission("Sensortest", "sensors:view");

        AccessToken at = toAccessToken(accessToken);

        getRealm().clearEvents();

        try {
            authzClient.authorization(accessToken).authorize(request);
            Assertions.fail("resource is invalid");
        } catch (RuntimeException expected) {
            Assertions.assertEquals(400, HttpResponseException.class.cast(expected.getCause()).getStatusCode());
            Assertions.assertTrue(HttpResponseException.class.cast(expected.getCause()).toString().contains("invalid_resource"));
        }

        List<EventRepresentation> events = getRealm()
                .getEvents(Arrays.asList(EventType.PERMISSION_TOKEN_ERROR.name()), null, null, null, null, null, null, null);
        Assertions.assertEquals(1, events.size());
        EventRepresentation event = events.iterator().next();
        Assertions.assertEquals(RESOURCE_SERVER_TEST, event.getClientId());
        Assertions.assertEquals("invalid_request", event.getError());
        Assertions.assertEquals("Resource with id [Sensortest] does not exist.", event.getDetails().get("reason"));
        Assertions.assertEquals(at.getSubject(), event.getUserId());
    }

    @Test
    public void testObtainAllEntitlementsInvalidScope() throws Exception {
        ClientResource client = getClient(getRealm(), RESOURCE_SERVER_TEST);
        AuthorizationResource authorization = client.authorization();

        JSPolicyRepresentation policy = new JSPolicyRepresentation();

        policy.setName(KeycloakModelUtils.generateId());
        policy.setType("script-scripts/default-policy.js");

        authorization.policies().js().create(policy).close();

        ResourceRepresentation resource = new ResourceRepresentation();

        resource.setName(KeycloakModelUtils.generateId());
        resource.addScope("sensors:view", "sensors:update", "sensors:delete");

        try (Response response = authorization.resources().create(resource)) {
            resource = response.readEntity(ResourceRepresentation.class);
        }

        ScopePermissionRepresentation permission = new ScopePermissionRepresentation();

        permission.setName(KeycloakModelUtils.generateId());
        permission.addScope("sensors:view");
        permission.addPolicy(policy.getName());

        authorization.permissions().scope().create(permission).close();

        String accessToken = oauth.realm("authz-test").clientId(RESOURCE_SERVER_TEST).doGrantAccessTokenRequest("secret", "kolo", "password").getAccessToken();
        AuthzClient authzClient = getAuthzClient(AUTHZ_CLIENT_CONFIG);
        AuthorizationRequest request = new AuthorizationRequest();

        request.addPermission(resource.getId(), "sensors:view_invalid");

        try {
            authzClient.authorization(accessToken).authorize(request);
            Assertions.fail("scope is invalid");
        } catch (RuntimeException expected) {
            Assertions.assertEquals(400, HttpResponseException.class.cast(expected.getCause()).getStatusCode());
            Assertions.assertTrue(HttpResponseException.class.cast(expected.getCause()).toString().contains("invalid_scope"));
        }

        request = new AuthorizationRequest();

        request.addPermission(null, "sensors:view_invalid");

        try {
            authzClient.authorization(accessToken).authorize(request);
            Assertions.fail("scope is invalid");
        } catch (RuntimeException expected) {
            Assertions.assertEquals(400, HttpResponseException.class.cast(expected.getCause()).getStatusCode());
            Assertions.assertTrue(HttpResponseException.class.cast(expected.getCause()).toString().contains("invalid_scope"));
        }
    }

    @Test
    public void testObtainAllEntitlementsForScope() throws Exception {
        ClientResource client = getClient(getRealm(), RESOURCE_SERVER_TEST);
        AuthorizationResource authorization = client.authorization();

        JSPolicyRepresentation policy = new JSPolicyRepresentation();

        policy.setName(KeycloakModelUtils.generateId());
        policy.setType("script-scripts/default-policy.js");

        authorization.policies().js().create(policy).close();

        Set<String> resourceIds = new HashSet<>();
        ResourceRepresentation resource = new ResourceRepresentation();

        resource.setName(KeycloakModelUtils.generateId());
        resource.addScope("sensors:view", "sensors:update", "sensors:delete");

        try (Response response = authorization.resources().create(resource)) {
            resourceIds.add(response.readEntity(ResourceRepresentation.class).getId());
        }

        resource = new ResourceRepresentation();

        resource.setName(KeycloakModelUtils.generateId());
        resource.addScope("sensors:view", "sensors:update");

        try (Response response = authorization.resources().create(resource)) {
            resourceIds.add(response.readEntity(ResourceRepresentation.class).getId());
        }

        ScopePermissionRepresentation permission = new ScopePermissionRepresentation();

        permission.setName(KeycloakModelUtils.generateId());
        permission.addScope("sensors:view", "sensors:update");
        permission.addPolicy(policy.getName());

        authorization.permissions().scope().create(permission).close();

        String accessToken = oauth.realm("authz-test").clientId(RESOURCE_SERVER_TEST).doGrantAccessTokenRequest("secret", "kolo", "password").getAccessToken();
        AuthzClient authzClient = getAuthzClient(AUTHZ_CLIENT_CONFIG);
        AuthorizationRequest request = new AuthorizationRequest();

        request.addPermission(null, "sensors:view");

        AuthorizationResponse response = authzClient.authorization(accessToken).authorize(request);
        Assertions.assertNotNull(response.getToken());
        Collection<Permission> permissions = toAccessToken(response.getToken()).getAuthorization().getPermissions();
        Assertions.assertEquals(2, permissions.size());

        for (Permission grantedPermission : permissions) {
            Assertions.assertTrue(resourceIds.containsAll(Arrays.asList(grantedPermission.getResourceId())));
            Assertions.assertEquals(1, grantedPermission.getScopes().size());
            Assertions.assertTrue(grantedPermission.getScopes().containsAll(Arrays.asList("sensors:view")));
        }

        request.addPermission(null, "sensors:view", "sensors:update");

        response = authzClient.authorization(accessToken).authorize(request);
        Assertions.assertNotNull(response.getToken());
        permissions = toAccessToken(response.getToken()).getAuthorization().getPermissions();
        Assertions.assertEquals(2, permissions.size());

        for (Permission grantedPermission : permissions) {
            Assertions.assertTrue(resourceIds.containsAll(Arrays.asList(grantedPermission.getResourceId())));
            Assertions.assertEquals(2, grantedPermission.getScopes().size());
            Assertions.assertTrue(grantedPermission.getScopes().containsAll(Arrays.asList("sensors:view", "sensors:update")));
        }

        request.addPermission(null, "sensors:view", "sensors:update", "sensors:delete");

        response = authzClient.authorization(accessToken).authorize(request);
        Assertions.assertNotNull(response.getToken());
        permissions = toAccessToken(response.getToken()).getAuthorization().getPermissions();
        Assertions.assertEquals(2, permissions.size());

        for (Permission grantedPermission : permissions) {
            Assertions.assertTrue(resourceIds.containsAll(Arrays.asList(grantedPermission.getResourceId())));
            Assertions.assertEquals(2, grantedPermission.getScopes().size());
            Assertions.assertTrue(grantedPermission.getScopes().containsAll(Arrays.asList("sensors:view", "sensors:update")));
        }

        request = new AuthorizationRequest();

        request.addPermission(null, "sensors:view");
        request.addPermission(null, "sensors:update");

        response = authzClient.authorization(accessToken).authorize(request);
        Assertions.assertNotNull(response.getToken());
        permissions = toAccessToken(response.getToken()).getAuthorization().getPermissions();
        Assertions.assertEquals(2, permissions.size());

        for (Permission grantedPermission : permissions) {
            Assertions.assertTrue(resourceIds.containsAll(Arrays.asList(grantedPermission.getResourceId())));
            Assertions.assertEquals(2, grantedPermission.getScopes().size());
            Assertions.assertTrue(grantedPermission.getScopes().containsAll(Arrays.asList("sensors:view", "sensors:update")));
        }
    }

    @Test
    public void testObtainAllEntitlementsForScopeWithDeny() throws Exception {
        ClientResource client = getClient(getRealm(), RESOURCE_SERVER_TEST);
        AuthorizationResource authorization = client.authorization();

        JSPolicyRepresentation policy = new JSPolicyRepresentation();

        policy.setName(KeycloakModelUtils.generateId());
        policy.setType("script-scripts/default-policy.js");

        authorization.policies().js().create(policy).close();

        authorization.scopes().create(new ScopeRepresentation("sensors:view")).close();

        ScopePermissionRepresentation permission = new ScopePermissionRepresentation();

        permission.setName(KeycloakModelUtils.generateId());
        permission.addScope("sensors:view");
        permission.addPolicy(policy.getName());

        authorization.permissions().scope().create(permission).close();

        String accessToken = oauth.realm("authz-test").clientId(RESOURCE_SERVER_TEST).doGrantAccessTokenRequest("secret", "kolo", "password").getAccessToken();
        AuthzClient authzClient = getAuthzClient(AUTHZ_CLIENT_CONFIG);
        AuthorizationRequest request = new AuthorizationRequest();

        request.addPermission(null, "sensors:view");

        AuthorizationResponse response = authzClient.authorization(accessToken).authorize(request);
        Assertions.assertNotNull(response.getToken());
        Collection<Permission> permissions = toAccessToken(response.getToken()).getAuthorization().getPermissions();
        Assertions.assertEquals(1, permissions.size());

        for (Permission grantedPermission : permissions) {
            Assertions.assertNull(grantedPermission.getResourceId());
            Assertions.assertEquals(1, grantedPermission.getScopes().size());
            Assertions.assertTrue(grantedPermission.getScopes().containsAll(Arrays.asList("sensors:view")));
        }
    }

    @Test
    public void testObtainAllEntitlementsForResourceWithResourcePermission() throws Exception {
        ClientResource client = getClient(getRealm(), RESOURCE_SERVER_TEST);
        AuthorizationResource authorization = client.authorization();

        JSPolicyRepresentation policy = new JSPolicyRepresentation();

        policy.setName(KeycloakModelUtils.generateId());
        policy.setType("script-scripts/default-policy.js");

        authorization.policies().js().create(policy).close();

        ResourceRepresentation resource = new ResourceRepresentation();

        resource.setName(KeycloakModelUtils.generateId());
        resource.addScope("scope:view", "scope:update", "scope:delete");

        try (Response response = authorization.resources().create(resource)) {
            resource = response.readEntity(ResourceRepresentation.class);
        }

        ResourcePermissionRepresentation permission = new ResourcePermissionRepresentation();

        permission.setName(KeycloakModelUtils.generateId());
        permission.addResource(resource.getId());
        permission.addPolicy(policy.getName());

        authorization.permissions().resource().create(permission).close();

        String accessToken = oauth.realm("authz-test").clientId(RESOURCE_SERVER_TEST).doGrantAccessTokenRequest("secret", "kolo", "password").getAccessToken();
        AuthzClient authzClient = getAuthzClient(AUTHZ_CLIENT_CONFIG);
        AuthorizationRequest request = new AuthorizationRequest();

        request.addPermission(null, "scope:view", "scope:update", "scope:delete");

        AuthorizationResponse response = authzClient.authorization(accessToken).authorize(request);
        Assertions.assertNotNull(response.getToken());
        Collection<Permission> permissions = toAccessToken(response.getToken()).getAuthorization().getPermissions();
        Assertions.assertEquals(1, permissions.size());

        for (Permission grantedPermission : permissions) {
            Assertions.assertEquals(resource.getId(), grantedPermission.getResourceId());
            Assertions.assertEquals(3, grantedPermission.getScopes().size());
            Assertions.assertTrue(grantedPermission.getScopes().containsAll(Arrays.asList("scope:view")));
        }

        resource.setScopes(new HashSet<>());
        resource.addScope("scope:view", "scope:update");

        authorization.resources().resource(resource.getId()).update(resource);

        request = new AuthorizationRequest();

        request.addPermission(null, "scope:view", "scope:update", "scope:delete");

        response = authzClient.authorization(accessToken).authorize(request);
        Assertions.assertNotNull(response.getToken());
        permissions = toAccessToken(response.getToken()).getAuthorization().getPermissions();
        Assertions.assertEquals(1, permissions.size());

        for (Permission grantedPermission : permissions) {
            Assertions.assertEquals(resource.getId(), grantedPermission.getResourceId());
            Assertions.assertEquals(2, grantedPermission.getScopes().size());
            Assertions.assertTrue(grantedPermission.getScopes().containsAll(Arrays.asList("scope:view", "scope:update")));
        }

        request = new AuthorizationRequest();

        request.addPermission(resource.getId(), "scope:view", "scope:update", "scope:delete");

        response = authzClient.authorization(accessToken).authorize(request);
        Assertions.assertNotNull(response.getToken());
        permissions = toAccessToken(response.getToken()).getAuthorization().getPermissions();
        Assertions.assertEquals(1, permissions.size());

        for (Permission grantedPermission : permissions) {
            Assertions.assertEquals(resource.getId(), grantedPermission.getResourceId());
            Assertions.assertEquals(2, grantedPermission.getScopes().size());
            Assertions.assertTrue(grantedPermission.getScopes().containsAll(Arrays.asList("scope:view", "scope:update")));
        }
    }

    @Test
    public void testObtainAllEntitlementsForResourceWithScopePermission() throws Exception {
        ClientResource client = getClient(getRealm(), RESOURCE_SERVER_TEST);
        AuthorizationResource authorization = client.authorization();

        JSPolicyRepresentation policy = new JSPolicyRepresentation();

        policy.setName(KeycloakModelUtils.generateId());
        policy.setType("script-scripts/default-policy.js");

        authorization.policies().js().create(policy).close();

        ResourceRepresentation resourceWithoutType = new ResourceRepresentation();

        resourceWithoutType.setName(KeycloakModelUtils.generateId());
        resourceWithoutType.addScope("scope:view", "scope:update", "scope:delete");

        try (Response response = authorization.resources().create(resourceWithoutType)) {
            resourceWithoutType = response.readEntity(ResourceRepresentation.class);
        }

        ResourceRepresentation resourceWithType = new ResourceRepresentation();

        resourceWithType.setName(KeycloakModelUtils.generateId());
        resourceWithType.setType("type-one");
        resourceWithType.addScope("scope:view", "scope:update", "scope:delete");

        try (Response response = authorization.resources().create(resourceWithType)) {
            resourceWithType = response.readEntity(ResourceRepresentation.class);
        }

        ScopePermissionRepresentation permission = new ScopePermissionRepresentation();

        permission.setName(KeycloakModelUtils.generateId());
        permission.addResource(resourceWithoutType.getId());
        permission.addScope("scope:view");
        permission.addPolicy(policy.getName());

        authorization.permissions().scope().create(permission).close();

        permission = new ScopePermissionRepresentation();

        permission.setName(KeycloakModelUtils.generateId());
        permission.setResourceType("type-one");
        permission.addScope("scope:update");
        permission.addPolicy(policy.getName());

        authorization.permissions().scope().create(permission).close();

        String accessToken = oauth.realm("authz-test").clientId(RESOURCE_SERVER_TEST).doGrantAccessTokenRequest("secret", "kolo", "password").getAccessToken();
        AuthzClient authzClient = getAuthzClient(AUTHZ_CLIENT_CONFIG);

        AuthorizationRequest request = new AuthorizationRequest();
        request.addPermission(resourceWithoutType.getId(), "scope:view", "scope:update", "scope:delete");

        AuthorizationResponse response = authzClient.authorization(accessToken).authorize(request);
        Assertions.assertNotNull(response.getToken());
        Collection<Permission> permissions = toAccessToken(response.getToken()).getAuthorization().getPermissions();
        Assertions.assertEquals(1, permissions.size());

        for (Permission grantedPermission : permissions) {
            Assertions.assertEquals(resourceWithoutType.getId(), grantedPermission.getResourceId());
            Assertions.assertEquals(1, grantedPermission.getScopes().size());
            Assertions.assertTrue(grantedPermission.getScopes().containsAll(Arrays.asList("scope:view")));
        }

        request = new AuthorizationRequest();
        request.addPermission(resourceWithType.getId(), "scope:view", "scope:update", "scope:delete");

        response = authzClient.authorization(accessToken).authorize(request);
        Assertions.assertNotNull(response.getToken());
        permissions = toAccessToken(response.getToken()).getAuthorization().getPermissions();
        Assertions.assertEquals(1, permissions.size());

        for (Permission grantedPermission : permissions) {
            Assertions.assertEquals(resourceWithType.getId(), grantedPermission.getResourceId());
            Assertions.assertEquals(1, grantedPermission.getScopes().size());
            Assertions.assertTrue(grantedPermission.getScopes().containsAll(Arrays.asList("scope:update")));
        }
    }

    @Test
    public void testServerDecisionStrategy() throws Exception {
        ClientResource client = getClient(getRealm(), RESOURCE_SERVER_TEST);
        AuthorizationResource authorization = client.authorization();

        ResourceRepresentation resource = new ResourceRepresentation();

        resource.setName(KeycloakModelUtils.generateId());
        resource.addScope("read", "write", "delete");

        try (Response response = authorization.resources().create(resource)) {
            resource = response.readEntity(ResourceRepresentation.class);
        }

        JSPolicyRepresentation grantPolicy = new JSPolicyRepresentation();

        grantPolicy.setName(KeycloakModelUtils.generateId());
        grantPolicy.setType("script-scripts/default-policy.js");

        authorization.policies().js().create(grantPolicy).close();

        JSPolicyRepresentation denyPolicy = new JSPolicyRepresentation();

        denyPolicy.setName(KeycloakModelUtils.generateId());
        denyPolicy.setType("script-scripts/always-deny-policy.js");

        authorization.policies().js().create(denyPolicy).close();

        ResourcePermissionRepresentation resourcePermission = new ResourcePermissionRepresentation();

        resourcePermission.setName(KeycloakModelUtils.generateId());
        resourcePermission.addResource(resource.getId());
        resourcePermission.addPolicy(denyPolicy.getName());

        authorization.permissions().resource().create(resourcePermission).close();

        ScopePermissionRepresentation scopePermission1 = new ScopePermissionRepresentation();

        scopePermission1.setName(KeycloakModelUtils.generateId());
        scopePermission1.addScope("read");
        scopePermission1.addPolicy(grantPolicy.getName());

        ScopePermissionsResource scopePermissions = authorization.permissions().scope();
        scopePermissions.create(scopePermission1).close();

        String accessToken = oauth.realm("authz-test").clientId(RESOURCE_SERVER_TEST).doGrantAccessTokenRequest("secret", "kolo", "password").getAccessToken();
        AuthzClient authzClient = getAuthzClient(AUTHZ_CLIENT_CONFIG);
        AuthorizationRequest request = new AuthorizationRequest();

        request.addPermission(resource.getName());

        try {
            authzClient.authorization(accessToken).authorize(request);
            Assertions.fail("kolo can not access the resource");
        } catch (RuntimeException expected) {
            Assertions.assertEquals(403, HttpResponseException.class.cast(expected.getCause()).getStatusCode());
            Assertions.assertTrue(HttpResponseException.class.cast(expected.getCause()).toString().contains("access_denied"));
        }

        ResourceServerRepresentation settings = authorization.getSettings();

        settings.setDecisionStrategy(DecisionStrategy.AFFIRMATIVE);

        authorization.update(settings);

        assertPermissions(authzClient, accessToken, request, resource, "read");

        scopePermission1 = scopePermissions.findByName(scopePermission1.getName());

        scopePermission1.addScope("read", "delete");

        scopePermissions.findById(scopePermission1.getId()).update(scopePermission1);

        assertPermissions(authzClient, accessToken, request, resource, "read", "delete");

        ScopePermissionRepresentation scopePermission2 = new ScopePermissionRepresentation();

        scopePermission2.setName(KeycloakModelUtils.generateId());
        scopePermission2.addScope("write");
        scopePermission2.addPolicy(grantPolicy.getName());

        scopePermissions.create(scopePermission2).close();

        assertPermissions(authzClient, accessToken, request, resource, "read", "delete", "write");

        ScopePermissionRepresentation scopePermission3 = new ScopePermissionRepresentation();

        scopePermission3.setName(KeycloakModelUtils.generateId());
        scopePermission3.addResource(resource.getId());
        scopePermission3.addScope("write", "read", "delete");
        scopePermission3.addPolicy(grantPolicy.getName());

        scopePermissions.create(scopePermission3).close();

        assertPermissions(authzClient, accessToken, request, resource, "read", "delete", "write");

        scopePermission2 = scopePermissions.findByName(scopePermission2.getName());
        scopePermissions.findById(scopePermission2.getId()).remove();

        assertPermissions(authzClient, accessToken, request, resource, "read", "delete", "write");

        scopePermission1 = scopePermissions.findByName(scopePermission1.getName());
        scopePermissions.findById(scopePermission1.getId()).remove();

        assertPermissions(authzClient, accessToken, request, resource, "read", "delete", "write");

        scopePermission3 = scopePermissions.findByName(scopePermission3.getName());

        scopePermission3.addScope("write", "delete");
        scopePermissions.findById(scopePermission3.getId()).update(scopePermission3);

        assertPermissions(authzClient, accessToken, request, resource, "delete", "write");

        scopePermissions.findById(scopePermission3.getId()).remove();

        try {
            authzClient.authorization(accessToken).authorize(request);
            Assertions.fail("kolo can not access the resource");
        } catch (RuntimeException expected) {
            Assertions.assertEquals(403, HttpResponseException.class.cast(expected.getCause()).getStatusCode());
            Assertions.assertTrue(HttpResponseException.class.cast(expected.getCause()).toString().contains("access_denied"));
        }

        ResourcePermissionRepresentation grantResourcePermission = new ResourcePermissionRepresentation();

        grantResourcePermission.setName(KeycloakModelUtils.generateId());
        grantResourcePermission.addResource(resource.getId());
        grantResourcePermission.addPolicy(grantPolicy.getName());

        authorization.permissions().resource().create(grantResourcePermission).close();

        assertPermissions(authzClient, accessToken, request, resource, "read", "delete", "write");

        settings.setDecisionStrategy(DecisionStrategy.UNANIMOUS);
        authorization.update(settings);

        try {
            authzClient.authorization(accessToken).authorize(request);
            Assertions.fail("kolo can not access the resource");
        } catch (RuntimeException expected) {
            Assertions.assertEquals(403, HttpResponseException.class.cast(expected.getCause()).getStatusCode());
            Assertions.assertTrue(HttpResponseException.class.cast(expected.getCause()).toString().contains("access_denied"));
        }
    }

    @Test
    public void testObtainAllEntitlementsForResourceType() throws Exception {
        ClientResource client = getClient(getRealm(), RESOURCE_SERVER_TEST);
        AuthorizationResource authorization = client.authorization();

        JSPolicyRepresentation policy = new JSPolicyRepresentation();

        policy.setName(KeycloakModelUtils.generateId());
        policy.setType("script-scripts/default-policy.js");

        authorization.policies().js().create(policy).close();

        for (int i = 0; i < 10; i++) {
            ResourceRepresentation resource = new ResourceRepresentation();

            resource.setType("type-one");
            resource.setName(KeycloakModelUtils.generateId());

            authorization.resources().create(resource).close();
        }

        for (int i = 0; i < 10; i++) {
            ResourceRepresentation resource = new ResourceRepresentation();

            resource.setType("type-two");
            resource.setName(KeycloakModelUtils.generateId());

            authorization.resources().create(resource).close();
        }

        for (int i = 0; i < 10; i++) {
            ResourceRepresentation resource = new ResourceRepresentation();

            resource.setType("type-three");
            resource.setName(KeycloakModelUtils.generateId());

            authorization.resources().create(resource).close();
        }

        for (int i = 0; i < 10; i++) {
            ResourceRepresentation resource = new ResourceRepresentation();

            resource.setType("type-four");
            resource.setName(KeycloakModelUtils.generateId());
            resource.addScope("scope:view", "scope:update");

            authorization.resources().create(resource).close();
        }

        for (int i = 0; i < 10; i++) {
            ResourceRepresentation resource = new ResourceRepresentation();

            resource.setType("type-five");
            resource.setName(KeycloakModelUtils.generateId());
            resource.addScope("scope:view");

            authorization.resources().create(resource).close();
        }


        ResourcePermissionRepresentation resourcePermission = new ResourcePermissionRepresentation();

        resourcePermission.setName(KeycloakModelUtils.generateId());
        resourcePermission.setResourceType("type-one");
        resourcePermission.addPolicy(policy.getName());

        authorization.permissions().resource().create(resourcePermission).close();

        resourcePermission = new ResourcePermissionRepresentation();

        resourcePermission.setName(KeycloakModelUtils.generateId());
        resourcePermission.setResourceType("type-two");
        resourcePermission.addPolicy(policy.getName());

        authorization.permissions().resource().create(resourcePermission).close();

        resourcePermission = new ResourcePermissionRepresentation();

        resourcePermission.setName(KeycloakModelUtils.generateId());
        resourcePermission.setResourceType("type-three");
        resourcePermission.addPolicy(policy.getName());

        authorization.permissions().resource().create(resourcePermission).close();

        ScopePermissionRepresentation scopePersmission = new ScopePermissionRepresentation();

        scopePersmission.setName(KeycloakModelUtils.generateId());
        scopePersmission.setResourceType("type-four");
        scopePersmission.addScope("scope:view");
        scopePersmission.addPolicy(policy.getName());

        authorization.permissions().scope().create(scopePersmission).close();

        String accessToken = oauth.realm("authz-test").clientId(RESOURCE_SERVER_TEST).doGrantAccessTokenRequest("secret", "kolo", "password").getAccessToken();
        AuthzClient authzClient = getAuthzClient(AUTHZ_CLIENT_CONFIG);

        AuthorizationRequest request = new AuthorizationRequest();
        request.addPermission("resource-type:type-one");
        AuthorizationResponse response = authzClient.authorization(accessToken).authorize(request);
        Assertions.assertNotNull(response.getToken());
        Collection<Permission> permissions = toAccessToken(response.getToken()).getAuthorization().getPermissions();
        Assertions.assertEquals(10, permissions.size());

        request = new AuthorizationRequest();
        request.addPermission("resource-type:type-three");
        response = authzClient.authorization(accessToken).authorize(request);
        Assertions.assertNotNull(response.getToken());
        permissions = toAccessToken(response.getToken()).getAuthorization().getPermissions();
        Assertions.assertEquals(10, permissions.size());

        request = new AuthorizationRequest();
        request.addPermission("resource-type:type-four", "scope:view");
        response = authzClient.authorization(accessToken).authorize(request);
        Assertions.assertNotNull(response.getToken());
        permissions = toAccessToken(response.getToken()).getAuthorization().getPermissions();
        Assertions.assertEquals(10, permissions.size());
        for (Permission grantedPermission : permissions) {
            Assertions.assertEquals(1, grantedPermission.getScopes().size());
            Assertions.assertTrue(grantedPermission.getScopes().containsAll(Arrays.asList("scope:view")));
        }

        request = new AuthorizationRequest();
        request.addPermission("resource-type:type-five", "scope:view");
        try {
            authzClient.authorization(accessToken).authorize(request);
            Assertions.fail("no type-five resources can be granted since scope permission for scope:view only applies to type-four");
        } catch (RuntimeException expected) {
            Assertions.assertEquals(403, HttpResponseException.class.cast(expected.getCause()).getStatusCode());
            Assertions.assertTrue(HttpResponseException.class.cast(expected.getCause()).toString().contains("access_denied"));
        }

        for (int i = 0; i < 5; i++) {
            ResourceRepresentation resource = new ResourceRepresentation();

            resource.setOwner("kolo");
            resource.setType("type-two");
            resource.setName(KeycloakModelUtils.generateId());

            authorization.resources().create(resource).close();
        }

        request = new AuthorizationRequest();
        request.addPermission("resource-type-any:type-two");
        response = authzClient.authorization(accessToken).authorize(request);
        Assertions.assertNotNull(response.getToken());
        permissions = toAccessToken(response.getToken()).getAuthorization().getPermissions();
        Assertions.assertEquals(15, permissions.size());

        request = new AuthorizationRequest();
        request.addPermission("resource-type-owner:type-two");
        response = authzClient.authorization(accessToken).authorize(request);
        Assertions.assertNotNull(response.getToken());
        permissions = toAccessToken(response.getToken()).getAuthorization().getPermissions();
        Assertions.assertEquals(5, permissions.size());

        request = new AuthorizationRequest();
        request.addPermission("resource-type-instance:type-two");
        response = authzClient.authorization(accessToken).authorize(request);
        Assertions.assertNotNull(response.getToken());
        permissions = toAccessToken(response.getToken()).getAuthorization().getPermissions();
        Assertions.assertEquals(5, permissions.size());

        Permission next = permissions.iterator().next();

        ResourceResource resourceMgmt = client.authorization().resources().resource(next.getResourceId());
        ResourceRepresentation representation = resourceMgmt.toRepresentation();

        representation.setType("type-three");

        resourceMgmt.update(representation);

        request = new AuthorizationRequest();
        request.addPermission("resource-type-instance:type-two");
        response = authzClient.authorization(accessToken).authorize(request);
        Assertions.assertNotNull(response.getToken());
        permissions = toAccessToken(response.getToken()).getAuthorization().getPermissions();
        Assertions.assertEquals(4, permissions.size());

        request = new AuthorizationRequest();
        request.addPermission("resource-type-instance:type-three");
        response = authzClient.authorization(accessToken).authorize(request);
        Assertions.assertNotNull(response.getToken());
        permissions = toAccessToken(response.getToken()).getAuthorization().getPermissions();
        Assertions.assertEquals(1, permissions.size());

        request = new AuthorizationRequest();
        request.addPermission("resource-type-any:type-three");
        response = authzClient.authorization(accessToken).authorize(request);
        Assertions.assertNotNull(response.getToken());
        permissions = toAccessToken(response.getToken()).getAuthorization().getPermissions();
        Assertions.assertEquals(11, permissions.size());

        for (int i = 0; i < 2; i++) {
            ResourceRepresentation resource = new ResourceRepresentation();

            resource.setOwner("marta");
            resource.setType("type-one");
            resource.setName(KeycloakModelUtils.generateId());

            authorization.resources().create(resource).close();
        }

        request = new AuthorizationRequest();
        request.addPermission("resource-type:type-one");
        response = authzClient.authorization(accessToken).authorize(request);
        Assertions.assertNotNull(response.getToken());
        permissions = toAccessToken(response.getToken()).getAuthorization().getPermissions();
        Assertions.assertEquals(10, permissions.size());

        accessToken = oauth.realm("authz-test").clientId(RESOURCE_SERVER_TEST).doGrantAccessTokenRequest("secret", "marta", "password").getAccessToken();

        request = new AuthorizationRequest();
        request.addPermission("resource-type-owner:type-one");
        response = authzClient.authorization(accessToken).authorize(request);
        Assertions.assertNotNull(response.getToken());
        permissions = toAccessToken(response.getToken()).getAuthorization().getPermissions();
        Assertions.assertEquals(2, permissions.size());

        request = new AuthorizationRequest();
        request.addPermission("resource-type-instance:type-one");
        response = authzClient.authorization(accessToken).authorize(request);
        Assertions.assertNotNull(response.getToken());
        permissions = toAccessToken(response.getToken()).getAuthorization().getPermissions();
        Assertions.assertEquals(2, permissions.size());

        request = new AuthorizationRequest();
        request.addPermission("resource-type-any:type-one");
        response = authzClient.authorization(accessToken).authorize(request);
        Assertions.assertNotNull(response.getToken());
        permissions = toAccessToken(response.getToken()).getAuthorization().getPermissions();
        Assertions.assertEquals(12, permissions.size());
    }

    @Test
    public void testOverridePermission() throws Exception {
        ClientResource client = getClient(getRealm(), RESOURCE_SERVER_TEST);
        AuthorizationResource authorization = client.authorization();
        JSPolicyRepresentation onlyOwnerPolicy = createOnlyOwnerPolicy();

        authorization.policies().js().create(onlyOwnerPolicy).close();

        ResourceRepresentation typedResource = new ResourceRepresentation();

        typedResource.setType("resource");
        typedResource.setName(KeycloakModelUtils.generateId());
        typedResource.addScope("read", "update");

        try (Response response = authorization.resources().create(typedResource)) {
            typedResource = response.readEntity(ResourceRepresentation.class);
        }

        ResourcePermissionRepresentation typedResourcePermission = new ResourcePermissionRepresentation();

        typedResourcePermission.setName(KeycloakModelUtils.generateId());
        typedResourcePermission.setResourceType("resource");
        typedResourcePermission.addPolicy(onlyOwnerPolicy.getName());

        try (Response response = authorization.permissions().resource().create(typedResourcePermission)) {
            typedResourcePermission = response.readEntity(ResourcePermissionRepresentation.class);
        }

        ResourceRepresentation martaResource = new ResourceRepresentation();

        martaResource.setType("resource");
        martaResource.setName(KeycloakModelUtils.generateId());
        martaResource.addScope("read", "update");
        martaResource.setOwner("marta");

        try (Response response = authorization.resources().create(martaResource)) {
            martaResource = response.readEntity(ResourceRepresentation.class);
        }

        String accessToken = oauth.realm("authz-test").clientId(RESOURCE_SERVER_TEST).doGrantAccessTokenRequest("secret", "marta", "password").getAccessToken();
        AuthzClient authzClient = getAuthzClient(AUTHZ_CLIENT_CONFIG);
        AuthorizationRequest request = new AuthorizationRequest();

        request.addPermission(martaResource.getName());

        // marta can access her resource
        AuthorizationResponse response = authzClient.authorization(accessToken).authorize(request);
        Assertions.assertNotNull(response.getToken());
        Collection<Permission> permissions = toAccessToken(response.getToken()).getAuthorization().getPermissions();
        Assertions.assertEquals(1, permissions.size());

        for (Permission grantedPermission : permissions) {
            Assertions.assertEquals(martaResource.getName(), grantedPermission.getResourceName());
            Set<String> scopes = grantedPermission.getScopes();
            Assertions.assertEquals(2, scopes.size());
            MatcherAssert.assertThat(scopes, Matchers.containsInAnyOrder("read", "update"));
        }

        accessToken = oauth.realm("authz-test").clientId(RESOURCE_SERVER_TEST).doGrantAccessTokenRequest("secret", "kolo", "password").getAccessToken();
        authzClient = getAuthzClient(AUTHZ_CLIENT_CONFIG);

        request = new AuthorizationRequest();

        request.addPermission(martaResource.getId());

        try {
            authzClient.authorization(accessToken).authorize(request);
            Assertions.fail("kolo can not access marta resource");
        } catch (RuntimeException expected) {
            Assertions.assertEquals(403, HttpResponseException.class.cast(expected.getCause()).getStatusCode());
            Assertions.assertTrue(HttpResponseException.class.cast(expected.getCause()).toString().contains("access_denied"));
        }

        UserPolicyRepresentation onlyKoloPolicy = new UserPolicyRepresentation();

        onlyKoloPolicy.setName(KeycloakModelUtils.generateId());
        onlyKoloPolicy.addUser("kolo");

        authorization.policies().user().create(onlyKoloPolicy).close();

        ResourcePermissionRepresentation martaResourcePermission = new ResourcePermissionRepresentation();

        martaResourcePermission.setName(KeycloakModelUtils.generateId());
        martaResourcePermission.addResource(martaResource.getId());
        martaResourcePermission.addPolicy(onlyKoloPolicy.getName());

        try (Response response1 = authorization.permissions().resource().create(martaResourcePermission)) {
            martaResourcePermission = response1.readEntity(ResourcePermissionRepresentation.class);
        }

        response = authzClient.authorization(accessToken).authorize(request);
        Assertions.assertNotNull(response.getToken());
        permissions = toAccessToken(response.getToken()).getAuthorization().getPermissions();
        Assertions.assertEquals(1, permissions.size());

        for (Permission grantedPermission : permissions) {
            Assertions.assertEquals(martaResource.getName(), grantedPermission.getResourceName());
            Set<String> scopes = grantedPermission.getScopes();
            Assertions.assertEquals(2, scopes.size());
            MatcherAssert.assertThat(scopes, Matchers.containsInAnyOrder("read", "update"));
        }

        typedResourcePermission.setResourceType(null);
        typedResourcePermission.addResource(typedResource.getName());

        authorization.permissions().resource().findById(typedResourcePermission.getId()).update(typedResourcePermission);

        // now kolo can access marta's resources, last permission is overriding policies from typed resource
        response = authzClient.authorization(accessToken).authorize(request);
        Assertions.assertNotNull(response.getToken());
        permissions = toAccessToken(response.getToken()).getAuthorization().getPermissions();
        Assertions.assertEquals(1, permissions.size());

        for (Permission grantedPermission : permissions) {
            Assertions.assertEquals(martaResource.getName(), grantedPermission.getResourceName());
            Set<String> scopes = grantedPermission.getScopes();
            Assertions.assertEquals(2, scopes.size());
            MatcherAssert.assertThat(scopes, Matchers.containsInAnyOrder("read", "update"));
        }

        ScopePermissionRepresentation martaResourceUpdatePermission = new ScopePermissionRepresentation();

        martaResourceUpdatePermission.setName(KeycloakModelUtils.generateId());
        martaResourceUpdatePermission.addResource(martaResource.getId());
        martaResourceUpdatePermission.addScope("update");
        martaResourceUpdatePermission.addPolicy(onlyOwnerPolicy.getName());

        try (Response response1 = authorization.permissions().scope().create(martaResourceUpdatePermission)) {
            martaResourceUpdatePermission = response1.readEntity(ScopePermissionRepresentation.class);
        }

        // now kolo can only read, but not update
        response = authzClient.authorization(accessToken).authorize(request);
        Assertions.assertNotNull(response.getToken());
        permissions = toAccessToken(response.getToken()).getAuthorization().getPermissions();
        Assertions.assertEquals(1, permissions.size());

        for (Permission grantedPermission : permissions) {
            Assertions.assertEquals(martaResource.getName(), grantedPermission.getResourceName());
            Set<String> scopes = grantedPermission.getScopes();
            Assertions.assertEquals(1, scopes.size());
            MatcherAssert.assertThat(scopes, Matchers.containsInAnyOrder("read"));
        }

        authorization.permissions().resource().findById(martaResourcePermission.getId()).remove();

        try {
            // after removing permission to marta resource, kolo can not access any scope in the resource
            authzClient.authorization(accessToken).authorize(request);
            Assertions.fail("kolo can not access marta resource");
        } catch (RuntimeException expected) {
            Assertions.assertEquals(403, HttpResponseException.class.cast(expected.getCause()).getStatusCode());
            Assertions.assertTrue(HttpResponseException.class.cast(expected.getCause()).toString().contains("access_denied"));
        }

        martaResourceUpdatePermission.addPolicy(onlyKoloPolicy.getName());
        martaResourceUpdatePermission.setDecisionStrategy(DecisionStrategy.AFFIRMATIVE);

        authorization.permissions().scope().findById(martaResourceUpdatePermission.getId()).update(martaResourceUpdatePermission);

        // now kolo can access because update permission changed to allow him to access the resource using an affirmative strategy
        response = authzClient.authorization(accessToken).authorize(request);
        Assertions.assertNotNull(response.getToken());
        permissions = toAccessToken(response.getToken()).getAuthorization().getPermissions();
        Assertions.assertEquals(1, permissions.size());

        for (Permission grantedPermission : permissions) {
            Assertions.assertEquals(martaResource.getName(), grantedPermission.getResourceName());
            Set<String> scopes = grantedPermission.getScopes();
            Assertions.assertEquals(1, scopes.size());
            MatcherAssert.assertThat(scopes, Matchers.containsInAnyOrder("update"));
        }

        accessToken = oauth.realm("authz-test").clientId(RESOURCE_SERVER_TEST).doGrantAccessTokenRequest("secret", "marta", "password").getAccessToken();

        // marta can still access her resource
        response = authzClient.authorization(accessToken).authorize(request);
        Assertions.assertNotNull(response.getToken());
        permissions = toAccessToken(response.getToken()).getAuthorization().getPermissions();
        Assertions.assertEquals(1, permissions.size());

        for (Permission grantedPermission : permissions) {
            Assertions.assertEquals(martaResource.getName(), grantedPermission.getResourceName());
            Set<String> scopes = grantedPermission.getScopes();
            Assertions.assertEquals(2, scopes.size());
            MatcherAssert.assertThat(scopes, Matchers.containsInAnyOrder("update", "read"));
        }

        authorization.permissions().scope().findById(martaResourceUpdatePermission.getId()).remove();
        accessToken = oauth.realm("authz-test").clientId(RESOURCE_SERVER_TEST).doGrantAccessTokenRequest("secret", "kolo", "password").getAccessToken();

        try {
            // back to original setup, permissions not granted by the type resource
            authzClient.authorization(accessToken).authorize(request);
            Assertions.fail("kolo can not access marta resource");
        } catch (RuntimeException expected) {
            Assertions.assertEquals(403, HttpResponseException.class.cast(expected.getCause()).getStatusCode());
            Assertions.assertTrue(HttpResponseException.class.cast(expected.getCause()).toString().contains("access_denied"));
        }
    }

    @Test
    public void testOverrideParentScopePermission() throws Exception {
        ClientResource client = getClient(getRealm(), RESOURCE_SERVER_TEST);
        AuthorizationResource authorization = client.authorization();
        JSPolicyRepresentation onlyOwnerPolicy = createOnlyOwnerPolicy();

        authorization.policies().js().create(onlyOwnerPolicy).close();

        ResourceRepresentation typedResource = new ResourceRepresentation();

        typedResource.setType("resource");
        typedResource.setName(KeycloakModelUtils.generateId());
        typedResource.addScope("read", "update");

        try (Response response = authorization.resources().create(typedResource)) {
            typedResource = response.readEntity(ResourceRepresentation.class);
        }

        ScopePermissionRepresentation typedResourcePermission = new ScopePermissionRepresentation();

        typedResourcePermission.setName(KeycloakModelUtils.generateId());
        typedResourcePermission.addResource(typedResource.getName());
        typedResourcePermission.addPolicy(onlyOwnerPolicy.getName());
        typedResourcePermission.addScope("read", "update");

        authorization.permissions().scope().create(typedResourcePermission).close();

        ResourceRepresentation martaResource = new ResourceRepresentation();

        martaResource.setType("resource");
        martaResource.setName(KeycloakModelUtils.generateId());
        martaResource.addScope("read");
        martaResource.setOwner("marta");

        try (Response response = authorization.resources().create(martaResource)) {
            martaResource = response.readEntity(ResourceRepresentation.class);
        }

        String accessToken = oauth.realm("authz-test").clientId(RESOURCE_SERVER_TEST).doGrantAccessTokenRequest("secret", "marta", "password").getAccessToken();
        AuthzClient authzClient = getAuthzClient(AUTHZ_CLIENT_CONFIG);
        AuthorizationRequest request = new AuthorizationRequest();

        request.addPermission(martaResource.getName());

        // marta can access her resource
        AuthorizationResponse response = authzClient.authorization(accessToken).authorize(request);
        Assertions.assertNotNull(response.getToken());
        Collection<Permission> permissions = toAccessToken(response.getToken()).getAuthorization().getPermissions();
        Assertions.assertEquals(1, permissions.size());

        for (Permission grantedPermission : permissions) {
            Assertions.assertEquals(martaResource.getName(), grantedPermission.getResourceName());
            Set<String> scopes = grantedPermission.getScopes();
            Assertions.assertEquals(2, scopes.size());
            MatcherAssert.assertThat(scopes, Matchers.containsInAnyOrder("read", "update"));
        }

        accessToken = oauth.realm("authz-test").clientId(RESOURCE_SERVER_TEST).doGrantAccessTokenRequest("secret", "kolo", "password").getAccessToken();
        authzClient = getAuthzClient(AUTHZ_CLIENT_CONFIG);

        request = new AuthorizationRequest();

        request.addPermission(martaResource.getId());

        try {
            authzClient.authorization(accessToken).authorize(request);
            Assertions.fail("kolo can not access marta resource");
        } catch (RuntimeException expected) {
            Assertions.assertEquals(403, HttpResponseException.class.cast(expected.getCause()).getStatusCode());
            Assertions.assertTrue(HttpResponseException.class.cast(expected.getCause()).toString().contains("access_denied"));
        }

        UserPolicyRepresentation onlyKoloPolicy = new UserPolicyRepresentation();

        onlyKoloPolicy.setName(KeycloakModelUtils.generateId());
        onlyKoloPolicy.addUser("kolo");

        authorization.policies().user().create(onlyKoloPolicy).close();

        ResourcePermissionRepresentation martaResourcePermission = new ResourcePermissionRepresentation();

        martaResourcePermission.setName(KeycloakModelUtils.generateId());
        martaResourcePermission.addResource(martaResource.getId());
        martaResourcePermission.addPolicy(onlyKoloPolicy.getName());

        try (Response response1 = authorization.permissions().resource().create(martaResourcePermission)) {
            martaResourcePermission = response1.readEntity(ResourcePermissionRepresentation.class);
        }

        response = authzClient.authorization(accessToken).authorize(request);
        Assertions.assertNotNull(response.getToken());
        permissions = toAccessToken(response.getToken()).getAuthorization().getPermissions();
        Assertions.assertEquals(1, permissions.size());

        for (Permission grantedPermission : permissions) {
            Assertions.assertEquals(martaResource.getName(), grantedPermission.getResourceName());
            Set<String> scopes = grantedPermission.getScopes();
            Assertions.assertEquals(2, scopes.size());
            MatcherAssert.assertThat(scopes, Matchers.containsInAnyOrder("read", "update"));
        }

        ScopePermissionRepresentation martaResourceUpdatePermission = new ScopePermissionRepresentation();

        martaResourceUpdatePermission.setName(KeycloakModelUtils.generateId());
        martaResourceUpdatePermission.addResource(martaResource.getId());
        martaResourceUpdatePermission.addScope("update");
        martaResourceUpdatePermission.addPolicy(onlyOwnerPolicy.getName());

        try (Response response1 = authorization.permissions().scope().create(martaResourceUpdatePermission)) {
            martaResourceUpdatePermission = response1.readEntity(ScopePermissionRepresentation.class);
        }

        // now kolo can only read, but not update
        response = authzClient.authorization(accessToken).authorize(request);
        Assertions.assertNotNull(response.getToken());
        permissions = toAccessToken(response.getToken()).getAuthorization().getPermissions();
        Assertions.assertEquals(1, permissions.size());

        for (Permission grantedPermission : permissions) {
            Assertions.assertEquals(martaResource.getName(), grantedPermission.getResourceName());
            Set<String> scopes = grantedPermission.getScopes();
            Assertions.assertEquals(1, scopes.size());
            MatcherAssert.assertThat(scopes, Matchers.containsInAnyOrder("read"));
        }

        authorization.permissions().resource().findById(martaResourcePermission.getId()).remove();

        try {
            // after removing permission to marta resource, kolo can not access any scope in the resource
            authzClient.authorization(accessToken).authorize(request);
            Assertions.fail("kolo can not access marta resource");
        } catch (RuntimeException expected) {
            Assertions.assertEquals(403, HttpResponseException.class.cast(expected.getCause()).getStatusCode());
            Assertions.assertTrue(HttpResponseException.class.cast(expected.getCause()).toString().contains("access_denied"));
        }

        martaResourceUpdatePermission.addPolicy(onlyKoloPolicy.getName());
        martaResourceUpdatePermission.setDecisionStrategy(DecisionStrategy.AFFIRMATIVE);

        authorization.permissions().scope().findById(martaResourceUpdatePermission.getId()).update(martaResourceUpdatePermission);

        // now kolo can access because update permission changed to allow him to access the resource using an affirmative strategy
        response = authzClient.authorization(accessToken).authorize(request);
        Assertions.assertNotNull(response.getToken());
        permissions = toAccessToken(response.getToken()).getAuthorization().getPermissions();
        Assertions.assertEquals(1, permissions.size());

        for (Permission grantedPermission : permissions) {
            Assertions.assertEquals(martaResource.getName(), grantedPermission.getResourceName());
            Set<String> scopes = grantedPermission.getScopes();
            Assertions.assertEquals(1, scopes.size());
            MatcherAssert.assertThat(scopes, Matchers.containsInAnyOrder("update"));
        }

        accessToken = oauth.realm("authz-test").clientId(RESOURCE_SERVER_TEST).doGrantAccessTokenRequest("secret", "marta", "password").getAccessToken();

        // marta can still access her resource
        response = authzClient.authorization(accessToken).authorize(request);
        Assertions.assertNotNull(response.getToken());
        permissions = toAccessToken(response.getToken()).getAuthorization().getPermissions();
        Assertions.assertEquals(1, permissions.size());

        for (Permission grantedPermission : permissions) {
            Assertions.assertEquals(martaResource.getName(), grantedPermission.getResourceName());
            Set<String> scopes = grantedPermission.getScopes();
            Assertions.assertEquals(2, scopes.size());
            MatcherAssert.assertThat(scopes, Matchers.containsInAnyOrder("update", "read"));
        }

        authorization.permissions().scope().findById(martaResourceUpdatePermission.getId()).remove();
        accessToken = oauth.realm("authz-test").clientId(RESOURCE_SERVER_TEST).doGrantAccessTokenRequest("secret", "kolo", "password").getAccessToken();

        try {
            // back to original setup, permissions not granted by the type resource
            authzClient.authorization(accessToken).authorize(request);
            Assertions.fail("kolo can not access marta resource");
        } catch (RuntimeException expected) {
            Assertions.assertEquals(403, HttpResponseException.class.cast(expected.getCause()).getStatusCode());
            Assertions.assertTrue(HttpResponseException.class.cast(expected.getCause()).toString().contains("access_denied"));
        }
    }

    private JSPolicyRepresentation createOnlyOwnerPolicy() {
        JSPolicyRepresentation onlyOwnerPolicy = new JSPolicyRepresentation();

        onlyOwnerPolicy.setName(KeycloakModelUtils.generateId());
        onlyOwnerPolicy.setType("script-scripts/only-owner-policy.js");

        return onlyOwnerPolicy;
    }

    @Test
    public void testPermissionsWithResourceAttributes() throws Exception {
        ClientResource client = getClient(getRealm(), RESOURCE_SERVER_TEST);
        AuthorizationResource authorization = client.authorization();
        JSPolicyRepresentation onlyPublicResourcesPolicy = new JSPolicyRepresentation();

        onlyPublicResourcesPolicy.setName(KeycloakModelUtils.generateId());
        onlyPublicResourcesPolicy.setType("script-scripts/resource-visibility-attribute-policy.js");

        authorization.policies().js().create(onlyPublicResourcesPolicy).close();

        JSPolicyRepresentation onlyOwnerPolicy = createOnlyOwnerPolicy();

        authorization.policies().js().create(onlyOwnerPolicy).close();

        ResourceRepresentation typedResource = new ResourceRepresentation();

        typedResource.setType("resource");
        typedResource.setName(KeycloakModelUtils.generateId());

        try (Response response = authorization.resources().create(typedResource)) {
            typedResource = response.readEntity(ResourceRepresentation.class);
        }

        ResourceRepresentation userResource = new ResourceRepresentation();

        userResource.setName(KeycloakModelUtils.generateId());
        userResource.setType("resource");
        userResource.setOwner("marta");
        Map<String, List<String>> attributes = new HashMap<>();
        attributes.put("visibility", Arrays.asList("private"));
        userResource.setAttributes(attributes);

        try (Response response = authorization.resources().create(userResource)) {
            userResource = response.readEntity(ResourceRepresentation.class);
        }

        ResourcePermissionRepresentation typedResourcePermission = new ResourcePermissionRepresentation();

        typedResourcePermission.setName(KeycloakModelUtils.generateId());
        typedResourcePermission.setResourceType("resource");
        typedResourcePermission.addPolicy(onlyPublicResourcesPolicy.getName());

        try (Response response = authorization.permissions().resource().create(typedResourcePermission)) {
            typedResourcePermission = response.readEntity(ResourcePermissionRepresentation.class);
        }

        // marta can access any public resource
        AuthzClient authzClient = getAuthzClient(AUTHZ_CLIENT_CONFIG);
        AuthorizationRequest request = new AuthorizationRequest();

        request.addPermission(typedResource.getId());
        request.addPermission(userResource.getId());

        AuthorizationResponse response = authzClient.authorization("marta", "password").authorize(request);
        Assertions.assertNotNull(response.getToken());
        Collection<Permission> permissions = toAccessToken(response.getToken()).getAuthorization().getPermissions();
        Assertions.assertEquals(1, permissions.size());

        for (Permission grantedPermission : permissions) {
            Assertions.assertEquals(typedResource.getName(), grantedPermission.getResourceName());
        }

        typedResourcePermission.addPolicy(onlyOwnerPolicy.getName());
        typedResourcePermission.setDecisionStrategy(DecisionStrategy.AFFIRMATIVE);

        authorization.permissions().resource().findById(typedResourcePermission.getId()).update(typedResourcePermission);

        response = authzClient.authorization("marta", "password").authorize(request);
        Assertions.assertNotNull(response.getToken());
        permissions = toAccessToken(response.getToken()).getAuthorization().getPermissions();
        Assertions.assertEquals(2, permissions.size());

        for (Permission grantedPermission : permissions) {
            MatcherAssert.assertThat(Arrays.asList(typedResource.getName(), userResource.getName()), Matchers.hasItem(grantedPermission.getResourceName()));
        }

        typedResource.setAttributes(attributes);

        authorization.resources().resource(typedResource.getId()).update(typedResource);

        response = authzClient.authorization("marta", "password").authorize(request);
        Assertions.assertNotNull(response.getToken());
        permissions = toAccessToken(response.getToken()).getAuthorization().getPermissions();
        Assertions.assertEquals(1, permissions.size());

        for (Permission grantedPermission : permissions) {
            MatcherAssert.assertThat(userResource.getName(), Matchers.equalTo(grantedPermission.getResourceName()));
        }

        userResource.addScope("create", "read");
        authorization.resources().resource(userResource.getId()).update(userResource);

        typedResource.addScope("create", "read");
        authorization.resources().resource(typedResource.getId()).update(typedResource);

        ScopePermissionRepresentation createPermission = new ScopePermissionRepresentation();

        createPermission.setName(KeycloakModelUtils.generateId());
        createPermission.addScope("create");
        createPermission.addPolicy(onlyPublicResourcesPolicy.getName());

        authorization.permissions().scope().create(createPermission).close();

        response = authzClient.authorization("marta", "password").authorize(request);
        Assertions.assertNotNull(response.getToken());
        permissions = toAccessToken(response.getToken()).getAuthorization().getPermissions();
        Assertions.assertEquals(1, permissions.size());

        for (Permission grantedPermission : permissions) {
            MatcherAssert.assertThat(userResource.getName(), Matchers.equalTo(grantedPermission.getResourceName()));
            MatcherAssert.assertThat(grantedPermission.getScopes(), Matchers.not(Matchers.hasItem("create")));
        }

        typedResource.setAttributes(new HashMap<>());

        authorization.resources().resource(typedResource.getId()).update(typedResource);

        response = authzClient.authorization("marta", "password").authorize();
        Assertions.assertNotNull(response.getToken());
        permissions = toAccessToken(response.getToken()).getAuthorization().getPermissions();

        for (Permission grantedPermission : permissions) {
            if (grantedPermission.getResourceName().equals(userResource.getName())) {
                MatcherAssert.assertThat(grantedPermission.getScopes(), Matchers.not(Matchers.hasItem("create")));
            } else if (grantedPermission.getResourceName().equals(typedResource.getName())) {
                MatcherAssert.assertThat(grantedPermission.getScopes(), Matchers.containsInAnyOrder("create", "read"));
            }
        }

        request = new AuthorizationRequest();

        request.addPermission(typedResource.getId());
        request.addPermission(userResource.getId());

        response = authzClient.authorization("marta", "password").authorize(request);
        Assertions.assertNotNull(response.getToken());
        permissions = toAccessToken(response.getToken()).getAuthorization().getPermissions();

        for (Permission grantedPermission : permissions) {
            if (grantedPermission.getResourceName().equals(userResource.getName())) {
                MatcherAssert.assertThat(grantedPermission.getScopes(), Matchers.not(Matchers.hasItem("create")));
            } else if (grantedPermission.getResourceName().equals(typedResource.getName())) {
                MatcherAssert.assertThat(grantedPermission.getScopes(), Matchers.containsInAnyOrder("create", "read"));
            }
        }

        request = new AuthorizationRequest();

        request.addPermission(userResource.getId());
        request.addPermission(typedResource.getId());

        response = authzClient.authorization("marta", "password").authorize(request);
        Assertions.assertNotNull(response.getToken());
        permissions = toAccessToken(response.getToken()).getAuthorization().getPermissions();

        for (Permission grantedPermission : permissions) {
            if (grantedPermission.getResourceName().equals(userResource.getName())) {
                MatcherAssert.assertThat(grantedPermission.getScopes(), Matchers.not(Matchers.hasItem("create")));
            } else if (grantedPermission.getResourceName().equals(typedResource.getName())) {
                MatcherAssert.assertThat(grantedPermission.getScopes(), Matchers.containsInAnyOrder("create", "read"));
            }
        }
    }

    @Test
    public void testOfflineRequestingPartyToken() throws Exception {
        ClientResource client = getClient(getRealm(), RESOURCE_SERVER_TEST);
        AuthorizationResource authorization = client.authorization();

        JSPolicyRepresentation policy = new JSPolicyRepresentation();

        policy.setName(KeycloakModelUtils.generateId());
        policy.setType("script-scripts/default-policy.js");

        authorization.policies().js().create(policy).close();

        ResourceRepresentation resource = new ResourceRepresentation();

        resource.setName("Sensors");
        resource.addScope("sensors:view", "sensors:update", "sensors:delete");

        try (Response response = authorization.resources().create(resource)) {
            response.readEntity(ResourceRepresentation.class);
        }

        ScopePermissionRepresentation permission = new ScopePermissionRepresentation();

        permission.setName("View Sensor");
        permission.addScope("sensors:view");
        permission.addPolicy(policy.getName());

        authorization.permissions().scope().create(permission).close();

        String accessToken = oauth.realm("authz-test").clientId(RESOURCE_SERVER_TEST).scope("offline_access").doGrantAccessTokenRequest("secret", "offlineuser", "password").getAccessToken();
        AuthzClient authzClient = getAuthzClient(AUTHZ_CLIENT_CONFIG);
        AccessTokenResponse response = authzClient.authorization(accessToken).authorize();
        Assertions.assertNotNull(response.getToken());

        TokenIntrospectionResponse introspectionResponse = authzClient.protection().introspectRequestingPartyToken(response.getToken());

        Assertions.assertTrue(introspectionResponse.getActive());
        Assertions.assertFalse(introspectionResponse.getPermissions().isEmpty());

        response = authzClient.authorization(accessToken).authorize();
        Assertions.assertNotNull(response.getToken());

        oauth.scope(null);
    }

    @Test
    public void testProcessMappersForTargetAudience() throws Exception {
        ClientResource publicClient = getClient(getRealm(), PUBLIC_TEST_CLIENT);

        ProtocolMapperRepresentation customClaimMapper = new ProtocolMapperRepresentation();

        customClaimMapper.setName("custom_claim");
        customClaimMapper.setProtocolMapper("oidc-hardcoded-claim-mapper");
        customClaimMapper.setProtocol("openid-connect");
        Map<String, String> config = new HashMap<>();
        config.put("claim.name", "custom_claim");
        config.put("claim.value", PUBLIC_TEST_CLIENT);
        config.put("access.token.claim", "true");
        customClaimMapper.setConfig(config);

        publicClient.getProtocolMappers().createMapper(customClaimMapper);

        ClientResource client = getClient(getRealm(), RESOURCE_SERVER_TEST);

        config.put("claim.value", RESOURCE_SERVER_TEST);

        client.getProtocolMappers().createMapper(customClaimMapper);

        AuthorizationResource authorization = client.authorization();

        JSPolicyRepresentation policy = new JSPolicyRepresentation();

        policy.setName(KeycloakModelUtils.generateId());
        policy.setType("script-scripts/default-policy.js");

        authorization.policies().js().create(policy).close();

        ResourceRepresentation resource = new ResourceRepresentation();

        resource.setName("Sensors");

        try (Response response = authorization.resources().create(resource)) {
            resource = response.readEntity(ResourceRepresentation.class);
        }

        ResourcePermissionRepresentation permission = new ResourcePermissionRepresentation();

        permission.setName("View Sensor");
        permission.addResource(resource.getName());
        permission.addPolicy(policy.getName());

        authorization.permissions().resource().create(permission).close();

        oauth.realm("authz-test");
        oauth.clientId(PUBLIC_TEST_CLIENT);
        oauth.scope("openid");
        oauth.redirectUri("https://localhost:8543/auth/realms/master/app/auth/");
        OAuthClient.AuthorizationEndpointResponse res = oauth.doLogin("marta", "password");

        // Token request
        OAuthClient.AccessTokenResponse response = oauth.doAccessTokenRequest(res.getCode(), null);
        AccessToken token = toAccessToken(response.getAccessToken());

        Assertions.assertEquals(PUBLIC_TEST_CLIENT, token.getOtherClaims().get("custom_claim"));

        AuthorizationRequest request = new AuthorizationRequest();

        request.addPermission("Sensors");

        AuthorizationResponse authorizationResponse = getAuthzClient(AUTHZ_CLIENT_CONFIG).authorization(response.getAccessToken()).authorize(request);
        token = toAccessToken(authorizationResponse.getToken());
        Assertions.assertEquals(RESOURCE_SERVER_TEST, token.getOtherClaims().get("custom_claim"));
        Assertions.assertEquals(PUBLIC_TEST_CLIENT, token.getIssuedFor());

        authorizationResponse = getAuthzClient(AUTHZ_CLIENT_CONFIG).authorization(response.getAccessToken()).authorize(request);
        token = toAccessToken(authorizationResponse.getToken());
        Assertions.assertEquals(RESOURCE_SERVER_TEST, token.getOtherClaims().get("custom_claim"));
        Assertions.assertEquals(PUBLIC_TEST_CLIENT, token.getIssuedFor());

        oauth.doLogout(response.getRefreshToken(), null);
    }

    @Test
    public void testRefreshTokenFromClientOtherThanAudience() throws IOException {
        oauth.realm("authz-test");
        oauth.clientId(PUBLIC_TEST_CLIENT);
        oauth.scope("openid");
        oauth.redirectUri("https://localhost:8543/auth/realms/master/app/auth/");
        OAuthClient.AuthorizationEndpointResponse res = oauth.doLogin("marta", "password");
        OAuthClient.AccessTokenResponse accessTokenResponse = oauth.doAccessTokenRequest(res.getCode(), null);
        Assertions.assertNotNull(accessTokenResponse.getAccessToken());
        Assertions.assertNotNull(accessTokenResponse.getRefreshToken());

        AuthorizationRequest request = new AuthorizationRequest();
        request.setAudience(RESOURCE_SERVER_TEST);
        AuthorizationResponse authorizationResponse = getAuthzClient(PUBLIC_TEST_CLIENT_CONFIG).authorization(accessTokenResponse.getAccessToken()).authorize(request);
        AccessToken token = toAccessToken(authorizationResponse.getToken());
        Assertions.assertEquals(PUBLIC_TEST_CLIENT, token.getIssuedFor());
        Assertions.assertEquals(RESOURCE_SERVER_TEST, token.getAudience()[0]);
        Assertions.assertFalse(token.getAuthorization().getPermissions().isEmpty());

        accessTokenResponse = oauth.doRefreshTokenRequest(authorizationResponse.getRefreshToken(), null);
        Assertions.assertNotNull(accessTokenResponse.getAccessToken());
        Assertions.assertNotNull(accessTokenResponse.getRefreshToken());
        token = toAccessToken(authorizationResponse.getToken());
        Assertions.assertEquals(PUBLIC_TEST_CLIENT, token.getIssuedFor());
        Assertions.assertFalse(token.getAuthorization().getPermissions().isEmpty());

        oauth.doLogout(accessTokenResponse.getRefreshToken(), null);
    }

    @Test
    public void testTokenExpirationRenewalWhenIssuingTokens() throws IOException, InterruptedException {
        oauth.realm("authz-test");
        oauth.clientId(PUBLIC_TEST_CLIENT);
        oauth.scope("openid");
        oauth.redirectUri("https://localhost:8543/auth/realms/master/app/auth/");
        OAuthClient.AuthorizationEndpointResponse res = oauth.doLogin("marta", "password");
        OAuthClient.AccessTokenResponse accessTokenResponse = oauth.doAccessTokenRequest(res.getCode(), null);
        Assertions.assertNotNull(accessTokenResponse.getAccessToken());
        Assertions.assertNotNull(accessTokenResponse.getRefreshToken());

        for (int i = 0; i < 3; i++) {
            AuthorizationRequest request = new AuthorizationRequest();
            request.setAudience(RESOURCE_SERVER_TEST);
            AuthorizationResponse authorizationResponse = getAuthzClient(PUBLIC_TEST_CLIENT_CONFIG).authorization(accessTokenResponse.getAccessToken()).authorize(request);
            AccessToken refreshToken = toAccessToken(authorizationResponse.getRefreshToken());
            AccessToken accessTokenToken = toAccessToken(authorizationResponse.getToken());
            Assertions.assertEquals(1800, refreshToken.getExp() - refreshToken.getIat());
            Assertions.assertEquals(300, accessTokenToken.getExp() - accessTokenToken.getIat());
            TimeUnit.SECONDS.sleep(1);
        }

        oauth.doLogout(accessTokenResponse.getRefreshToken(), null);
    }

    @Test
    public void testUsingExpiredToken() throws Exception {
        ClientResource client = getClient(getRealm(), RESOURCE_SERVER_TEST);
        AuthorizationResource authorization = client.authorization();

        JSPolicyRepresentation policy = new JSPolicyRepresentation();

        policy.setName(KeycloakModelUtils.generateId());
        policy.setType("script-scripts/default-policy.js");

        authorization.policies().js().create(policy).close();

        ResourceRepresentation resource = new ResourceRepresentation();

        resource.setName("Sensors");

        try (Response response = authorization.resources().create(resource)) {
            response.readEntity(ResourceRepresentation.class);
        }

        ResourcePermissionRepresentation permission = new ResourcePermissionRepresentation();

        permission.setName("View Sensor");
        permission.addPolicy(policy.getName());

        authorization.permissions().resource().create(permission).close();

        String accessToken = oauth.realm("authz-test").clientId(RESOURCE_SERVER_TEST).doGrantAccessTokenRequest("secret", "marta", "password").getAccessToken();
        AuthzClient authzClient = getAuthzClient(AUTHZ_CLIENT_CONFIG);
        AccessTokenResponse response = authzClient.authorization(accessToken).authorize();
        Assertions.assertNotNull(response.getToken());

        getRealm().logoutAll();

        AuthorizationRequest request = new AuthorizationRequest();

        request.addPermission("Sensors");
        request.setSubjectToken(accessToken);

        RuntimeException runtimeException = Assertions.assertThrows(RuntimeException.class, () -> authzClient.authorization().authorize(request));
        MatcherAssert.assertThat(runtimeException.getCause(), Matchers.instanceOf(HttpResponseException.class));
        HttpResponseException httpException = (HttpResponseException) runtimeException.getCause();
        Assertions.assertEquals(400, httpException.getStatusCode());
        MatcherAssert.assertThat(httpException.toString(), Matchers.containsString("unauthorized_client"));
    }

    @Test
    public void testInvalidTokenSignature() throws Exception {
        ClientResource client = getClient(getRealm(), RESOURCE_SERVER_TEST);
        AuthorizationResource authorization = client.authorization();

        JSPolicyRepresentation policy = new JSPolicyRepresentation();

        policy.setName(KeycloakModelUtils.generateId());
        policy.setType("script-scripts/default-policy.js");

        authorization.policies().js().create(policy).close();

        ResourceRepresentation resource = new ResourceRepresentation();

        resource.setName("Sensors");

        try (Response response = authorization.resources().create(resource)) {
            response.readEntity(ResourceRepresentation.class);
        }

        ResourcePermissionRepresentation permission = new ResourcePermissionRepresentation();

        permission.setName("View Sensor");
        permission.addPolicy(policy.getName());

        authorization.permissions().resource().create(permission).close();

        String accessToken = oauth.realm("authz-test").clientId(RESOURCE_SERVER_TEST).doGrantAccessTokenRequest("secret", "marta", "password").getAccessToken();
        AuthzClient authzClient = getAuthzClient(AUTHZ_CLIENT_CONFIG);
        AuthorizationRequest request = new AuthorizationRequest();

        request.addPermission("Sensors");
        request.setSubjectToken(accessToken + "i");

        getRealm().clearEvents();

        RuntimeException runtimeException = Assertions.assertThrows(RuntimeException.class, () -> authzClient.authorization().authorize(request));
        MatcherAssert.assertThat(runtimeException.getCause(), Matchers.instanceOf(HttpResponseException.class));
        HttpResponseException httpException = (HttpResponseException) runtimeException.getCause();
        Assertions.assertEquals(400, httpException.getStatusCode());
        MatcherAssert.assertThat(httpException.toString(), Matchers.containsString("unauthorized_client"));

        List<EventRepresentation> events = getRealm()
                .getEvents(Arrays.asList(EventType.PERMISSION_TOKEN_ERROR.name()), null, null, null, null, null, null, null);
        Assertions.assertEquals(1, events.size());
    }

    @Test
    public void testDenyScopeNotManagedByScopePolicy() throws Exception {
        ClientResource client = getClient(getRealm(), RESOURCE_SERVER_TEST);
        AuthorizationResource authorization = client.authorization();

        JSPolicyRepresentation policy = new JSPolicyRepresentation();

        policy.setName(KeycloakModelUtils.generateId());
        policy.setType("script-scripts/default-policy.js");

        authorization.policies().js().create(policy).close();

        ResourceRepresentation resource = new ResourceRepresentation();

        resource.setName(KeycloakModelUtils.generateId());
        resource.addScope("sensors:view", "sensors:update", "sensors:delete");

        try (Response response = authorization.resources().create(resource)) {
            resource = response.readEntity(ResourceRepresentation.class);
        }

        ScopePermissionRepresentation permission = new ScopePermissionRepresentation();

        permission.setName(KeycloakModelUtils.generateId());
        permission.addResource(resource.getId());
        permission.addScope("sensors:view");
        permission.addPolicy(policy.getName());

        authorization.permissions().scope().create(permission).close();

        String accessToken = oauth.realm("authz-test").clientId(RESOURCE_SERVER_TEST).doGrantAccessTokenRequest("secret", "kolo", "password").getAccessToken();
        AuthzClient authzClient = getAuthzClient(AUTHZ_CLIENT_CONFIG);
        AuthorizationRequest request = new AuthorizationRequest();

        request.addPermission(resource.getId(), "sensors:view");

        AuthorizationResponse response = authzClient.authorization(accessToken).authorize(request);
        Assertions.assertNotNull(response.getToken());
        Collection<Permission> permissions = toAccessToken(response.getToken()).getAuthorization().getPermissions();
        Assertions.assertEquals(1, permissions.size());

        for (Permission grantedPermission : permissions) {
            Assertions.assertEquals(resource.getId(), grantedPermission.getResourceId());
            Assertions.assertEquals(1, grantedPermission.getScopes().size());
            MatcherAssert.assertThat(grantedPermission.getScopes(), Matchers.hasItem("sensors:view"));
        }

        final AuthorizationRequest requestUpdate = new AuthorizationRequest();
        requestUpdate.addPermission(resource.getId(), "sensors:update");

        AuthorizationDeniedException ex = Assertions.assertThrows(AuthorizationDeniedException.class, () -> authzClient.authorization().authorize(requestUpdate));
        MatcherAssert.assertThat(ex.getCause(), Matchers.instanceOf(HttpResponseException.class));
        MatcherAssert.assertThat(ex.getCause(), Matchers.hasProperty("statusCode", Matchers.is(403)));
    }

    @Test
    public void testPermissionsAcrossResourceServers() throws Exception {
        try (Response response = getRealm().clients().create(ClientBuilder.create().clientId("rs-a").secret("secret").serviceAccount().authorizationServicesEnabled(true).build())) {
            ApiUtil.getCreatedId(response);
        }
        String rsBId;
        try (Response response = getRealm().clients().create(ClientBuilder.create().clientId("rs-b").secret("secret").serviceAccount().authorizationServicesEnabled(true).build())) {
            rsBId = ApiUtil.getCreatedId(response);
        }
        ClientResource rsB = getRealm().clients().get(rsBId);

        rsB.authorization().resources().create(new ResourceRepresentation("Resource A"));

        JSPolicyRepresentation grantPolicy = new JSPolicyRepresentation();

        grantPolicy.setName("Grant Policy");
        grantPolicy.setType("script-scripts/default-policy.js");

        rsB.authorization().policies().js().create(grantPolicy);

        ResourcePermissionRepresentation permission = new ResourcePermissionRepresentation();

        permission.setName("Resource A Permission");
        permission.addResource("Resource A");
        permission.addPolicy(grantPolicy.getName());

        rsB.authorization().permissions().resource().create(permission);

        AuthzClient authzClient = getAuthzClient(AUTHZ_CLIENT_CONFIG);
        Configuration config = authzClient.getConfiguration();

        config.setResource("rs-a");

        authzClient = AuthzClient.create(config);
        AccessTokenResponse accessTokenResponse = authzClient.obtainAccessToken();

        config.setResource("rs-b");

        AuthorizationRequest request = new AuthorizationRequest();

        request.addPermission("Resource A");

        AuthorizationResponse response = authzClient.authorization(accessTokenResponse.getToken()).authorize(request);

        Assertions.assertNotNull(response.getToken());
        Collection<Permission> permissions = toAccessToken(response.getToken()).getAuthorization().getPermissions();
        Assertions.assertEquals(1, permissions.size());
        Assertions.assertEquals("Resource A", permissions.iterator().next().getResourceName());
    }

    @Test
    public void testClientToClientPermissionRequest() throws Exception {
        ClientResource client = getClient(getRealm(), RESOURCE_SERVER_TEST);
        AuthorizationResource authorization = client.authorization();

        JSPolicyRepresentation policy = new JSPolicyRepresentation();

        policy.setName(KeycloakModelUtils.generateId());
        policy.setType("script-scripts/default-policy.js");

        authorization.policies().js().create(policy).close();

        ResourceRepresentation resource = new ResourceRepresentation();

        resource.setName("Sensors");

        try (Response response = authorization.resources().create(resource)) {
            response.readEntity(ResourceRepresentation.class);
        }

        ResourcePermissionRepresentation permission = new ResourcePermissionRepresentation();

        permission.setName("View Sensor");
        permission.addPolicy(policy.getName());

        authorization.permissions().resource().create(permission).close();

        ClientRepresentation otherClient = new ClientRepresentation();

        otherClient.setClientId("serviceB");
        otherClient.setServiceAccountsEnabled(true);
        otherClient.setSecret("secret");
        otherClient.setPublicClient(false);

        getRealm().clients().create(otherClient);

        Map<String, Object> credentials = new HashMap<>();

        credentials.put("secret", "secret");

        AuthzClient authzClient = AuthzClient
                .create(new Configuration(ServerURLs.AUTH_SERVER_URL,
                        getRealm().toRepresentation().getRealm(), otherClient.getClientId(),
                        credentials, getAuthzClient(AUTHZ_CLIENT_CONFIG).getConfiguration().getHttpClient()));

        AuthorizationRequest request = new AuthorizationRequest();

        request.setAudience(RESOURCE_SERVER_TEST);

        AuthorizationResponse response = authzClient.authorization().authorize(request);

        Assertions.assertNotNull(response.getToken());
        // Refresh token should not be present
        Assertions.assertNull(response.getRefreshToken());
    }

    @Test
    public void testPermissionOrder() throws Exception {
        ClientResource client = getClient(getRealm(), RESOURCE_SERVER_TEST);
        AuthorizationResource authorization = client.authorization();
        JSPolicyRepresentation policy = new JSPolicyRepresentation();

        policy.setName(KeycloakModelUtils.generateId());
        policy.setType("script-scripts/default-policy.js");

        authorization.policies().js().create(policy).close();

        ResourceRepresentation resource = new ResourceRepresentation();

        resource.setName("my_resource");
        resource.addScope("entity:read");

        try (Response response = authorization.resources().create(resource)) {
            resource = response.readEntity(ResourceRepresentation.class);
        }

        ScopeRepresentation featureAccessScope = new ScopeRepresentation("feature:access");
        authorization.scopes().create(featureAccessScope);

        ResourcePermissionRepresentation permission = new ResourcePermissionRepresentation();

        permission.setName(KeycloakModelUtils.generateId());
        permission.addPolicy(policy.getName());
        permission.addResource(resource.getId());

        authorization.permissions().resource().create(permission).close();

        ScopePermissionRepresentation scopePermission = new ScopePermissionRepresentation();

        scopePermission.setName(KeycloakModelUtils.generateId());
        scopePermission.addPolicy(policy.getName());
        scopePermission.addScope(featureAccessScope.getName());

        authorization.permissions().scope().create(scopePermission).close();

        AuthorizationRequest request = new AuthorizationRequest();

        request.addPermission(null, "entity:read");
        request.addPermission(null, "feature:access");

        AuthzClient authzClient = getAuthzClient(AUTHZ_CLIENT_CONFIG);

        AuthorizationResponse response = authzClient.authorization().authorize(request);
        AccessToken token = toAccessToken(response.getToken());
        Authorization result = token.getAuthorization();

        Assertions.assertEquals(2, result.getPermissions().size());
        Assertions.assertTrue(result.getPermissions().stream().anyMatch(p ->
                p.getResourceId() == null && p.getScopes().contains(featureAccessScope.getName())));
        String resourceId = resource.getId();
        Assertions.assertTrue(result.getPermissions().stream().anyMatch(p ->
                p.getResourceId() != null && p.getResourceId().equals(resourceId) && p
                .getScopes().contains("entity:read")));

        request = new AuthorizationRequest();

        request.addPermission(null, "feature:access");
        request.addPermission(null, "entity:read");

        response = authzClient.authorization().authorize(request);
        token = toAccessToken(response.getToken());
        result = token.getAuthorization();

        Assertions.assertEquals(2, result.getPermissions().size());
        Assertions.assertTrue(result.getPermissions().stream().anyMatch(p ->
                p.getResourceId() == null && p.getScopes().contains(featureAccessScope.getName())));
        Assertions.assertTrue(result.getPermissions().stream().anyMatch(p ->
                p.getResourceId() != null && p.getResourceId().equals(resourceId) && p
                        .getScopes().contains("entity:read")));
    }

    @Test
    public void testSameResultRegardlessOPermissionParameterValue() throws Exception {
        ClientResource client = getClient(getRealm(), RESOURCE_SERVER_TEST);
        AuthorizationResource authorization = client.authorization();
        ResourceRepresentation resource = new ResourceRepresentation();

        resource.setName(KeycloakModelUtils.generateId());
        resource.addScope("scope1", "scope2");
        resource.setOwnerManagedAccess(true);

        try (Response response = authorization.resources().create(resource)) {
            resource = response.readEntity(ResourceRepresentation.class);
        }

        UserPolicyRepresentation policy = new UserPolicyRepresentation();

        policy.setName(KeycloakModelUtils.generateId());
        policy.addUser("marta");

        authorization.policies().user().create(policy).close();

        ScopePermissionRepresentation representation = new ScopePermissionRepresentation();

        representation.setName(KeycloakModelUtils.generateId());
        representation.addScope("scope1");
        representation.addPolicy(policy.getName());

        authorization.permissions().scope().create(representation).close();

        AuthzClient authzClient = getAuthzClient(AUTHZ_CLIENT_CONFIG);
        PermissionTicketRepresentation ticket = new PermissionTicketRepresentation();

        ticket.setResource(resource.getId());
        ticket.setRequesterName("marta");
        ticket.setGranted(true);
        ticket.setScopeName("scope1");

        authzClient.protection().permission().create(ticket);

        AuthorizationRequest request = new AuthorizationRequest();
        request.addPermission(resource.getId());
        AuthorizationResponse response = authzClient.authorization("marta", "password").authorize(request);
        AccessToken rpt = toAccessToken(response.getToken());
        ResourceRepresentation finalResource = resource;
        List<Permission> permissions = rpt.getAuthorization().getPermissions().stream().filter(permission -> permission.getResourceId().equals(finalResource.getId())).collect(Collectors.toList());
        Assertions.assertEquals(1, permissions.size());
        Assertions.assertEquals(1, permissions.get(0).getScopes().size());
        Assertions.assertEquals("scope1", permissions.get(0).getScopes().iterator().next());

        request = new AuthorizationRequest();
        request.addPermission(resource.getName());
        response = authzClient.authorization("marta", "password").authorize(request);
        rpt = toAccessToken(response.getToken());
        permissions = rpt.getAuthorization().getPermissions().stream().filter(permission -> permission.getResourceId().equals(finalResource.getId())).collect(Collectors.toList());
        Assertions.assertEquals(1, permissions.size());
        Assertions.assertEquals(1, permissions.get(0).getScopes().size());
        Assertions.assertEquals("scope1", permissions.get(0).getScopes().iterator().next());
    }

    private void testRptRequestWithResourceName(String configFile) {
        Metadata metadata = new Metadata();

        metadata.setIncludeResourceName(true);

        assertResponse(metadata, () -> getAuthzClient(configFile).authorization("marta", "password").authorize());

        AuthorizationRequest request = new AuthorizationRequest();

        request.setMetadata(metadata);
        request.addPermission("Resource 13");

        assertResponse(metadata, () -> getAuthzClient(configFile).authorization("marta", "password").authorize(request));

        request.setMetadata(null);

        assertResponse(metadata, () -> getAuthzClient(configFile).authorization("marta", "password").authorize(request));
    }

    private void testResourceServerAsAudience(String testClientId, String resourceServerClientId, String configFile) throws Exception {
        AuthorizationRequest request = new AuthorizationRequest();

        request.addPermission("Resource 1");

        String accessToken = oauth.realm("authz-test").clientId(testClientId).doGrantAccessTokenRequest("secret", "marta", "password").getAccessToken();
        AuthorizationResponse response = getAuthzClient(configFile).authorization(accessToken).authorize(request);
        AccessToken rpt = toAccessToken(response.getToken());

        Assertions.assertEquals(resourceServerClientId, rpt.getAudience()[0]);
    }

    private boolean hasPermission(String userName, String password, String resourceId, String... scopeIds) throws Exception {
        String accessToken = oauth.realm("authz-test").clientId(RESOURCE_SERVER_TEST).doGrantAccessTokenRequest("secret", userName, password).getAccessToken();
        AuthorizationResponse response = getAuthzClient(AUTHZ_CLIENT_CONFIG).authorization(accessToken).authorize(new AuthorizationRequest());
        AccessToken rpt = toAccessToken(response.getToken());
        Authorization authz = rpt.getAuthorization();
        Collection<Permission> permissions = authz.getPermissions();

        Assertions.assertNotNull(permissions);
        Assertions.assertFalse(permissions.isEmpty());

        for (Permission grantedPermission : permissions) {
            if (grantedPermission.getResourceId().equals(resourceId)) {
                return scopeIds == null || scopeIds.length == 0 || grantedPermission.getScopes().containsAll(Arrays.asList(scopeIds));
            }
        }

        return false;
    }

    private boolean hasPermission(String userName, String password, String resourceId) throws Exception {
        return hasPermission(userName, password, resourceId, new String[0]);
    }

    private void assertResponse(Metadata metadata, Supplier<AuthorizationResponse> responseSupplier) {
        AccessToken.Authorization authorization = toAccessToken(responseSupplier.get().getToken()).getAuthorization();

        Collection<Permission> permissions = authorization.getPermissions();

        Assertions.assertNotNull(permissions);
        Assertions.assertFalse(permissions.isEmpty());

        for (Permission permission : permissions) {
            if (metadata.getIncludeResourceName()) {
                Assertions.assertNotNull(permission.getResourceName());
            } else {
                Assertions.assertNull(permission.getResourceName());
            }
        }
    }

    private RealmResource getRealm() throws Exception {
        return adminClient.realm("authz-test");
    }

    private ClientResource getClient(RealmResource realm, String clientId) {
        ClientsResource clients = realm.clients();
        return clients.findByClientId(clientId).stream().map(representation -> clients.get(representation.getId())).findFirst().orElseThrow(() -> new RuntimeException("Expected client [resource-server-test]"));
    }

    private void configureAuthorization(String clientId) throws Exception {
        ClientResource client = getClient(getRealm(), clientId);
        AuthorizationResource authorization = client.authorization();

        JSPolicyRepresentation policy = new JSPolicyRepresentation();

        policy.setName("Default Policy");
        policy.setType("script-scripts/default-policy.js");

        authorization.policies().js().create(policy).close();

        for (int i = 1; i <= 20; i++) {
            ResourceRepresentation resource = new ResourceRepresentation("Resource " + i);

            authorization.resources().create(resource).close();

            ResourcePermissionRepresentation permission = new ResourcePermissionRepresentation();

            permission.setName(resource.getName() + " Permission");
            permission.addResource(resource.getName());
            permission.addPolicy(policy.getName());

            authorization.permissions().resource().create(permission).close();
        }
    }

    private void removeAuthorization(String clientId) throws Exception {
        ClientResource client = getClient(getRealm(), clientId);
        ClientRepresentation representation = client.toRepresentation();

        representation.setAuthorizationServicesEnabled(false);

        client.update(representation);

        representation.setAuthorizationServicesEnabled(true);

        client.update(representation);
    }

    private void assertPermissions(AuthzClient authzClient, String accessToken, AuthorizationRequest request, ResourceRepresentation resource, String... expectedScopes) {
        AuthorizationResponse response = authzClient.authorization(accessToken).authorize(request);
        Assertions.assertNotNull(response.getToken());
        Collection<Permission> permissions = toAccessToken(response.getToken()).getAuthorization().getPermissions();
        Assertions.assertEquals(1, permissions.size());

        for (Permission grantedPermission : permissions) {
            Assertions.assertEquals(resource.getId(), grantedPermission.getResourceId());
            Assertions.assertEquals(expectedScopes.length, grantedPermission.getScopes().size());
            Assertions.assertTrue(grantedPermission.getScopes().containsAll(Arrays.asList(expectedScopes)));
        }
    }
}
