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
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.admin.client.resource.AuthorizationResource;
import org.keycloak.admin.client.resource.ClientResource;
import org.keycloak.admin.client.resource.ClientsResource;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.admin.client.resource.ResourcesResource;
import org.keycloak.authorization.client.AuthzClient;
import org.keycloak.authorization.client.util.HttpResponseException;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.AccessToken.Authorization;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.representations.idm.RealmRepresentation;
import org.keycloak.representations.idm.authorization.AuthorizationRequest;
import org.keycloak.representations.idm.authorization.AuthorizationResponse;
import org.keycloak.representations.idm.authorization.JSPolicyRepresentation;
import org.keycloak.representations.idm.authorization.Permission;
import org.keycloak.representations.idm.authorization.PermissionRequest;
import org.keycloak.representations.idm.authorization.ResourcePermissionRepresentation;
import org.keycloak.representations.idm.authorization.ResourceRepresentation;
import org.keycloak.representations.idm.authorization.ScopePermissionRepresentation;
import org.keycloak.testsuite.util.ClientBuilder;
import org.keycloak.testsuite.util.KeycloakModelUtils;
import org.keycloak.testsuite.util.RealmBuilder;
import org.keycloak.testsuite.util.RoleBuilder;
import org.keycloak.testsuite.util.RolesBuilder;
import org.keycloak.testsuite.util.UserBuilder;
import org.testcontainers.shaded.org.hamcrest.MatcherAssert;
import org.testcontainers.shaded.org.hamcrest.Matchers;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class PermissionClaimTest extends AbstractAuthzTest {

    private JSPolicyRepresentation claimAPolicy;
    private JSPolicyRepresentation claimBPolicy;
    private JSPolicyRepresentation claimCPolicy;
    private JSPolicyRepresentation denyPolicy;

    @Override
    public List<RealmRepresentation> getRealmsForImport() {
        List<RealmRepresentation> testRealms = new ArrayList<>();
        testRealms.add(RealmBuilder.create().name("authz-test")
                .roles(RolesBuilder.create().realmRole(RoleBuilder.create().name("uma_authorization").build()))
                .user(UserBuilder.create().username("marta").password("password").addRoles("uma_authorization"))
                .user(UserBuilder.create().username("kolo").password("password"))
                .client(ClientBuilder.create().clientId("resource-server-test")
                    .secret("secret")
                    .authorizationServicesEnabled(true)
                    .redirectUris("http://localhost/resource-server-test")
                    .defaultRoles("uma_protection")
                    .directAccessGrants())
                .client(ClientBuilder.create().clientId("test-client")
                    .secret("secret")
                    .authorizationServicesEnabled(true)
                    .redirectUris("http://localhost/test-client")
                    .directAccessGrants())
                .build());
        return testRealms;
    }

    @BeforeEach
    public void configureAuthorization() throws Exception {
        ClientResource client = getClient(getRealm());
        AuthorizationResource authorization = client.authorization();

        claimAPolicy = new JSPolicyRepresentation();

        claimAPolicy.setName("Claim A Policy");
        claimAPolicy.setType("script-scripts/add-claim-a-policy.js");

        authorization.policies().js().create(claimAPolicy).close();

        claimBPolicy = new JSPolicyRepresentation();

        claimBPolicy.setName("Policy Claim B");
        claimBPolicy.setType("script-scripts/add-claim-b-policy.js");

        authorization.policies().js().create(claimBPolicy).close();

        claimCPolicy = new JSPolicyRepresentation();

        claimCPolicy.setName("Policy Claim C");
        claimCPolicy.setType("script-scripts/add-claim-c-policy.js");

        authorization.policies().js().create(claimCPolicy).close();

        denyPolicy = new JSPolicyRepresentation();

        denyPolicy.setName("Deny Policy");
        denyPolicy.setType("script-scripts/always-deny-with-claim-policy.js");

        authorization.policies().js().create(denyPolicy).close();
    }

    @AfterEach
    public void removeAuthorization() throws Exception {
        ClientResource client = getClient(getRealm());
        ClientRepresentation representation = client.toRepresentation();

        representation.setAuthorizationServicesEnabled(false);

        client.update(representation);

        representation.setAuthorizationServicesEnabled(true);

        client.update(representation);

        ResourcesResource resources = client.authorization().resources();
        List<ResourceRepresentation> defaultResource = resources.findByName("Default Resource");

        resources.resource(defaultResource.get(0).getId()).remove();
    }

    @Test
    public void testPermissionWithClaims() throws Exception {
        ClientResource client = getClient(getRealm());
        AuthorizationResource authorization = client.authorization();
        ResourceRepresentation resource = new ResourceRepresentation("Resource A");

        authorization.resources().create(resource).close();

        ResourcePermissionRepresentation permission = new ResourcePermissionRepresentation();

        permission.setName(resource.getName() + " Permission");
        permission.addResource(resource.getName());
        permission.addPolicy(claimAPolicy.getName());

        authorization.permissions().resource().create(permission).close();

        PermissionRequest request = new PermissionRequest();

        request.setResourceId(resource.getName());

        String accessToken = oauth.realm("authz-test").clientId("test-client").doGrantAccessTokenRequest("secret", "marta", "password").getAccessToken();
        AuthzClient authzClient = getAuthzClient("/authorization-test/default-keycloak.json");
        String ticket = authzClient.protection().permission().create(request).getTicket();
        AuthorizationResponse response = authzClient.authorization(accessToken).authorize(new AuthorizationRequest(ticket));

        Assertions.assertNotNull(response.getToken());
        AccessToken rpt = toAccessToken(response.getToken());
        Authorization authorizationClaim = rpt.getAuthorization();
        List<Permission> permissions = new ArrayList<>(authorizationClaim.getPermissions());

        Assertions.assertEquals(1, permissions.size());

        Assertions.assertTrue(permissions.get(0).getClaims().get("claim-a").containsAll(Arrays.asList("claim-a", "claim-a1")));
    }

    @Test
    public void testPermissionWithClaimsDifferentPolicies() throws Exception {
        ClientResource client = getClient(getRealm());
        AuthorizationResource authorization = client.authorization();

        ResourceRepresentation resource = new ResourceRepresentation("Resource B");

        authorization.resources().create(resource).close();

        ResourcePermissionRepresentation permission = new ResourcePermissionRepresentation();

        permission.setName(resource.getName() + " Permission");
        permission.addResource(resource.getName());
        permission.addPolicy(claimAPolicy.getName(), claimBPolicy.getName());

        authorization.permissions().resource().create(permission).close();

        PermissionRequest request = new PermissionRequest();

        request.setResourceId(resource.getName());

        String accessToken = oauth.realm("authz-test").clientId("test-client").doGrantAccessTokenRequest("secret", "marta", "password").getAccessToken();
        AuthzClient authzClient = getAuthzClient("/authorization-test/default-keycloak.json");
        String ticket = authzClient.protection().permission().forResource(request).getTicket();
        AuthorizationResponse response = authzClient.authorization(accessToken).authorize(new AuthorizationRequest(ticket));

        Assertions.assertNotNull(response.getToken());
        AccessToken rpt = toAccessToken(response.getToken());
        Authorization authorizationClaim = rpt.getAuthorization();
        List<Permission> permissions = new ArrayList<>(authorizationClaim.getPermissions());

        Assertions.assertEquals(1, permissions.size());

        Map<String, Set<String>> claims = permissions.get(0).getClaims();

        Assertions.assertTrue(claims.containsKey("claim-a"));
        Assertions.assertTrue(claims.containsKey("claim-b"));
    }

    @Test
    public void testClaimsFromDifferentScopePermissions() throws Exception {
        ClientResource client = getClient(getRealm());
        AuthorizationResource authorization = client.authorization();

        ResourceRepresentation resourceA = new ResourceRepresentation(KeycloakModelUtils.generateId(), "create", "update");

        authorization.resources().create(resourceA).close();

        ResourceRepresentation resourceB = new ResourceRepresentation(KeycloakModelUtils.generateId(), "create", "update");

        authorization.resources().create(resourceB).close();

        ScopePermissionRepresentation allScopesPermission = new ScopePermissionRepresentation();

        allScopesPermission.setName(KeycloakModelUtils.generateId());
        allScopesPermission.addScope("create", "update");
        allScopesPermission.addPolicy(claimAPolicy.getName(), claimBPolicy.getName());

        authorization.permissions().scope().create(allScopesPermission).close();

        ScopePermissionRepresentation updatePermission = new ScopePermissionRepresentation();

        updatePermission.setName(KeycloakModelUtils.generateId());
        updatePermission.addScope("update");
        updatePermission.addPolicy(claimCPolicy.getName());

        try (Response response = authorization.permissions().scope().create(updatePermission)) {
            updatePermission = response.readEntity(ScopePermissionRepresentation.class);
        }

        AuthzClient authzClient = getAuthzClient("/authorization-test/default-keycloak.json");
        AuthorizationRequest request = new AuthorizationRequest();

        request.addPermission(null, "create", "update");

        AuthorizationResponse response = authzClient.authorization("marta", "password").authorize(request);
        Assertions.assertNotNull(response.getToken());
        AccessToken rpt = toAccessToken(response.getToken());
        Authorization authorizationClaim = rpt.getAuthorization();
        List<Permission> permissions = new ArrayList<>(authorizationClaim.getPermissions());

        Assertions.assertEquals(2, permissions.size());

        for (Permission permission : permissions) {
            Map<String, Set<String>> claims = permission.getClaims();

            Assertions.assertNotNull(claims);

            MatcherAssert.assertThat(claims.get("claim-a"), Matchers.containsInAnyOrder("claim-a", "claim-a1"));
            MatcherAssert.assertThat(claims.get("claim-b"), Matchers.containsInAnyOrder("claim-b"));
            MatcherAssert.assertThat(claims.get("claim-c"), Matchers.containsInAnyOrder("claim-c"));
        }

        updatePermission.addPolicy(denyPolicy.getName());
        authorization.permissions().scope().findById(updatePermission.getId()).update(updatePermission);

        response = authzClient.authorization("marta", "password").authorize(request);
        Assertions.assertNotNull(response.getToken());
        rpt = toAccessToken(response.getToken());
        authorizationClaim = rpt.getAuthorization();
        permissions = new ArrayList<>(authorizationClaim.getPermissions());

        Assertions.assertEquals(2, permissions.size());

        for (Permission permission : permissions) {
            Map<String, Set<String>> claims = permission.getClaims();

            Assertions.assertNotNull(claims);

            MatcherAssert.assertThat(claims.get("claim-a"), Matchers.containsInAnyOrder("claim-a", "claim-a1"));
            MatcherAssert.assertThat(claims.get("claim-b"), Matchers.containsInAnyOrder("claim-b"));
            MatcherAssert.assertThat(claims.get("claim-c"), Matchers.containsInAnyOrder("claim-c"));
            MatcherAssert.assertThat(claims.get("deny-policy"), Matchers.containsInAnyOrder("deny-policy"));
        }
    }

    @Test
    public void testClaimsFromDifferentResourcePermissions() throws Exception {
        ClientResource client = getClient(getRealm());
        AuthorizationResource authorization = client.authorization();

        ResourceRepresentation resourceA = new ResourceRepresentation(KeycloakModelUtils.generateId());

        resourceA.setType("typed-resource");

        authorization.resources().create(resourceA).close();

        ResourcePermissionRepresentation allScopesPermission = new ResourcePermissionRepresentation();

        allScopesPermission.setName(KeycloakModelUtils.generateId());
        allScopesPermission.addResource(resourceA.getName());
        allScopesPermission.addPolicy(claimAPolicy.getName(), claimBPolicy.getName());

        authorization.permissions().resource().create(allScopesPermission).close();

        ResourcePermissionRepresentation updatePermission = new ResourcePermissionRepresentation();

        updatePermission.setName(KeycloakModelUtils.generateId());
        updatePermission.addResource(resourceA.getName());
        updatePermission.addPolicy(claimCPolicy.getName());

        try (Response response = authorization.permissions().resource().create(updatePermission)) {
            updatePermission = response.readEntity(ResourcePermissionRepresentation.class);
        }

        AuthzClient authzClient = getAuthzClient("/authorization-test/default-keycloak.json");
        AuthorizationResponse response = authzClient.authorization("marta", "password").authorize();
        Assertions.assertNotNull(response.getToken());
        AccessToken rpt = toAccessToken(response.getToken());
        Authorization authorizationClaim = rpt.getAuthorization();
        List<Permission> permissions = new ArrayList<>(authorizationClaim.getPermissions());

        Assertions.assertEquals(1, permissions.size());

        for (Permission permission : permissions) {
            Map<String, Set<String>> claims = permission.getClaims();

            Assertions.assertNotNull(claims);

            MatcherAssert.assertThat(claims.get("claim-a"), Matchers.containsInAnyOrder("claim-a", "claim-a1"));
            MatcherAssert.assertThat(claims.get("claim-b"), Matchers.containsInAnyOrder("claim-b"));
            MatcherAssert.assertThat(claims.get("claim-c"), Matchers.containsInAnyOrder("claim-c"));
        }

        updatePermission.addPolicy(denyPolicy.getName());
        authorization.permissions().resource().findById(updatePermission.getId()).update(updatePermission);

        try {
            authzClient.authorization("marta", "password").authorize();
            Assertions.fail("can not access resource");
        } catch (RuntimeException expected) {
            Assertions.assertEquals(403, HttpResponseException.class.cast(expected.getCause()).getStatusCode());
            Assertions.assertTrue(HttpResponseException.class.cast(expected.getCause()).toString().contains("access_denied"));
        }

        ResourceRepresentation resourceInstance = new ResourceRepresentation(KeycloakModelUtils.generateId(), "create", "update");

        resourceInstance.setType(resourceA.getType());
        resourceInstance.setOwner("marta");

        try (Response response1 = authorization.resources().create(resourceInstance)) {
            resourceInstance = response1.readEntity(ResourceRepresentation.class);
        }

        AuthorizationRequest request = new AuthorizationRequest();

        request.addPermission(null, "create", "update");

        try {
            authzClient.authorization("marta", "password").authorize(request);
            Assertions.fail("can not access resource");
        } catch (RuntimeException expected) {
            Assertions.assertEquals(403, HttpResponseException.class.cast(expected.getCause()).getStatusCode());
            Assertions.assertTrue(HttpResponseException.class.cast(expected.getCause()).toString().contains("access_denied"));
        }

        ResourcePermissionRepresentation resourceInstancePermission = new ResourcePermissionRepresentation();

        resourceInstancePermission.setName(KeycloakModelUtils.generateId());
        resourceInstancePermission.addResource(resourceInstance.getId());
        resourceInstancePermission.addPolicy(claimCPolicy.getName());

        try (Response response1 = authorization.permissions().resource().create(resourceInstancePermission)) {
            response1.readEntity(ResourcePermissionRepresentation.class);
        }

        response = authzClient.authorization("marta", "password").authorize(request);
        Assertions.assertNotNull(response.getToken());
        rpt = toAccessToken(response.getToken());
        authorizationClaim = rpt.getAuthorization();
        permissions = new ArrayList<>(authorizationClaim.getPermissions());

        Assertions.assertEquals(1, permissions.size());

        for (Permission permission : permissions) {
            Map<String, Set<String>> claims = permission.getClaims();

            Assertions.assertNotNull(claims);

            MatcherAssert.assertThat(claims.get("claim-a"), Matchers.containsInAnyOrder("claim-a", "claim-a1"));
            MatcherAssert.assertThat(claims.get("claim-b"), Matchers.containsInAnyOrder("claim-b"));
            MatcherAssert.assertThat(claims.get("claim-c"), Matchers.containsInAnyOrder("claim-c"));
            MatcherAssert.assertThat(claims.get("deny-policy"), Matchers.containsInAnyOrder("deny-policy"));
        }

        response = authzClient.authorization("marta", "password").authorize();
        Assertions.assertNotNull(response.getToken());
        rpt = toAccessToken(response.getToken());
        authorizationClaim = rpt.getAuthorization();
        permissions = new ArrayList<>(authorizationClaim.getPermissions());

        Assertions.assertEquals(1, permissions.size());

        for (Permission permission : permissions) {
            Map<String, Set<String>> claims = permission.getClaims();

            Assertions.assertNotNull(claims);

            MatcherAssert.assertThat(claims.get("claim-a"), Matchers.containsInAnyOrder("claim-a", "claim-a1"));
            MatcherAssert.assertThat(claims.get("claim-b"), Matchers.containsInAnyOrder("claim-b"));
            MatcherAssert.assertThat(claims.get("claim-c"), Matchers.containsInAnyOrder("claim-c"));
            MatcherAssert.assertThat(claims.get("deny-policy"), Matchers.containsInAnyOrder("deny-policy"));
            MatcherAssert.assertThat(permission.getScopes(), Matchers.containsInAnyOrder("create", "update"));
        }

        updatePermission.setPolicies(new HashSet<>());
        updatePermission.addPolicy(claimCPolicy.getName());
        authorization.permissions().resource().findById(updatePermission.getId()).update(updatePermission);

        response = authzClient.authorization("marta", "password").authorize();
        Assertions.assertNotNull(response.getToken());
        rpt = toAccessToken(response.getToken());
        authorizationClaim = rpt.getAuthorization();
        permissions = new ArrayList<>(authorizationClaim.getPermissions());

        Assertions.assertEquals(2, permissions.size());

        for (Permission permission : permissions) {
            Map<String, Set<String>> claims = permission.getClaims();

            Assertions.assertNotNull(claims);

            MatcherAssert.assertThat(claims.get("claim-a"), Matchers.containsInAnyOrder("claim-a", "claim-a1"));
            MatcherAssert.assertThat(claims.get("claim-b"), Matchers.containsInAnyOrder("claim-b"));
            MatcherAssert.assertThat(claims.get("claim-c"), Matchers.containsInAnyOrder("claim-c"));
        }
    }

    private RealmResource getRealm() throws Exception {
        return adminClient.realm("authz-test");
    }

    private ClientResource getClient(RealmResource realm) {
        ClientsResource clients = realm.clients();
        return clients.findByClientId("resource-server-test").stream().map(representation -> clients.get(representation.getId())).findFirst().orElseThrow(() -> new RuntimeException("Expected client [resource-server-test]"));
    }
}