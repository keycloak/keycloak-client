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
package org.keycloak.client.testsuite.authz;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.admin.client.resource.AuthorizationResource;
import org.keycloak.admin.client.resource.ClientResource;
import org.keycloak.admin.client.resource.ClientScopeResource;
import org.keycloak.admin.client.resource.ClientsResource;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.authorization.client.AuthorizationDeniedException;
import org.keycloak.authorization.client.AuthzClient;
import org.keycloak.client.testsuite.framework.KeycloakVersion;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.representations.idm.ClientScopeRepresentation;
import org.keycloak.representations.idm.GroupRepresentation;
import org.keycloak.representations.idm.RealmRepresentation;
import org.keycloak.representations.idm.RoleRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.keycloak.representations.idm.authorization.AuthorizationRequest;
import org.keycloak.representations.idm.authorization.AuthorizationResponse;
import org.keycloak.representations.idm.authorization.PermissionRequest;
import org.keycloak.representations.idm.authorization.ResourcePermissionRepresentation;
import org.keycloak.representations.idm.authorization.ResourceRepresentation;
import org.keycloak.representations.idm.authorization.RolePolicyRepresentation;
import org.keycloak.testsuite.util.ApiUtil;
import org.keycloak.testsuite.util.ClientBuilder;
import org.keycloak.testsuite.util.GroupBuilder;
import org.keycloak.testsuite.util.RealmBuilder;
import org.keycloak.testsuite.util.RoleBuilder;
import org.keycloak.testsuite.util.RolesBuilder;
import org.keycloak.testsuite.util.UserBuilder;
import org.testcontainers.shaded.org.hamcrest.MatcherAssert;
import org.testcontainers.shaded.org.hamcrest.Matchers;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class RolePolicyTest extends AbstractAuthzTest {

    @Override
    public List<RealmRepresentation> getRealmsForImport() {
        List<RealmRepresentation> testRealms = new ArrayList<>();
        testRealms.add(RealmBuilder.create().name("authz-test")
                .roles(RolesBuilder.create()
                        .realmRole(RoleBuilder.create().name("uma_authorization").build())
                        .realmRole(RoleBuilder.create().name("Role A").build())
                        .realmRole(RoleBuilder.create().name("Role B").build())
                        .realmRole(RoleBuilder.create().name("Role C").build())
                )
                .group(GroupBuilder.create().name("Group A").realmRoles(Arrays.asList("Role A")).build())
                .group(GroupBuilder.create().name("Group B").realmRoles(Arrays.asList("Role C")).build())
                .user(UserBuilder.create().username("marta").password("password").addRoles("uma_authorization", "Role A"))
                .user(UserBuilder.create().username("kolo").password("password").addRoles("uma_authorization", "Role B"))
                .user(UserBuilder.create().username("alice").password("password").addRoles("uma_authorization").addGroups("Group B"))
                .client(ClientBuilder.create().clientId("resource-server-test")
                    .secret("secret")
                    .authorizationServicesEnabled(true)
                    .redirectUris("http://localhost/resource-server-test")
                    .defaultRoles("uma_protection")
                    .directAccessGrants())
                .build());
        return testRealms;
    }

    @BeforeEach
    public void configureAuthorization() throws Exception {
        createResource("Resource A");
        createResource("Resource B");
        createResource("Resource C");

        createRealmRolePolicy("Role A Policy", "Role A");
        createRealmRolePolicy("Role B Policy", "Role B");
        createRealmRolePolicy("Role C Policy", "Role C");

        createResourcePermission("Resource A Permission", "Resource A", "Role A Policy");
        createResourcePermission("Resource B Permission", "Resource B", "Role B Policy");
        createResourcePermission("Resource C Permission", "Resource C", "Role C Policy");
    }

    @Test
    public void testUserWithExpectedRole() {
        AuthzClient authzClient = getAuthzClient();
        PermissionRequest request = new PermissionRequest("Resource A");

        String ticket = authzClient.protection().permission().create(request).getTicket();
        AuthorizationResponse response = authzClient.authorization("marta", "password").authorize(new AuthorizationRequest(ticket));

        Assertions.assertNotNull(response.getToken());
    }

    @Test
    public void testUserWithoutExpectedRole() {
        AuthzClient authzClient = getAuthzClient();
        PermissionRequest request = new PermissionRequest("Resource A");
        String ticket1 = authzClient.protection().permission().create(request).getTicket();

        AuthorizationDeniedException ade = Assertions.assertThrows(AuthorizationDeniedException.class,
            () -> authzClient.authorization("kolo", "password").authorize(new AuthorizationRequest(ticket1)));
        MatcherAssert.assertThat(ade.getMessage(), Matchers.containsString("Forbidden"));

        request.setResourceId("Resource B");
        String ticket = authzClient.protection().permission().create(request).getTicket();
        Assertions.assertNotNull(authzClient.authorization("kolo", "password").authorize(new AuthorizationRequest(ticket)));

        UserRepresentation user = getRealm().users().search("kolo").get(0);
        RoleRepresentation roleA = getRealm().roles().get("Role A").toRepresentation();
        getRealm().users().get(user.getId()).roles().realmLevel().add(Arrays.asList(roleA));

        request.setResourceId("Resource A");
        ticket = authzClient.protection().permission().create(request).getTicket();
        Assertions.assertNotNull(authzClient.authorization("kolo", "password").authorize(new AuthorizationRequest(ticket)));
    }

    @Test
    public void testUserWithGroupRole() throws InterruptedException {
        AuthzClient authzClient = getAuthzClient();
        PermissionRequest request = new PermissionRequest();

        request.setResourceId("Resource C");

        String ticket1 = authzClient.protection().permission().create(request).getTicket();
        Assertions.assertNotNull(authzClient.authorization("alice", "password").authorize(new AuthorizationRequest(ticket1)));

        UserRepresentation user = getRealm().users().search("alice").get(0);
        GroupRepresentation groupB = getRealm().groups().groups().stream().filter(representation -> "Group B".equals(representation.getName())).findFirst().get();
        getRealm().users().get(user.getId()).leaveGroup(groupB.getId());

        AuthorizationDeniedException ade = Assertions.assertThrows(AuthorizationDeniedException.class,
            () -> authzClient.authorization("alice", "password").authorize(new AuthorizationRequest(ticket1)));
        MatcherAssert.assertThat(ade.getMessage(), Matchers.containsString("Forbidden"));

        request.setResourceId("Resource A");
        String ticket2 = authzClient.protection().permission().create(request).getTicket();

        ade = Assertions.assertThrows(AuthorizationDeniedException.class,
            () -> authzClient.authorization("alice", "password").authorize(new AuthorizationRequest(ticket2)));
        MatcherAssert.assertThat(ade.getMessage(), Matchers.containsString("Forbidden"));

        GroupRepresentation groupA = getRealm().groups().groups().stream().filter(representation -> "Group A".equals(representation.getName())).findFirst().get();
        getRealm().users().get(user.getId()).joinGroup(groupA.getId());

        Assertions.assertNotNull(authzClient.authorization("alice", "password").authorize(new AuthorizationRequest(ticket2)));
    }

    @Test
    @KeycloakVersion(min = "25.0.0") // fetchRoles added in 25
    public void testFetchRoles() {
        AuthzClient authzClient = getAuthzClient();
        RealmResource realm = getRealm();
        ClientsResource clients = realm.clients();
        ClientRepresentation client = clients.findByClientId(authzClient.getConfiguration().getResource()).get(0);
        ClientScopeRepresentation rolesScope = ApiUtil.findClientScopeByName(realm, "roles").toRepresentation();
        ClientResource clientResource = clients.get(client.getId());
        clientResource.removeDefaultClientScope(rolesScope.getId());
        PermissionRequest request = new PermissionRequest("Resource B");
        String ticket = authzClient.protection().permission().create(request).getTicket();
        AuthorizationDeniedException ade = Assertions.assertThrows(AuthorizationDeniedException.class,
            () -> authzClient.authorization("kolo", "password").authorize(new AuthorizationRequest(ticket)));
        MatcherAssert.assertThat(ade.getMessage(), Matchers.containsString("Forbidden"));

        RolePolicyRepresentation roleRep = clientResource.authorization().policies().role().findByName("Role B Policy");
        roleRep.setFetchRoles(true);
        clientResource.authorization().policies().role().findById(roleRep.getId()).update(roleRep);
        Assertions.assertNotNull(authzClient.authorization("kolo", "password").authorize(new AuthorizationRequest(ticket)));

        clientResource.addDefaultClientScope(rolesScope.getId());
    }

    @Test
    @KeycloakVersion(min = "25.0.0") // fetchRoles added in 25
    public void testFetchRolesUsingServiceAccount() {
        AuthzClient authzClient = getAuthzClient();
        RealmResource realm = getRealm();
        ClientsResource clients = realm.clients();
        ClientRepresentation client = clients.findByClientId(authzClient.getConfiguration().getResource()).get(0);
        ClientScopeResource rolesScopeRes = ApiUtil.findClientScopeByName(realm, "roles");
        ClientScopeRepresentation rolesScope = rolesScopeRes.toRepresentation();
        ClientResource clientResource = clients.get(client.getId());
        clientResource.removeDefaultClientScope(rolesScope.getId());
        UserRepresentation serviceAccountUser = clientResource.getServiceAccountUser();
        RoleRepresentation roleB = realm.roles().get("Role B").toRepresentation();
        realm.users().get(serviceAccountUser.getId()).roles().realmLevel().add(Collections.singletonList(roleB));
        RolePolicyRepresentation roleRep = clientResource.authorization().policies().role().findByName("Role B Policy");
        roleRep.setFetchRoles(true);
        clientResource.authorization().policies().role().findById(roleRep.getId()).update(roleRep);
        Assertions.assertNotNull(authzClient.authorization().authorize(new AuthorizationRequest()));

        clientResource.addDefaultClientScope(rolesScope.getId());
        roleRep.setFetchRoles(false);
        clientResource.authorization().policies().role().findById(roleRep.getId()).update(roleRep);
    }

    private void createRealmRolePolicy(String name, String... roles) {
        RolePolicyRepresentation policy = new RolePolicyRepresentation();

        policy.setName(name);

        for (String role : roles) {
            policy.addRole(role);
        }

        getClient().authorization().policies().role().create(policy).close();
    }

    private void createResourcePermission(String name, String resource, String... policies) {
        ResourcePermissionRepresentation permission = new ResourcePermissionRepresentation();

        permission.setName(name);
        permission.addResource(resource);
        permission.addPolicy(policies);

        getClient().authorization().permissions().resource().create(permission).close();
    }

    private void createResource(String name) {
        AuthorizationResource authorization = getClient().authorization();
        ResourceRepresentation resource = new ResourceRepresentation(name);

        authorization.resources().create(resource).close();
    }

    private RealmResource getRealm() {
        try {
            return adminClient.realm("authz-test");
        } catch (Exception e) {
            throw new RuntimeException("Failed to create admin client");
        }
    }

    private ClientResource getClient(RealmResource realm) {
        ClientsResource clients = realm.clients();
        return clients.findByClientId("resource-server-test").stream().map(representation -> clients.get(representation.getId())).findFirst().orElseThrow(() -> new RuntimeException("Expected client [resource-server-test]"));
    }

    private AuthzClient getAuthzClient() {
        return getAuthzClient("/authorization-test/default-keycloak.json");
    }

    private ClientResource getClient() {
        return getClient(getRealm());
    }
}