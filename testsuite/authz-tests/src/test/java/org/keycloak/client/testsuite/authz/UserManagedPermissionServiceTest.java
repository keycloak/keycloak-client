/*
 * Copyright 2022 Red Hat, Inc. and/or its affiliates
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

import jakarta.ws.rs.NotFoundException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.keycloak.admin.client.resource.ClientResource;
import org.keycloak.admin.client.resource.UsersResource;
import org.keycloak.authorization.client.AuthorizationDeniedException;
import org.keycloak.authorization.client.resource.AuthorizationResource;
import org.keycloak.authorization.client.resource.PolicyResource;
import org.keycloak.authorization.client.resource.ProtectionResource;
import org.keycloak.authorization.client.util.HttpResponseException;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.idm.RealmRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.keycloak.representations.idm.authorization.AuthorizationRequest;
import org.keycloak.representations.idm.authorization.AuthorizationResponse;
import org.keycloak.representations.idm.authorization.Permission;
import org.keycloak.representations.idm.authorization.PermissionRequest;
import org.keycloak.representations.idm.authorization.PermissionResponse;
import org.keycloak.representations.idm.authorization.PermissionTicketRepresentation;
import org.keycloak.representations.idm.authorization.PolicyRepresentation;
import org.keycloak.representations.idm.authorization.ResourceRepresentation;
import org.keycloak.representations.idm.authorization.UmaPermissionRepresentation;
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
public class UserManagedPermissionServiceTest extends AbstractResourceServerTest {

    @Override
    public List<RealmRepresentation> getRealmsForImport() {
        List<RealmRepresentation> testRealms = new ArrayList<>();
        testRealms.add(RealmBuilder.create().name(REALM_NAME)
                .roles(RolesBuilder.create()
                        .realmRole(RoleBuilder.create().name("uma_authorization").build())
                        .realmRole(RoleBuilder.create().name("uma_protection").build())
                        .realmRole(RoleBuilder.create().name("role_a").build())
                        .realmRole(RoleBuilder.create().name("role_b").build())
                        .realmRole(RoleBuilder.create().name("role_c").build())
                        .realmRole(RoleBuilder.create().name("role_d").build())
                )
                .group(GroupBuilder.create().name("group_a")
                        .subGroups(Arrays.asList(GroupBuilder.create().name("group_b").build()))
                        .build())
                .group(GroupBuilder.create().name("group_c").build())
                .group(GroupBuilder.create().name("group_remove").build())
                .user(UserBuilder.create().username("marta").password("password")
                        .addRoles("uma_authorization", "uma_protection")
                        .role("resource-server-test", "uma_protection"))
                .user(UserBuilder.create().username("alice").password("password")
                        .addRoles("uma_authorization", "uma_protection")
                        .role("resource-server-test", "uma_protection"))
                .user(UserBuilder.create().username("kolo").password("password")
                        .addRoles("role_a")
                        .addGroups("group_a"))
                .client(ClientBuilder.create().clientId("resource-server-test")
                        .secret("secret")
                        .authorizationServicesEnabled(true)
                        .redirectUris("http://localhost/resource-server-test")
                        .defaultRoles("uma_protection")
                        .directAccessGrants()
                        .serviceAccountsEnabled(true))
                .client(ClientBuilder.create().clientId("client-a")
                        .redirectUris("http://localhost/resource-server-test")
                        .publicClient())
                .client(ClientBuilder.create().clientId("client-remove")
                        .redirectUris("http://localhost/resource-server-test")
                        .publicClient())
                .build());
        return testRealms;
    }

    private void testCreate() {
        ResourceRepresentation resource = new ResourceRepresentation();

        resource.setName("Resource A");
        resource.setOwnerManagedAccess(true);
        resource.setOwner("marta");
        resource.addScope("Scope A", "Scope B", "Scope C");

        resource = getAuthzClient().protection().resource().create(resource);

        UmaPermissionRepresentation newPermission = new UmaPermissionRepresentation();

        newPermission.setName("Custom User-Managed Permission");
        newPermission.setDescription("Users from specific roles are allowed to access");
        newPermission.addScope("Scope A", "Scope B", "Scope C");
        newPermission.addRole("role_a", "role_b", "role_c", "role_d");
        newPermission.addGroup("/group_a", "/group_a/group_b", "/group_c");
        newPermission.addClient("client-a", "resource-server-test");

        newPermission.setCondition("script-scripts/default-policy.js");

        newPermission.addUser("kolo");

        ProtectionResource protection = getAuthzClient().protection("marta", "password");

        UmaPermissionRepresentation permission = protection.policy(resource.getId()).create(newPermission);

        Assertions.assertEquals(newPermission.getName(), permission.getName());
        Assertions.assertEquals(newPermission.getDescription(), permission.getDescription());
        Assertions.assertNotNull(permission.getScopes());
        Assertions.assertTrue(permission.getScopes().containsAll(newPermission.getScopes()));
        Assertions.assertNotNull(permission.getRoles());
        Assertions.assertTrue(permission.getRoles().containsAll(newPermission.getRoles()));
        Assertions.assertNotNull(permission.getGroups());
        Assertions.assertTrue(permission.getGroups().containsAll(newPermission.getGroups()));
        Assertions.assertNotNull(permission.getClients());
        Assertions.assertTrue(permission.getClients().containsAll(newPermission.getClients()));
        Assertions.assertEquals(newPermission.getCondition(), permission.getCondition());
        Assertions.assertNotNull(permission.getUsers());
        Assertions.assertTrue(permission.getUsers().containsAll(newPermission.getUsers()));
    }

    @Test
    public void testCreateDeprecatedFeaturesEnabled() {
        testCreate();
    }

    @Test
    public void testCreateDeprecatedFeaturesDisabled() {
        testCreate();
    }

    private void testUpdate() {
        ResourceRepresentation resource = new ResourceRepresentation();

        resource.setName("Resource A");
        resource.setOwnerManagedAccess(true);
        resource.setOwner("marta");
        resource.addScope("Scope A", "Scope B", "Scope C");

        resource = getAuthzClient().protection().resource().create(resource);

        UmaPermissionRepresentation permissionTmp = new UmaPermissionRepresentation();

        permissionTmp.setName("Custom User-Managed Permission");
        permissionTmp.setDescription("Users from specific roles are allowed to access");
        permissionTmp.addScope("Scope A");
        permissionTmp.addRole("role_a");

        ProtectionResource protection = getAuthzClient().protection("marta", "password");

        final UmaPermissionRepresentation permission = protection.policy(resource.getId()).create(permissionTmp);

        Assertions.assertEquals(1, getAssociatedPolicies(permission).size());

        permission.setName("Changed");
        permission.setDescription("Changed");

        protection.policy(resource.getId()).update(permission);

        UmaPermissionRepresentation updated = protection.policy(resource.getId()).findById(permission.getId());

        Assertions.assertEquals(permission.getName(), updated.getName());
        Assertions.assertEquals(permission.getDescription(), updated.getDescription());

        permission.removeRole("role_a");
        permission.addRole("role_b", "role_c");

        protection.policy(resource.getId()).update(permission);
        Assertions.assertEquals(1, getAssociatedPolicies(permission).size());
        updated = protection.policy(resource.getId()).findById(permission.getId());

        Assertions.assertTrue(permission.getRoles().containsAll(updated.getRoles()));

        permission.addRole("role_d");

        protection.policy(resource.getId()).update(permission);
        Assertions.assertEquals(1, getAssociatedPolicies(permission).size());
        updated = protection.policy(resource.getId()).findById(permission.getId());

        Assertions.assertTrue(permission.getRoles().containsAll(updated.getRoles()));

        permission.addGroup("/group_a/group_b");

        protection.policy(resource.getId()).update(permission);
        Assertions.assertEquals(2, getAssociatedPolicies(permission).size());
        updated = protection.policy(resource.getId()).findById(permission.getId());

        Assertions.assertTrue(permission.getGroups().containsAll(updated.getGroups()));

        permission.addGroup("/group_a");

        protection.policy(resource.getId()).update(permission);
        Assertions.assertEquals(2, getAssociatedPolicies(permission).size());
        updated = protection.policy(resource.getId()).findById(permission.getId());

        Assertions.assertTrue(permission.getGroups().containsAll(updated.getGroups()));

        permission.removeGroup("/group_a/group_b");
        permission.addGroup("/group_c");

        protection.policy(resource.getId()).update(permission);
        Assertions.assertEquals(2, getAssociatedPolicies(permission).size());
        updated = protection.policy(resource.getId()).findById(permission.getId());

        Assertions.assertTrue(permission.getGroups().containsAll(updated.getGroups()));

        permission.addClient("client-a");

        protection.policy(resource.getId()).update(permission);
        Assertions.assertEquals(3, getAssociatedPolicies(permission).size());
        updated = protection.policy(resource.getId()).findById(permission.getId());

        Assertions.assertTrue(permission.getClients().containsAll(updated.getClients()));

        permission.addClient("resource-server-test");

        protection.policy(resource.getId()).update(permission);
        Assertions.assertEquals(3, getAssociatedPolicies(permission).size());
        updated = protection.policy(resource.getId()).findById(permission.getId());

        Assertions.assertTrue(permission.getClients().containsAll(updated.getClients()));

        permission.removeClient("client-a");

        protection.policy(resource.getId()).update(permission);
        Assertions.assertEquals(3, getAssociatedPolicies(permission).size());
        updated = protection.policy(resource.getId()).findById(permission.getId());

        Assertions.assertTrue(permission.getClients().containsAll(updated.getClients()));

        permission.setCondition("script-scripts/default-policy.js");

        protection.policy(resource.getId()).update(permission);
        Assertions.assertEquals(4, getAssociatedPolicies(permission).size());
        updated = protection.policy(resource.getId()).findById(permission.getId());

        Assertions.assertEquals(permission.getCondition(), updated.getCondition());

        permission.addUser("alice");

        protection.policy(resource.getId()).update(permission);

        int expectedPolicies = 5;

        Assertions.assertEquals(expectedPolicies, getAssociatedPolicies(permission).size());
        updated = protection.policy(resource.getId()).findById(permission.getId());
        Assertions.assertEquals(1, updated.getUsers().size());
        Assertions.assertEquals(permission.getUsers(), updated.getUsers());

        permission.addUser("kolo");

        protection.policy(resource.getId()).update(permission);
        Assertions.assertEquals(expectedPolicies, getAssociatedPolicies(permission).size());
        updated = protection.policy(resource.getId()).findById(permission.getId());
        Assertions.assertEquals(2, updated.getUsers().size());
        Assertions.assertEquals(permission.getUsers(), updated.getUsers());

        permission.removeUser("alice");

        protection.policy(resource.getId()).update(permission);
        Assertions.assertEquals(expectedPolicies, getAssociatedPolicies(permission).size());
        updated = protection.policy(resource.getId()).findById(permission.getId());
        Assertions.assertEquals(1, updated.getUsers().size());
        Assertions.assertEquals(permission.getUsers(), updated.getUsers());

        permission.setUsers(null);

        protection.policy(resource.getId()).update(permission);
        Assertions.assertEquals(--expectedPolicies, getAssociatedPolicies(permission).size());
        updated = protection.policy(resource.getId()).findById(permission.getId());

        Assertions.assertEquals(permission.getUsers(), updated.getUsers());

        permission.setCondition(null);

        protection.policy(resource.getId()).update(permission);
        Assertions.assertEquals(--expectedPolicies, getAssociatedPolicies(permission).size());
        updated = protection.policy(resource.getId()).findById(permission.getId());

        Assertions.assertEquals(permission.getCondition(), updated.getCondition());

        permission.setRoles(null);

        protection.policy(resource.getId()).update(permission);
        Assertions.assertEquals(--expectedPolicies, getAssociatedPolicies(permission).size());
        updated = protection.policy(resource.getId()).findById(permission.getId());

        Assertions.assertEquals(permission.getRoles(), updated.getRoles());

        permission.setClients(null);

        protection.policy(resource.getId()).update(permission);
        Assertions.assertEquals(--expectedPolicies, getAssociatedPolicies(permission).size());
        updated = protection.policy(resource.getId()).findById(permission.getId());

        Assertions.assertEquals(permission.getClients(), updated.getClients());

        permission.setGroups(null);

        protection.policy(resource.getId()).update(permission);

        NotFoundException nfe = Assertions.assertThrows(NotFoundException.class, () -> getAssociatedPolicies(permission));
        Assertions.assertEquals(404, nfe.getResponse().getStatus());
    }

    @Test
    public void testUpdatePermission() {
        testUpdate();
    }

    @Test
    public void testUploadScriptDisabled() {
        ResourceRepresentation resourceTmp = new ResourceRepresentation();

        resourceTmp.setName("Resource A");
        resourceTmp.setOwnerManagedAccess(true);
        resourceTmp.setOwner("marta");
        resourceTmp.addScope("Scope A", "Scope B", "Scope C");

        final ResourceRepresentation resource = getAuthzClient().protection().resource().create(resourceTmp);

        ProtectionResource protection = getAuthzClient().protection("marta", "password");

        UmaPermissionRepresentation newPermission = new UmaPermissionRepresentation();
        newPermission.setName("Custom User-Managed Permission");
        newPermission.setDescription("Users from specific roles are allowed to access");
        newPermission.setCondition("$evaluation.grant()");

        RuntimeException re = Assertions.assertThrows(RuntimeException.class,
                () -> protection.policy(resource.getId()).create(newPermission));
        MatcherAssert.assertThat(re.getCause(), Matchers.instanceOf(HttpResponseException.class));
    }

    @Test
    public void testUserManagedPermission() {
        ResourceRepresentation resourceTmp = new ResourceRepresentation();

        resourceTmp.setName("Resource A");
        resourceTmp.setOwnerManagedAccess(true);
        resourceTmp.setOwner("marta");
        resourceTmp.addScope("Scope A", "Scope B", "Scope C");

        final ResourceRepresentation resource = getAuthzClient().protection().resource().create(resourceTmp);

        UmaPermissionRepresentation permissionTmp = new UmaPermissionRepresentation();

        permissionTmp.setName("Custom User-Managed Permission");
        permissionTmp.setDescription("Users from specific roles are allowed to access");
        permissionTmp.addScope("Scope A");
        permissionTmp.addRole("role_a");

        ProtectionResource protection = getAuthzClient().protection("marta", "password");

        final UmaPermissionRepresentation permission = protection.policy(resource.getId()).create(permissionTmp);

        AuthorizationResource authorization = getAuthzClient().authorization("kolo", "password");

        AuthorizationRequest request = new AuthorizationRequest();

        request.addPermission(resource.getId(), "Scope A");

        AuthorizationResponse authzResponse = authorization.authorize(request);

        Assertions.assertNotNull(authzResponse);

        permission.removeRole("role_a");
        permission.addRole("role_b");

        protection.policy(resource.getId()).update(permission);

        AuthorizationDeniedException ade = Assertions.assertThrows(AuthorizationDeniedException.class,
                () -> authorization.authorize(request));
        MatcherAssert.assertThat(ade.getMessage(), Matchers.containsString("Forbidden"));

        ade = Assertions.assertThrows(AuthorizationDeniedException.class,
                () -> getAuthzClient().authorization("alice", "password").authorize(request));
        MatcherAssert.assertThat(ade.getMessage(), Matchers.containsString("Forbidden"));

        permission.addRole("role_a");

        protection.policy(resource.getId()).update(permission);

        authzResponse = authorization.authorize(request);

        Assertions.assertNotNull(authzResponse);

        protection.policy(resource.getId()).delete(permission.getId());

        ade = Assertions.assertThrows(AuthorizationDeniedException.class,
                () -> authorization.authorize(request));
        MatcherAssert.assertThat(ade.getMessage(), Matchers.containsString("Forbidden"));

        RuntimeException re = Assertions.assertThrows(RuntimeException.class,
                () -> getAuthzClient().protection("marta", "password").policy(resource.getId()).findById(permission.getId()));
        MatcherAssert.assertThat(re.getCause(), Matchers.instanceOf(HttpResponseException.class));
        Assertions.assertEquals(404, HttpResponseException.class.cast(re.getCause()).getStatusCode());

        // create a user based permission, where only selected users are allowed access to the resource.
        final UmaPermissionRepresentation permission2 = new UmaPermissionRepresentation();
        permission2.setName("Custom User-Managed Permission");
        permission2.setDescription("Specific users are allowed access to the resource");
        permission2.addScope("Scope A");
        permission2.addUser("alice");
        protection.policy(resource.getId()).create(permission2);

        // alice should be able to access the resource with the updated permission.
        authzResponse = getAuthzClient().authorization("alice", "password").authorize(request);
        Assertions.assertNotNull(authzResponse);

        // kolo shouldn't be able to access the resource with the updated permission.
        ade = Assertions.assertThrows(AuthorizationDeniedException.class,
                () -> authorization.authorize(request));
        MatcherAssert.assertThat(ade.getMessage(), Matchers.containsString("Forbidden"));
    }

    @Test
    public void testRemovePolicyWhenOwnerDeleted() {
        final ClientResource client = getClient(getRealm());

        ResourceRepresentation resource = new ResourceRepresentation();

        resource.setName("Resource A");
        resource.setOwnerManagedAccess(true);
        resource.setOwner("marta");
        resource.addScope("Scope A", "Scope B", "Scope C");

        resource = getAuthzClient().protection().resource().create(resource);

        UmaPermissionRepresentation permission = new UmaPermissionRepresentation();

        permission.setName("Custom User-Managed Permission");
        permission.addUser("kolo");

        ProtectionResource protection = getAuthzClient().protection("marta", "password");

        permission = protection.policy(resource.getId()).create(permission);
        PolicyRepresentation policy = client.authorization().policies().policy(permission.getId()).toRepresentation();

        AuthorizationResource authorization = getAuthzClient().authorization("kolo", "password");

        AuthorizationRequest request = new AuthorizationRequest();

        request.addPermission(resource.getId(), "Scope A");

        AuthorizationResponse authzResponse = authorization.authorize(request);

        Assertions.assertNotNull(authzResponse);

        UsersResource users = adminClient.realm(REALM_NAME).users();
        UserRepresentation marta = users.search("marta").get(0);

        users.delete(marta.getId());

        NotFoundException nfe = Assertions.assertThrows(NotFoundException.class,
                () -> client.authorization().policies().policy(policy.getId()).toRepresentation());
        Assertions.assertEquals(404, nfe.getResponse().getStatus());
    }

    @Test
    public void testPermissionInAdditionToUserGrantedPermission() {
        ResourceRepresentation resource = new ResourceRepresentation();

        resource.setName("Resource A");
        resource.setOwnerManagedAccess(true);
        resource.setOwner("marta");
        resource.addScope("Scope A", "Scope B", "Scope C");

        resource = getAuthzClient().protection().resource().create(resource);

        PermissionResponse ticketResponse = getAuthzClient().protection().permission().create(new PermissionRequest(resource.getId(), "Scope A"));

        AuthorizationRequest request1 = new AuthorizationRequest();

        request1.setTicket(ticketResponse.getTicket());

        AuthorizationDeniedException ade = Assertions.assertThrows(AuthorizationDeniedException.class,
                () -> getAuthzClient().authorization("kolo", "password").authorize(request1));
        MatcherAssert.assertThat(ade.getMessage(), Matchers.containsString("request_submitted"));

        List<PermissionTicketRepresentation> tickets = getAuthzClient().protection().permission().findByResource(resource.getId());

        Assertions.assertEquals(1, tickets.size());

        PermissionTicketRepresentation ticket = tickets.get(0);

        ticket.setGranted(true);

        getAuthzClient().protection().permission().update(ticket);

        AuthorizationResponse authzResponse = getAuthzClient().authorization("kolo", "password").authorize(request1);

        Assertions.assertNotNull(authzResponse);

        UmaPermissionRepresentation permission = new UmaPermissionRepresentation();

        permission.setName("Custom User-Managed Permission");
        permission.addScope("Scope A");
        permission.addRole("role_a");

        ProtectionResource protection = getAuthzClient().protection("marta", "password");

        permission = protection.policy(resource.getId()).create(permission);

        getAuthzClient().authorization("kolo", "password").authorize(request1);

        ticket.setGranted(false);

        getAuthzClient().protection().permission().update(ticket);

        getAuthzClient().authorization("kolo", "password").authorize(request1);

        permission = getAuthzClient().protection("marta", "password").policy(resource.getId()).findById(permission.getId());

        Assertions.assertNotNull(permission);

        permission.removeRole("role_a");
        permission.addRole("role_b");

        getAuthzClient().protection("marta", "password").policy(resource.getId()).update(permission);

        ade = Assertions.assertThrows(AuthorizationDeniedException.class,
                () -> getAuthzClient().authorization("kolo", "password").authorize(request1));
        MatcherAssert.assertThat(ade.getMessage(), Matchers.containsString("Forbidden"));

        AuthorizationRequest request2 = new AuthorizationRequest();

        request2.addPermission(resource.getId());

        ade = Assertions.assertThrows(AuthorizationDeniedException.class,
                () -> getAuthzClient().authorization("kolo", "password").authorize(request2));
        MatcherAssert.assertThat(ade.getMessage(), Matchers.containsString("Forbidden"));

        getAuthzClient().protection("marta", "password").policy(resource.getId()).delete(permission.getId());

        ade = Assertions.assertThrows(AuthorizationDeniedException.class,
                () -> getAuthzClient().authorization("kolo", "password").authorize(request2));
        MatcherAssert.assertThat(ade.getMessage(), Matchers.containsString("Forbidden"));
    }

    @Test
    public void testPermissionWithoutScopes() {
        ResourceRepresentation resource = new ResourceRepresentation();

        resource.setName(UUID.randomUUID().toString());
        resource.setOwner("marta");
        resource.setOwnerManagedAccess(true);
        resource.addScope("Scope A", "Scope B", "Scope C");

        ProtectionResource protection = getAuthzClient().protection();

        resource = protection.resource().create(resource);

        UmaPermissionRepresentation permission = new UmaPermissionRepresentation();

        permission.setName("Custom User-Managed Policy");
        permission.addRole("role_a");

        PolicyResource policy = getAuthzClient().protection("marta", "password").policy(resource.getId());

        permission = policy.create(permission);

        Assertions.assertEquals(3, permission.getScopes().size());
        Assertions.assertTrue(Arrays.asList("Scope A", "Scope B", "Scope C").containsAll(permission.getScopes()));

        permission = policy.findById(permission.getId());

        Assertions.assertTrue(Arrays.asList("Scope A", "Scope B", "Scope C").containsAll(permission.getScopes()));
        Assertions.assertEquals(3, permission.getScopes().size());

        permission.removeScope("Scope B");

        policy.update(permission);
        permission = policy.findById(permission.getId());

        Assertions.assertEquals(2, permission.getScopes().size());
        Assertions.assertTrue(Arrays.asList("Scope A", "Scope C").containsAll(permission.getScopes()));
    }

    @Test
    public void testOnlyResourceOwnerCanManagePolicies() {
        ResourceRepresentation resourceTmp = new ResourceRepresentation();

        resourceTmp.setName(UUID.randomUUID().toString());
        resourceTmp.setOwner("marta");
        resourceTmp.addScope("Scope A", "Scope B", "Scope C");

        ProtectionResource protection = getAuthzClient().protection();

        final ResourceRepresentation resource = protection.resource().create(resourceTmp);

        RuntimeException re = Assertions.assertThrows(RuntimeException.class,
                () -> getAuthzClient().protection("alice", "password").policy(resource.getId()).create(new UmaPermissionRepresentation()));
        MatcherAssert.assertThat(re.getCause(), Matchers.instanceOf(HttpResponseException.class));
        Assertions.assertEquals(400, HttpResponseException.class.cast(re.getCause()).getStatusCode());
        MatcherAssert.assertThat(HttpResponseException.class.cast(re.getCause()).toString(),
                Matchers.containsString("Only resource owner can access policies for resource"));
    }

    @Test
    public void testOnlyResourcesWithOwnerManagedAccess() {
        ResourceRepresentation resourceTmp = new ResourceRepresentation();

        resourceTmp.setName(UUID.randomUUID().toString());
        resourceTmp.setOwner("marta");
        resourceTmp.addScope("Scope A", "Scope B", "Scope C");

        ProtectionResource protection = getAuthzClient().protection();

        final ResourceRepresentation resource = protection.resource().create(resourceTmp);

        RuntimeException re = Assertions.assertThrows(RuntimeException.class,
                () -> getAuthzClient().protection("marta", "password").policy(resource.getId()).create(new UmaPermissionRepresentation()));
        MatcherAssert.assertThat(re.getCause(), Matchers.instanceOf(HttpResponseException.class));
        Assertions.assertEquals(400, HttpResponseException.class.cast(re.getCause()).getStatusCode());
        MatcherAssert.assertThat(HttpResponseException.class.cast(re.getCause()).toString(),
        Matchers.containsString("Only resources with owner managed accessed can have policies"));
    }

    @Test
    public void testOwnerAccess() {
        ResourceRepresentation resource = new ResourceRepresentation();

        resource.setName(UUID.randomUUID().toString());
        resource.setOwner("marta");
        resource.addScope("Scope A", "Scope B", "Scope C");
        resource.setOwnerManagedAccess(true);

        ProtectionResource protection = getAuthzClient().protection();

        resource = protection.resource().create(resource);

        UmaPermissionRepresentation rep = new UmaPermissionRepresentation();
        rep.setName("test");
        rep.addRole("role_b");

        rep = getAuthzClient().protection("marta", "password").policy(resource.getId()).create(rep);

        AuthorizationResource authorization = getAuthzClient().authorization("marta", "password");

        AuthorizationRequest request = new AuthorizationRequest();

        request.addPermission(resource.getId(), "Scope A");

        AuthorizationResponse authorize = authorization.authorize(request);

        Assertions.assertNotNull(authorize);

        AuthorizationDeniedException ade = Assertions.assertThrows(AuthorizationDeniedException.class,
                () -> getAuthzClient().authorization("kolo", "password").authorize(request));
        MatcherAssert.assertThat(ade.getMessage(), Matchers.containsString("Forbidden"));

        rep.addRole("role_a");

        getAuthzClient().protection("marta", "password").policy(resource.getId()).update(rep);

        authorization = getAuthzClient().authorization("kolo", "password");

        Assertions.assertNotNull(authorization.authorize(request));
    }

    @Test
    public void testFindPermission() {
        ResourceRepresentation resource = new ResourceRepresentation();

        resource.setName(UUID.randomUUID().toString());
        resource.setOwner("marta");
        resource.setOwnerManagedAccess(true);
        resource.addScope("Scope A", "Scope B", "Scope C");

        ProtectionResource protection = getAuthzClient().protection();

        resource = protection.resource().create(resource);

        PolicyResource policy = getAuthzClient().protection("marta", "password").policy(resource.getId());

        for (int i = 0; i < 10; i++) {
            UmaPermissionRepresentation permission = new UmaPermissionRepresentation();

            permission.setName("Custom User-Managed Policy " + i);
            permission.addRole("role_a");

            policy.create(permission);
        }

        Assertions.assertEquals(10, policy.find(null, null, null, null).size());

        List<UmaPermissionRepresentation> byId = policy.find("Custom User-Managed Policy 8", null, null, null);

        Assertions.assertEquals(1, byId.size());
        Assertions.assertEquals(byId.get(0).getId(), policy.findById(byId.get(0).getId()).getId());
        Assertions.assertEquals(10, policy.find(null, "Scope A", null, null).size());
        Assertions.assertEquals(5, policy.find(null, null, -1, 5).size());
        Assertions.assertEquals(2, policy.find(null, null, -1, 2).size());
    }

    @Test
    public void testGrantRequestedScopesOnly() {
        ResourceRepresentation resource = new ResourceRepresentation();

        resource.setName(UUID.randomUUID().toString());
        resource.setOwnerManagedAccess(true);
        resource.setOwner("marta");
        resource.addScope("view", "delete");

        ProtectionResource protection = getAuthzClient().protection("marta", "password");

        resource = protection.resource().create(resource);

        UmaPermissionRepresentation permission = new UmaPermissionRepresentation();

        permission.setName("Custom User-Managed Permission");
        permission.addScope("view");
        permission.addUser("kolo");

        protection.policy(resource.getId()).create(permission);

        AuthorizationRequest request1 = new AuthorizationRequest();

        request1.addPermission(resource.getId(), "view");

        AuthorizationResponse response = getAuthzClient().authorization("kolo", "password").authorize(request1);
        AccessToken rpt = toAccessToken(response.getToken());
        Collection<Permission> permissions = rpt.getAuthorization().getPermissions();

        assertPermissions(permissions, resource.getId(), "view");

        Assertions.assertTrue(permissions.isEmpty());

        AuthorizationRequest request2 = new AuthorizationRequest();

        request2.addPermission(resource.getId(), "delete");

        AuthorizationDeniedException ade = Assertions.assertThrows(AuthorizationDeniedException.class,
                () -> getAuthzClient().authorization("kolo", "password").authorize(request2));
        MatcherAssert.assertThat(ade.getMessage(), Matchers.containsString("Forbidden"));

        AuthorizationRequest request3 = new AuthorizationRequest();

        request3.addPermission(resource.getId(), "delete");

        ade = Assertions.assertThrows(AuthorizationDeniedException.class,
                () -> getAuthzClient().authorization("kolo", "password").authorize(request3));
        MatcherAssert.assertThat(ade.getMessage(), Matchers.containsString("Forbidden"));

        AuthorizationRequest request4 = new AuthorizationRequest();

        request4.addPermission(resource.getId());

        response = getAuthzClient().authorization("kolo", "password").authorize(request4);
        rpt = toAccessToken(response.getToken());
        permissions = rpt.getAuthorization().getPermissions();

        assertPermissions(permissions, resource.getId(), "view");

        Assertions.assertTrue(permissions.isEmpty());
    }

    @Test
    public void testDoNotGrantPermissionWhenObtainAllEntitlements() {
        ResourceRepresentation resource = new ResourceRepresentation();

        resource.setName("Resource A");
        resource.setOwnerManagedAccess(true);
        resource.setOwner("marta");
        resource.addScope("Scope A", "Scope B", "Scope C");

        resource = getAuthzClient().protection().resource().create(resource);

        UmaPermissionRepresentation permission = new UmaPermissionRepresentation();

        permission.setName("Custom User-Managed Permission");
        permission.addScope("Scope A", "Scope B");
        permission.addUser("kolo");

        ProtectionResource protection = getAuthzClient().protection("marta", "password");

        protection.policy(resource.getId()).create(permission);

        AuthorizationResource authorization = getAuthzClient().authorization("kolo", "password");

        AuthorizationRequest request = new AuthorizationRequest();

        request.addPermission(resource.getId(), "Scope A", "Scope B");

        AuthorizationResponse authzResponse = authorization.authorize(request);
        Assertions.assertNotNull(authzResponse);

        AccessToken token = toAccessToken(authzResponse.getToken());
        Assertions.assertNotNull(token.getAuthorization());

        Collection<Permission> permissions = token.getAuthorization().getPermissions();
        Assertions.assertEquals(1, permissions.size());

        Assertions.assertTrue(permissions
                .iterator().next().getScopes().containsAll(Arrays.asList("Scope A", "Scope B")));

        AuthorizationDeniedException ade = Assertions.assertThrows(AuthorizationDeniedException.class,
                () -> getAuthzClient().authorization("kolo", "password").authorize());
        MatcherAssert.assertThat(ade.getMessage(), Matchers.containsString("Forbidden"));
    }

    @Test
    public void testRemovePoliciesOnResourceDelete() {
        final ClientResource client = getClient(getRealm());

        ResourceRepresentation resource = new ResourceRepresentation();

        resource.setName("Resource A");
        resource.setOwnerManagedAccess(true);
        resource.setOwner("marta");
        resource.addScope("Scope A", "Scope B", "Scope C");

        resource = getAuthzClient().protection().resource().create(resource);

        UmaPermissionRepresentation newPermission = new UmaPermissionRepresentation();

        newPermission.setName("Custom User-Managed Permission");
        newPermission.setDescription("Users from specific roles are allowed to access");
        newPermission.addScope("Scope A", "Scope B", "Scope C");
        newPermission.addRole("role_a", "role_b", "role_c", "role_d");
        newPermission.addGroup("/group_a", "/group_a/group_b", "/group_c");
        newPermission.addClient("client-a", "resource-server-test");

        newPermission.setCondition("script-scripts/default-policy.js");

        newPermission.addUser("kolo");

        ProtectionResource protection = getAuthzClient().protection("marta", "password");

        newPermission = protection.policy(resource.getId()).create(newPermission);
        PolicyRepresentation policy = client.authorization().policies().policy(newPermission.getId()).toRepresentation();

        client.authorization().resources().resource(resource.getId()).remove();

        NotFoundException nfe = Assertions.assertThrows(NotFoundException.class,
                () -> client.authorization().policies().policy(policy.getId()).toRepresentation());
        Assertions.assertEquals(404, nfe.getResponse().getStatus());
    }

    private List<PolicyRepresentation> getAssociatedPolicies(UmaPermissionRepresentation permission) {
        return getClient(getRealm()).authorization().policies().policy(permission.getId()).associatedPolicies();
    }
}