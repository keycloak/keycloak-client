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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.stream.Collectors;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.keycloak.admin.client.resource.AuthorizationResource;
import org.keycloak.admin.client.resource.ResourceScopesResource;
import org.keycloak.authorization.client.AuthorizationDeniedException;
import org.keycloak.authorization.client.AuthzClient;
import org.keycloak.authorization.client.util.HttpResponseException;
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.representations.idm.UserRepresentation;
import org.keycloak.representations.idm.authorization.AuthorizationRequest;
import org.keycloak.representations.idm.authorization.Permission;
import org.keycloak.representations.idm.authorization.PermissionRequest;
import org.keycloak.representations.idm.authorization.PermissionResponse;
import org.keycloak.representations.idm.authorization.PermissionTicketRepresentation;
import org.keycloak.representations.idm.authorization.PermissionTicketToken;
import org.keycloak.representations.idm.authorization.ResourceRepresentation;
import org.keycloak.representations.idm.authorization.ScopeRepresentation;
import org.keycloak.testsuite.util.ApiUtil;
import org.keycloak.testsuite.util.UserBuilder;
import org.testcontainers.shaded.org.hamcrest.MatcherAssert;
import org.testcontainers.shaded.org.hamcrest.Matchers;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class PermissionManagementTest extends AbstractResourceServerTest {

    @Test
    public void testCreatePermissionTicketWithResourceName() throws Exception {
        ResourceRepresentation resource = addResource("Resource A", "kolo", true);
        AuthzClient authzClient = getAuthzClient();
        PermissionResponse response = authzClient.protection("marta", "password").permission().create(new PermissionRequest(resource.getId()));
        AuthorizationRequest request = new AuthorizationRequest();
        request.setTicket(response.getTicket());
        request.setClaimToken(authzClient.obtainAccessToken("marta", "password").getToken());
        AuthorizationDeniedException ex = Assertions.assertThrows(AuthorizationDeniedException.class,
                () -> authzClient.authorization().authorize(request));
        MatcherAssert.assertThat(ex.getMessage(), Matchers.containsString("Unexpected response from server: 403"));

        assertPersistence(response, resource);
    }

    @Test
    public void removeUserWithPermissionTicketTest() throws Exception {
        String userToRemoveID = ApiUtil.createUserWithAdminClient(getRealm(), UserBuilder.create().username("user-to-remove").password("password").build());

        ResourceRepresentation resource = addResource("Resource A", "kolo", true);
        AuthzClient authzClient = getAuthzClient();
        PermissionResponse response = authzClient.protection("user-to-remove", "password").permission().create(new PermissionRequest(resource.getId()));
        AuthorizationRequest request = new AuthorizationRequest();
        request.setTicket(response.getTicket());
        request.setClaimToken(authzClient.obtainAccessToken("user-to-remove", "password").getToken());
        AuthorizationDeniedException ex = Assertions.assertThrows(AuthorizationDeniedException.class,
                () -> authzClient.authorization().authorize(request));
        MatcherAssert.assertThat(ex.getMessage(), Matchers.containsString("Unexpected response from server: 403"));
        assertPersistence(response, resource);

        // Remove the user and expect the user and also hers permission tickets are successfully removed
        adminClient.realm(REALM_NAME).users().delete(userToRemoveID);
        MatcherAssert.assertThat(adminClient.realm(REALM_NAME).users().list().stream().map(UserRepresentation::getId).collect(Collectors.toList()),
                Matchers.not(Matchers.hasItem(userToRemoveID)));
        MatcherAssert.assertThat(getAuthzClient().protection().permission().findByResource(resource.getId()), Matchers.is(Matchers.empty()));
    }

    @Test
    public void testCreatePermissionTicketWithResourceId() throws Exception {
        ResourceRepresentation resource = addResource("Resource A", "kolo", true);
        AuthzClient authzClient = getAuthzClient();
        PermissionResponse response = authzClient.protection("marta", "password").permission().create(new PermissionRequest(resource.getId()));
        AuthorizationRequest request = new AuthorizationRequest();
        request.setTicket(response.getTicket());
        request.setClaimToken(authzClient.obtainAccessToken("marta", "password").getToken());

        AuthorizationDeniedException ex = Assertions.assertThrows(AuthorizationDeniedException.class,
                () -> authzClient.authorization().authorize(request));
        MatcherAssert.assertThat(ex.getMessage(), Matchers.containsString("Unexpected response from server: 403"));
        Assertions.assertNotNull(response.getTicket());
        Assertions.assertFalse(authzClient.protection().permission().findByResource(resource.getId()).isEmpty());
    }

    @Test
    public void testCreatePermissionTicketWithScopes() throws Exception {
        ResourceRepresentation resource = addResource("Resource A", "kolo", true, "ScopeA", "ScopeB", "ScopeC");
        AuthzClient authzClient = getAuthzClient();
        PermissionResponse response = authzClient.protection("marta", "password").permission().create(new PermissionRequest(resource.getId(), "ScopeA", "ScopeB", "ScopeC"));
        AuthorizationRequest request = new AuthorizationRequest();
        request.setTicket(response.getTicket());
        request.setClaimToken(authzClient.obtainAccessToken("marta", "password").getToken());

        AuthorizationDeniedException ex = Assertions.assertThrows(AuthorizationDeniedException.class,
                () -> authzClient.authorization().authorize(request));
        MatcherAssert.assertThat(ex.getMessage(), Matchers.containsString("Unexpected response from server: 403"));
        assertPersistence(response, resource, "ScopeA", "ScopeB", "ScopeC");
    }

    @Test
    public void testDeleteResourceAndPermissionTicket() throws Exception {
        ResourceRepresentation resource = addResource("Resource A", "kolo", true, "ScopeA", "ScopeB", "ScopeC");
        AuthzClient authzClient = getAuthzClient();
        PermissionResponse response = authzClient.protection("marta", "password").permission().create(new PermissionRequest(resource.getId(), "ScopeA", "ScopeB", "ScopeC"));
        AuthorizationRequest request = new AuthorizationRequest();
        request.setTicket(response.getTicket());
        request.setClaimToken(authzClient.obtainAccessToken("marta", "password").getToken());

        AuthorizationDeniedException ex = Assertions.assertThrows(AuthorizationDeniedException.class,
                () -> authzClient.authorization().authorize(request));
        MatcherAssert.assertThat(ex.getMessage(), Matchers.containsString("Unexpected response from server: 403"));

        assertPersistence(response, resource, "ScopeA", "ScopeB", "ScopeC");

        getAuthzClient().protection().resource().delete(resource.getId());
        Assertions.assertTrue(getAuthzClient().protection().permission().findByResource(resource.getId()).isEmpty());
    }

    @Test
    public void testMultiplePermissionRequest() throws Exception {
        List<PermissionRequest> permissions = new ArrayList<>();

        permissions.add(new PermissionRequest(addResource("Resource A", true).getName()));
        permissions.add(new PermissionRequest(addResource("Resource B", true).getName()));
        permissions.add(new PermissionRequest(addResource("Resource C", true).getName()));
        permissions.add(new PermissionRequest(addResource("Resource D", true).getName()));

        PermissionResponse response = getAuthzClient().protection().permission().create(permissions);
        Assertions.assertNotNull(response.getTicket());
    }

    @Test
    public void testDeleteScopeAndPermissionTicket() throws Exception {
        ResourceRepresentation resource = addResource("Resource A", "kolo", true, "ScopeA", "ScopeB", "ScopeC");
        PermissionRequest permissionRequest = new PermissionRequest(resource.getId());

        permissionRequest.setScopes(new HashSet<>(Arrays.asList("ScopeA", "ScopeB", "ScopeC")));

        AuthzClient authzClient = getAuthzClient();
        PermissionResponse response = authzClient.protection("marta", "password").permission().create(permissionRequest);
        Assertions.assertNotNull(response.getTicket());

        AuthorizationRequest request = new AuthorizationRequest();
        request.setTicket(response.getTicket());
        request.setClaimToken(authzClient.obtainAccessToken("marta", "password").getToken());

        AuthorizationDeniedException ex = Assertions.assertThrows(AuthorizationDeniedException.class,
                () -> authzClient.authorization().authorize(request));
        MatcherAssert.assertThat(ex.getMessage(), Matchers.containsString("Unexpected response from server: 403"));

        Assertions.assertEquals(3, authzClient.protection().permission().findByResource(resource.getId()).size());

        AuthorizationResource authorization = getClient(getRealm()).authorization();
        ResourceScopesResource scopes = authorization.scopes();
        ScopeRepresentation scope = scopes.findByName("ScopeA");

        List permissions = authzClient.protection().permission().findByScope(scope.getId());
        Assertions.assertFalse(permissions.isEmpty());
        Assertions.assertEquals(1, permissions.size());

        resource.setScopes(Collections.emptySet());
        authorization.resources().resource(resource.getId()).update(resource);
        scopes.scope(scope.getId()).remove();

        Assertions.assertTrue(authzClient.protection().permission().findByScope(scope.getId()).isEmpty());
        Assertions.assertEquals(0, authzClient.protection().permission().findByResource(resource.getId()).size());
    }

    @Test
    public void testRemoveScopeFromResource() throws Exception {
        ResourceRepresentation resource = addResource("Resource A", "kolo", true, "ScopeA", "ScopeB");
        PermissionRequest permissionRequest = new PermissionRequest(resource.getId(), "ScopeA", "ScopeB");
        AuthzClient authzClient = getAuthzClient();
        PermissionResponse response = authzClient.protection("marta", "password").permission().create(permissionRequest);

        Assertions.assertNotNull(response.getTicket());

        AuthorizationRequest request = new AuthorizationRequest();
        request.setTicket(response.getTicket());
        request.setClaimToken(authzClient.obtainAccessToken("marta", "password").getToken());

        AuthorizationDeniedException ex = Assertions.assertThrows(AuthorizationDeniedException.class,
                () -> authzClient.authorization().authorize(request));
        MatcherAssert.assertThat(ex.getMessage(), Matchers.containsString("Unexpected response from server: 403"));

        AuthorizationResource authorization = getClient(getRealm()).authorization();
        ResourceScopesResource scopes = authorization.scopes();
        ScopeRepresentation removedScope = scopes.findByName("ScopeA");
        List permissions = authzClient.protection().permission().findByScope(removedScope.getId());
        Assertions.assertFalse(permissions.isEmpty());

        resource.setScopes(new HashSet<>());
        resource.addScope("ScopeB");

        authorization.resources().resource(resource.getId()).update(resource);
        permissions = authzClient.protection().permission().findByScope(removedScope.getId());
        Assertions.assertTrue(permissions.isEmpty());

        ScopeRepresentation scopeB = scopes.findByName("ScopeB");
        permissions = authzClient.protection().permission().findByScope(scopeB.getId());
        Assertions.assertFalse(permissions.isEmpty());
    }

    @Test
    public void testCreatePermissionTicketWithResourceWithoutManagedAccess() throws Exception {
        ResourceRepresentation resource = addResource("Resource A");
        PermissionResponse response = getAuthzClient().protection().permission().create(new PermissionRequest(resource.getName()));
        Assertions.assertNotNull(response.getTicket());
        Assertions.assertTrue(getAuthzClient().protection().permission().findByResource(resource.getId()).isEmpty());
    }

    @Test
    public void testTicketNotCreatedWhenResourceOwner() throws Exception {
        ResourceRepresentation resource = addResource("Resource A", "marta", true);
        AuthzClient authzClient = getAuthzClient();
        PermissionResponse response = authzClient.protection("marta", "password").permission().create(new PermissionRequest(resource.getId()));
        Assertions.assertNotNull(response.getTicket());
        final AuthorizationRequest request = new AuthorizationRequest();
        request.setTicket(response.getTicket());
        request.setClaimToken(authzClient.obtainAccessToken("marta", "password").getToken());

        AuthorizationDeniedException ex = Assertions.assertThrows(AuthorizationDeniedException.class,
                () -> authzClient.authorization().authorize(request));
        MatcherAssert.assertThat(ex.getMessage(), Matchers.containsString("Unexpected response from server: 403"));

        List permissions = authzClient.protection().permission().findByResource(resource.getId());
        Assertions.assertTrue(permissions.isEmpty());

        response = authzClient.protection("kolo", "password").permission().create(new PermissionRequest(resource.getId()));
        Assertions.assertNotNull(response.getTicket());
        final AuthorizationRequest request2 = new AuthorizationRequest();
        request2.setTicket(response.getTicket());
        request2.setClaimToken(authzClient.obtainAccessToken("kolo", "password").getToken());

        ex = Assertions.assertThrows(AuthorizationDeniedException.class,
                () -> authzClient.authorization().authorize(request2));
        MatcherAssert.assertThat(ex.getMessage(), Matchers.containsString("Unexpected response from server: 403"));
        permissions = authzClient.protection().permission().findByResource(resource.getId());
        Assertions.assertFalse(permissions.isEmpty());
        Assertions.assertEquals(1, permissions.size());
    }

    @Test
    public void testPermissionForTypedScope() throws Exception {
        ResourceRepresentation typedResource = addResource("Typed Resource", "ScopeC");

        typedResource.setType("typed-resource");

        getClient(getRealm()).authorization().resources().resource(typedResource.getId()).update(typedResource);

        ResourceRepresentation resourceA = addResource("Resource A", "marta", true, "ScopeA", "ScopeB");

        resourceA.setType(typedResource.getType());

        getClient(getRealm()).authorization().resources().resource(resourceA.getId()).update(resourceA);

        PermissionRequest permissionRequest = new PermissionRequest(resourceA.getId());

        permissionRequest.setScopes(new HashSet<>(Arrays.asList("ScopeA", "ScopeC")));

        AuthzClient authzClient = getAuthzClient();
        PermissionResponse response = authzClient.protection("kolo", "password").permission().create(permissionRequest);

        AuthorizationRequest request = new AuthorizationRequest();
        request.setTicket(response.getTicket());
        request.setClaimToken(authzClient.obtainAccessToken("kolo", "password").getToken());

        AuthorizationDeniedException ex = Assertions.assertThrows(AuthorizationDeniedException.class,
                () -> authzClient.authorization().authorize(request));
        MatcherAssert.assertThat(ex.getMessage(), Matchers.containsString("Unexpected response from server: 403"));

        assertPersistence(response, resourceA, "ScopeA", "ScopeC");
    }

    @Test
    public void testSameTicketForSamePermissionRequest() throws Exception {
        ResourceRepresentation resource = addResource("Resource A", true);
        PermissionResponse response = getAuthzClient().protection("marta", "password").permission().create(new PermissionRequest(resource.getName()));
        Assertions.assertNotNull(response.getTicket());
    }

    private void assertPersistence(PermissionResponse response, ResourceRepresentation resource, String... scopeNames) throws Exception {
        String ticket = response.getTicket();
        Assertions.assertNotNull(ticket);

        int expectedPermissions = scopeNames.length > 0 ? scopeNames.length : 1;
        List<PermissionTicketRepresentation> tickets = getAuthzClient().protection().permission().findByResource(resource.getId());
        Assertions.assertEquals(expectedPermissions, tickets.size());

        PermissionTicketToken token = new JWSInput(ticket).readJsonContent(PermissionTicketToken.class);

        List<Permission> tokenPermissions = token.getPermissions();
        Assertions.assertNotNull(tokenPermissions);
        Assertions.assertEquals(expectedPermissions, scopeNames.length > 0 ? scopeNames.length : tokenPermissions.size());

        Iterator<Permission> permissionIterator = tokenPermissions.iterator();

        while (permissionIterator.hasNext()) {
            Permission resourcePermission = permissionIterator.next();
            long count = tickets.stream().filter(representation -> representation.getResource().equals(resourcePermission.getResourceId())).count();
            if (count == (scopeNames.length > 0 ? scopeNames.length : 1)) {
                permissionIterator.remove();
            }
        }

        Assertions.assertTrue(tokenPermissions.isEmpty());

        ArrayList<PermissionTicketRepresentation> expectedTickets = new ArrayList<>(tickets);
        Iterator<PermissionTicketRepresentation> ticketIterator = expectedTickets.iterator();

        while (ticketIterator.hasNext()) {
            PermissionTicketRepresentation ticketRep = ticketIterator.next();

            Assertions.assertFalse(ticketRep.isGranted());

            if (ticketRep.getScope() != null) {
                ScopeRepresentation scope = getClient(getRealm()).authorization().scopes().scope(ticketRep.getScope()).toRepresentation();

                if (Arrays.asList(scopeNames).contains(scope.getName())) {
                    ticketIterator.remove();
                }
            } else if (ticketRep.getResource().equals(resource.getId())) {
                ticketIterator.remove();
            }
        }

        Assertions.assertTrue(expectedTickets.isEmpty());
    }

    @Test
    public void failInvalidResource() {
        RuntimeException ex = Assertions.assertThrows(RuntimeException.class,
                () -> getAuthzClient().protection().permission().create(new PermissionRequest("Invalid Resource")));
        MatcherAssert.assertThat(ex.getCause(), Matchers.instanceOf(HttpResponseException.class));
        HttpResponseException cause = (HttpResponseException) ex.getCause();
        Assertions.assertEquals(400, cause.getStatusCode());
        MatcherAssert.assertThat(cause.toString(), Matchers.containsString("invalid_resource_id"));

        ex = Assertions.assertThrows(RuntimeException.class,
                () -> getAuthzClient().protection().permission().create(new PermissionRequest()));
        MatcherAssert.assertThat(ex.getCause(), Matchers.instanceOf(HttpResponseException.class));
        cause = (HttpResponseException) ex.getCause();
        Assertions.assertEquals(400, cause.getStatusCode());
        MatcherAssert.assertThat(cause.toString(), Matchers.containsString("invalid_resource_id"));
    }

    @Test
    public void failInvalidScope() throws Exception {
        addResource("Resource A", "ScopeA", "ScopeB");
        PermissionRequest permissionRequest = new PermissionRequest("Resource A");
        permissionRequest.setScopes(new HashSet<>(Arrays.asList("ScopeA", "ScopeC")));

        RuntimeException ex = Assertions.assertThrows(RuntimeException.class,
                () -> getAuthzClient().protection().permission().create(permissionRequest));
        MatcherAssert.assertThat(ex.getCause(), Matchers.instanceOf(HttpResponseException.class));
        HttpResponseException cause = (HttpResponseException) ex.getCause();
        Assertions.assertEquals(400, cause.getStatusCode());
        MatcherAssert.assertThat(cause.toString(), Matchers.containsString("invalid_scope"));
    }

    @Test
    public void testGetPermissionTicketWithPagination() throws Exception {
      String[] scopes = {"ScopeA", "ScopeB", "ScopeC", "ScopeD"};
      ResourceRepresentation resource = addResource("Resource A", "kolo", true, scopes);
      AuthzClient authzClient = getAuthzClient();
      PermissionResponse response = authzClient.protection("marta", "password").permission().create(new PermissionRequest(resource.getId(), scopes));
      AuthorizationRequest request = new AuthorizationRequest();
      request.setTicket(response.getTicket());
      request.setClaimToken(authzClient.obtainAccessToken("marta", "password").getToken());

      AuthorizationDeniedException ex = Assertions.assertThrows(AuthorizationDeniedException.class,
                () -> authzClient.authorization().authorize(request));
      MatcherAssert.assertThat(ex.getMessage(), Matchers.containsString("Unexpected response from server: 403"));

      // start with fetching the second half of all permission tickets
      Collection<String> expectedScopes = new ArrayList<>(Arrays.asList(scopes));
      List<PermissionTicketRepresentation> tickets = getAuthzClient().protection().permission().find(resource.getId(), null, null, null, null, true, 2, 2);
      Assertions.assertEquals(2, tickets.size(), "Returned number of permissions tickets must match the specified page size (i.e., 'maxResult').");
      boolean foundScope = expectedScopes.remove(tickets.get(0).getScopeName());
      Assertions.assertTrue(foundScope, "Returned set of permission tickets must be only a sub-set as per pagination offset and specified page size.");
      foundScope = expectedScopes.remove(tickets.get(1).getScopeName());
      Assertions.assertTrue(foundScope, "Returned set of permission tickets must be only a sub-set as per pagination offset and specified page size.");

      // fetch the first half of all permission tickets
      tickets = getAuthzClient().protection().permission().find(resource.getId(), null, null, null, null, true, 0, 2);
      Assertions.assertEquals(2, tickets.size(), "Returned number of permissions tickets must match the specified page size (i.e., 'maxResult').");
      foundScope = expectedScopes.remove(tickets.get(0).getScopeName());
      Assertions.assertTrue(foundScope, "Returned set of permission tickets must be only a sub-set as per pagination offset and specified page size.");
      foundScope = expectedScopes.remove(tickets.get(1).getScopeName());
      Assertions.assertTrue(foundScope, "Returned set of permission tickets must be only a sub-set as per pagination offset and specified page size.");
    }

    @Test
    public void testPermissionCount() throws Exception {
        String[] scopes = {"ScopeA", "ScopeB", "ScopeC", "ScopeD"};
        ResourceRepresentation resource = addResource("Resource A", "kolo", true, scopes);
        AuthzClient authzClient = getAuthzClient();
        PermissionResponse response = authzClient.protection("marta", "password").permission().create(new PermissionRequest(resource.getId(), scopes));
        AuthorizationRequest request = new AuthorizationRequest();
        request.setTicket(response.getTicket());
        request.setClaimToken(authzClient.obtainAccessToken("marta", "password").getToken());

        AuthorizationDeniedException ex = Assertions.assertThrows(AuthorizationDeniedException.class,
                () -> authzClient.authorization().authorize(request));
        MatcherAssert.assertThat(ex.getMessage(), Matchers.containsString("Unexpected response from server: 403"));

        Long ticketCount = getAuthzClient().protection().permission().count(resource.getId(), null, null, null, null, true);
        Assertions.assertEquals(Long.valueOf(4), ticketCount, "Returned number of permissions tickets must match the amount of permission tickets.");
    }
}