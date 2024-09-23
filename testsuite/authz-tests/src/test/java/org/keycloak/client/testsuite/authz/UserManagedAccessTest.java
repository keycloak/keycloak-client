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
import java.util.List;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.admin.client.resource.AuthorizationResource;
import org.keycloak.admin.client.resource.ClientResource;
import org.keycloak.authorization.client.AuthorizationDeniedException;
import org.keycloak.authorization.client.resource.PermissionResource;
import org.keycloak.authorization.client.resource.ProtectionResource;
import org.keycloak.authorization.client.util.HttpResponseException;
import org.keycloak.client.testsuite.events.EventType;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.idm.EventRepresentation;
import org.keycloak.representations.idm.authorization.AuthorizationRequest;
import org.keycloak.representations.idm.authorization.AuthorizationResponse;
import org.keycloak.representations.idm.authorization.JSPolicyRepresentation;
import org.keycloak.representations.idm.authorization.Permission;
import org.keycloak.representations.idm.authorization.PermissionTicketRepresentation;
import org.keycloak.representations.idm.authorization.PolicyEnforcementMode;
import org.keycloak.representations.idm.authorization.ResourcePermissionRepresentation;
import org.keycloak.representations.idm.authorization.ResourceRepresentation;
import org.keycloak.representations.idm.authorization.ResourceServerRepresentation;
import org.keycloak.representations.idm.authorization.ScopePermissionRepresentation;
import org.testcontainers.shaded.org.hamcrest.MatcherAssert;
import org.testcontainers.shaded.org.hamcrest.Matchers;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class UserManagedAccessTest extends AbstractResourceServerTest {

    private ResourceRepresentation resource;

    @BeforeEach
    public void configureAuthorization() throws Exception {
        ClientResource client = getClient(getRealm());
        AuthorizationResource authorization = client.authorization();

        JSPolicyRepresentation policy = new JSPolicyRepresentation();

        policy.setName("Only Owner Policy");
        policy.setType("script-scripts/only-owner-policy.js");

        authorization.policies().js().create(policy).close();
    }

    @Test
    public void testOnlyOwnerCanAccess() throws Exception {
        ResourcePermissionRepresentation permission = new ResourcePermissionRepresentation();
        resource = addResource("Resource A", "marta", true, "ScopeA", "ScopeB");

        permission.setName(resource.getName() + " Permission");
        permission.addResource(resource.getId());
        permission.addPolicy("Only Owner Policy");

        getClient(getRealm()).authorization().permissions().resource().create(permission).close();

        AuthorizationResponse response = authorize("marta", "password", resource.getName(), new String[] {"ScopeA", "ScopeB"});
        String rpt = response.getToken();

        Assertions.assertNotNull(rpt);
        Assertions.assertFalse(response.isUpgraded());

        AccessToken accessToken = toAccessToken(rpt);
        AccessToken.Authorization authorization = accessToken.getAuthorization();

        Assertions.assertNotNull(authorization);

        Collection<Permission> permissions = authorization.getPermissions();

        Assertions.assertNotNull(permissions);
        assertPermissions(permissions, resource.getName(), "ScopeA", "ScopeB");
        Assertions.assertTrue(permissions.isEmpty());

        AuthorizationDeniedException ade = Assertions.assertThrows(AuthorizationDeniedException.class,
                () -> authorize("kolo", "password", resource.getId(), new String[]{"ScopeA", "ScopeB"}));
        MatcherAssert.assertThat(ade.getMessage(), Matchers.containsString("Forbidden"));
    }

    @Test
    public void testOnlyOwnerCanAccessPermissionsToScope() throws Exception {
        resource = addResource("Resource A", "marta", true, "ScopeA", "ScopeB");
        ScopePermissionRepresentation permission = new ScopePermissionRepresentation();

        permission.setName(resource.getName() + " Scope A Permission");
        permission.addScope("ScopeA");
        permission.addPolicy("Only Owner Policy");

        getClient(getRealm()).authorization().permissions().scope().create(permission).close();

        permission = new ScopePermissionRepresentation();

        permission.setName(resource.getName() + " Scope B Permission");
        permission.addScope("ScopeB");
        permission.addPolicy("Only Owner Policy");

        getClient(getRealm()).authorization().permissions().scope().create(permission).close();

        AuthorizationResponse response = authorize("marta", "password", resource.getName(), new String[] {"ScopeA", "ScopeB"});
        String rpt = response.getToken();

        Assertions.assertNotNull(rpt);
        Assertions.assertFalse(response.isUpgraded());

        AccessToken accessToken = toAccessToken(rpt);
        AccessToken.Authorization authorization = accessToken.getAuthorization();

        Assertions.assertNotNull(authorization);

        Collection<Permission> permissions = authorization.getPermissions();

        Assertions.assertNotNull(permissions);
        assertPermissions(permissions, resource.getName(), "ScopeA", "ScopeB");
        Assertions.assertTrue(permissions.isEmpty());

        AuthorizationDeniedException ade = Assertions.assertThrows(AuthorizationDeniedException.class,
                () -> authorize("kolo", "password", resource.getId(), new String[] {"ScopeA", "ScopeB"}));
        MatcherAssert.assertThat(ade.getMessage(), Matchers.containsString("Forbidden"));

        List<PermissionTicketRepresentation> tickets = getAuthzClient().protection().permission().find(resource.getId(), null, null, null, null, null, null, null);

        for (PermissionTicketRepresentation ticket : tickets) {
            ticket.setGranted(true);
            getAuthzClient().protection().permission().update(ticket);
        }

        response = authorize("kolo", "password", resource.getId(), new String[] {"ScopeA", "ScopeB"});

        rpt = response.getToken();
        accessToken = toAccessToken(rpt);
        authorization = accessToken.getAuthorization();
        permissions = authorization.getPermissions();
        assertPermissions(permissions, resource.getName(), "ScopeA", "ScopeB");
        Assertions.assertTrue(permissions.isEmpty());

        response = authorize("marta", "password", resource.getId(), new String[] {"ScopeB"});

        rpt = response.getToken();
        accessToken = toAccessToken(rpt);
        authorization = accessToken.getAuthorization();
        permissions = authorization.getPermissions();
        assertPermissions(permissions, resource.getName(), "ScopeB");
        Assertions.assertTrue(permissions.isEmpty());
    }

    /**
     * Makes sure permissions granted to a typed resource instance does not grant access to resource instances with the same type.
     *
     * @throws Exception
     */
    @Test
    public void testOnlyOwnerCanAccessResourceWithType() throws Exception {
        ResourceRepresentation typedResource = addResource("Typed Resource", getClient(getRealm()).toRepresentation().getId(), false, "ScopeA", "ScopeB");

        typedResource.setType("my:resource");

        getClient(getRealm()).authorization().resources().resource(typedResource.getId()).update(typedResource);

        resource = addResource("Resource A", "marta", true, "ScopeA", "ScopeB");

        resource.setType(typedResource.getType());

        getClient(getRealm()).authorization().resources().resource(resource.getId()).update(resource);

        ResourceRepresentation resourceB = addResource("Resource B", "marta", true, "ScopeA", "ScopeB");

        resourceB.setType(typedResource.getType());

        getClient(getRealm()).authorization().resources().resource(resourceB.getId()).update(resourceB);

        ResourcePermissionRepresentation permission = new ResourcePermissionRepresentation();

        permission.setName(resource.getType() + " Permission");
        permission.setResourceType(resource.getType());
        permission.addPolicy("Only Owner Policy");

        getClient(getRealm()).authorization().permissions().resource().create(permission).close();

        AuthorizationResponse response = authorize("marta", "password", resource.getName(), new String[] {"ScopeA", "ScopeB"});
        String rpt = response.getToken();

        Assertions.assertNotNull(rpt);
        Assertions.assertFalse(response.isUpgraded());

        AccessToken accessToken = toAccessToken(rpt);
        AccessToken.Authorization authorization = accessToken.getAuthorization();

        Assertions.assertNotNull(authorization);

        Collection<Permission> permissions = authorization.getPermissions();

        Assertions.assertNotNull(permissions);
        assertPermissions(permissions, resource.getName(), "ScopeA", "ScopeB");
        Assertions.assertTrue(permissions.isEmpty());

        AuthorizationDeniedException ade = Assertions.assertThrows(AuthorizationDeniedException.class,
                () -> authorize("kolo", "password", resource.getId(), new String[] {"ScopeA", "ScopeB"}));
        MatcherAssert.assertThat(ade.getMessage(), Matchers.containsString("Forbidden"));

        List<PermissionTicketRepresentation> tickets = getAuthzClient().protection().permission().find(resource.getId(), null, null, null, null, null, null, null);

        for (PermissionTicketRepresentation ticket : tickets) {
            ticket.setGranted(true);
            getAuthzClient().protection().permission().update(ticket);
        }

        authorize("kolo", "password", resource.getId(), new String[] {"ScopeA", "ScopeB"});

        permissions = authorization.getPermissions();

        Assertions.assertNotNull(permissions);
        assertPermissions(permissions, resource.getName(), "ScopeA", "ScopeB");
        Assertions.assertTrue(permissions.isEmpty());

        for (PermissionTicketRepresentation ticket : tickets) {
            getAuthzClient().protection().permission().delete(ticket.getId());
        }

        tickets = getAuthzClient().protection().permission().find(resource.getId(), null, null, null, null, null, null, null);

        Assertions.assertEquals(0, tickets.size());
        ade = Assertions.assertThrows(AuthorizationDeniedException.class,
                () -> authorize("kolo", "password", resource.getId(), new String[] {"ScopeA", "ScopeB"}));
        MatcherAssert.assertThat(ade.getMessage(), Matchers.containsString("Forbidden"));
    }

    @Test
    public void testUserGrantsAccessToResource() throws Exception {
        ResourcePermissionRepresentation permission = new ResourcePermissionRepresentation();
        resource = addResource("Resource A", "marta", true, "ScopeA", "ScopeB");

        permission.setName(resource.getName() + " Permission");
        permission.addResource(resource.getId());
        permission.addPolicy("Only Owner Policy");

        ClientResource client = getClient(getRealm());

        client.authorization().permissions().resource().create(permission).close();

        AuthorizationResponse response = authorize("marta", "password", "Resource A", new String[] {"ScopeA", "ScopeB"});

        String rpt = response.getToken();

        Assertions.assertNotNull(rpt);
        Assertions.assertFalse(response.isUpgraded());

        AccessToken accessToken = toAccessToken(rpt);
        AccessToken.Authorization authorization = accessToken.getAuthorization();

        Assertions.assertNotNull(authorization);

        Collection<Permission> permissions = authorization.getPermissions();

        Assertions.assertNotNull(permissions);
        assertPermissions(permissions, "Resource A", "ScopeA", "ScopeB");
        Assertions.assertTrue(permissions.isEmpty());

        getRealm().clearEvents();

        AuthorizationDeniedException ade = Assertions.assertThrows(AuthorizationDeniedException.class,
                () -> authorize("kolo", "password", resource.getId(), new String[] {}));
        MatcherAssert.assertThat(ade.getMessage(), Matchers.containsString("Forbidden"));

        List<EventRepresentation> events = getRealm()
                .getEvents(Arrays.asList(EventType.PERMISSION_TOKEN_ERROR.name()), null, null, null, null, null, null, null);
        Assertions.assertEquals(1, events.size());
        EventRepresentation event = events.iterator().next();
        final String clientId = client.toRepresentation().getClientId();
        final String koloId = getRealm().users().search("kolo", true).get(0).getId();
        Assertions.assertEquals(clientId, event.getClientId());
        Assertions.assertEquals(koloId, event.getUserId());
        Assertions.assertEquals("access_denied", event.getError());
        Assertions.assertEquals("request_submitted", event.getDetails().get("reason"));

        PermissionResource permissionResource = getAuthzClient().protection().permission();
        List<PermissionTicketRepresentation> permissionTickets = permissionResource.findByResource(resource.getId());

        Assertions.assertFalse(permissionTickets.isEmpty());
        Assertions.assertEquals(2, permissionTickets.size());

        for (PermissionTicketRepresentation ticket : permissionTickets) {
            Assertions.assertFalse(ticket.isGranted());

            ticket.setGranted(true);

            permissionResource.update(ticket);
        }

        permissionTickets = permissionResource.findByResource(resource.getId());

        Assertions.assertFalse(permissionTickets.isEmpty());
        Assertions.assertEquals(2, permissionTickets.size());

        for (PermissionTicketRepresentation ticket : permissionTickets) {
            Assertions.assertTrue(ticket.isGranted());
        }

        getRealm().clearEvents();

        response = authorize("kolo", "password", resource.getId(), new String[] {"ScopeA", "ScopeB"});
        rpt = response.getToken();

        Assertions.assertNotNull(rpt);
        Assertions.assertFalse(response.isUpgraded());

        accessToken = toAccessToken(rpt);
        authorization = accessToken.getAuthorization();

        Assertions.assertNotNull(authorization);

        permissions = authorization.getPermissions();

        Assertions.assertNotNull(permissions);
        assertPermissions(permissions, resource.getName(), "ScopeA", "ScopeB");
        Assertions.assertTrue(permissions.isEmpty());

        events = getRealm().getEvents(Arrays.asList(EventType.PERMISSION_TOKEN.name()), null, null, null, null, null, null, null);
        Assertions.assertEquals(1, events.size());
        event = events.iterator().next();
        Assertions.assertEquals(clientId, event.getClientId());
        Assertions.assertEquals(koloId, event.getUserId());
    }

    @Test
    public void testUserGrantedAccessConsideredWhenRequestingAuthorizationByResourceName() throws Exception {
        ResourcePermissionRepresentation permission = new ResourcePermissionRepresentation();
        resource = addResource("Resource A", "marta", true, "ScopeA", "ScopeB");

        permission.setName(resource.getName() + " Permission");
        permission.addResource(resource.getId());
        permission.addPolicy("Only Owner Policy");

        getClient(getRealm()).authorization().permissions().resource().create(permission).close();

        AuthorizationDeniedException ade = Assertions.assertThrows(AuthorizationDeniedException.class,
                () -> authorize("kolo", "password", resource.getId(), new String[] {}));
        MatcherAssert.assertThat(ade.getMessage(), Matchers.containsString("Forbidden"));

        PermissionResource permissionResource = getAuthzClient().protection().permission();
        List<PermissionTicketRepresentation> permissionTickets = permissionResource.findByResource(resource.getId());

        Assertions.assertFalse(permissionTickets.isEmpty());
        Assertions.assertEquals(2, permissionTickets.size());

        for (PermissionTicketRepresentation ticket : permissionTickets) {
            Assertions.assertFalse(ticket.isGranted());

            ticket.setGranted(true);

            permissionResource.update(ticket);
        }

        permissionTickets = permissionResource.findByResource(resource.getId());

        Assertions.assertFalse(permissionTickets.isEmpty());
        Assertions.assertEquals(2, permissionTickets.size());

        for (PermissionTicketRepresentation ticket : permissionTickets) {
            Assertions.assertTrue(ticket.isGranted());
        }

        AuthorizationRequest request1 = new AuthorizationRequest();
        // No resource id used in request, only name
        request1.addPermission("Resource A", "ScopeA", "ScopeB");

        List<Permission> permissions = authorize("kolo", "password", request1);

        Assertions.assertEquals(1, permissions.size());
        Permission koloPermission = permissions.get(0);
        Assertions.assertEquals("Resource A", koloPermission.getResourceName());
        Assertions.assertTrue(koloPermission.getScopes().containsAll(Arrays.asList("ScopeA", "ScopeB")));

        ResourceRepresentation resourceRep = getAuthzClient().protection().resource().findById(resource.getId());

        resourceRep.setName("Resource A Changed");

        getAuthzClient().protection().resource().update(resourceRep);

        AuthorizationRequest request2 = new AuthorizationRequest();
        // Try to use the old name
        request2.addPermission("Resource A", "ScopeA", "ScopeB");

        RuntimeException re = Assertions.assertThrows(RuntimeException.class,
                () -> authorize("kolo", "password", request2));
        Assertions.assertNotNull(re.getCause());
        MatcherAssert.assertThat(re.getCause().toString(), Matchers.containsString("invalid_resource"));

        AuthorizationRequest request3 = new AuthorizationRequest();
        request3.addPermission(resourceRep.getName(), "ScopeA", "ScopeB");

        permissions = authorize("kolo", "password", request3);

        Assertions.assertEquals(1, permissions.size());
        koloPermission = permissions.get(0);
        Assertions.assertEquals(resourceRep.getName(), koloPermission.getResourceName());
        Assertions.assertTrue(koloPermission.getScopes().containsAll(Arrays.asList("ScopeA", "ScopeB")));
    }

    @Test
    public void testUserGrantsAccessToResourceWithoutScopes() throws Exception {
        ResourcePermissionRepresentation permission = new ResourcePermissionRepresentation();
        resource = addResource("Resource A", "marta", true);

        permission.setName(resource.getName() + " Permission");
        permission.addResource(resource.getId());
        permission.addPolicy("Only Owner Policy");

        getClient(getRealm()).authorization().permissions().resource().create(permission).close();

        AuthorizationResponse response = authorize("marta", "password", "Resource A", new String[] {});
        String rpt = response.getToken();

        Assertions.assertNotNull(rpt);
        Assertions.assertFalse(response.isUpgraded());

        AccessToken accessToken = toAccessToken(rpt);
        AccessToken.Authorization authorization = accessToken.getAuthorization();

        Assertions.assertNotNull(authorization);

        Collection<Permission> permissions = authorization.getPermissions();

        Assertions.assertNotNull(permissions);
        assertPermissions(permissions, "Resource A");
        Assertions.assertTrue(permissions.isEmpty());

        AuthorizationDeniedException ade = Assertions.assertThrows(AuthorizationDeniedException.class,
                () -> authorize("kolo", "password", resource.getId(), new String[] {}));
        MatcherAssert.assertThat(ade.getMessage(), Matchers.containsString("Forbidden"));

        PermissionResource permissionResource = getAuthzClient().protection().permission();
        List<PermissionTicketRepresentation> permissionTickets = permissionResource.findByResource(resource.getId());

        Assertions.assertFalse(permissionTickets.isEmpty());
        Assertions.assertEquals(1, permissionTickets.size());

        for (PermissionTicketRepresentation ticket : permissionTickets) {
            Assertions.assertFalse(ticket.isGranted());

            ticket.setGranted(true);

            permissionResource.update(ticket);
        }

        permissionTickets = permissionResource.findByResource(resource.getId());

        Assertions.assertFalse(permissionTickets.isEmpty());
        Assertions.assertEquals(1, permissionTickets.size());

        for (PermissionTicketRepresentation ticket : permissionTickets) {
            Assertions.assertTrue(ticket.isGranted());
        }

        response = authorize("kolo", "password", resource.getId(), new String[] {});
        rpt = response.getToken();

        Assertions.assertNotNull(rpt);
        Assertions.assertFalse(response.isUpgraded());

        accessToken = toAccessToken(rpt);
        authorization = accessToken.getAuthorization();

        Assertions.assertNotNull(authorization);

        permissions = authorization.getPermissions();

        Assertions.assertNotNull(permissions);
        assertPermissions(permissions, resource.getName());
        Assertions.assertTrue(permissions.isEmpty());

        response = authorize("kolo", "password", resource.getId(), new String[] {});
        rpt = response.getToken();

        Assertions.assertNotNull(rpt);
        Assertions.assertFalse(response.isUpgraded());

        accessToken = toAccessToken(rpt);
        authorization = accessToken.getAuthorization();

        Assertions.assertNotNull(authorization);

        permissions = authorization.getPermissions();

        Assertions.assertNotNull(permissions);
        assertPermissions(permissions, resource.getName());
        Assertions.assertTrue(permissions.isEmpty());

        permissionTickets = permissionResource.findByResource(resource.getId());

        Assertions.assertFalse(permissionTickets.isEmpty());
        Assertions.assertEquals(1, permissionTickets.size());

        for (PermissionTicketRepresentation ticket : permissionTickets) {
            Assertions.assertTrue(ticket.isGranted());
        }

        for (PermissionTicketRepresentation ticket : permissionTickets) {
            permissionResource.delete(ticket.getId());
        }

        permissionTickets = permissionResource.findByResource(resource.getId());

        Assertions.assertEquals(0, permissionTickets.size());
    }

    @Test
    public void testScopePermissionsToScopeOnly() throws Exception {
        ResourcePermissionRepresentation permission = new ResourcePermissionRepresentation();
        resource = addResource("Resource A", "marta", true, "ScopeA", "ScopeB");

        permission.setName(resource.getName() + " Permission");
        permission.addResource(resource.getId());
        permission.addPolicy("Only Owner Policy");

        getClient(getRealm()).authorization().permissions().resource().create(permission).close();

        AuthorizationResponse response = authorize("marta", "password", "Resource A", new String[] {"ScopeA", "ScopeB"});
        String rpt = response.getToken();

        Assertions.assertNotNull(rpt);
        Assertions.assertFalse(response.isUpgraded());

        AccessToken accessToken = toAccessToken(rpt);
        AccessToken.Authorization authorization = accessToken.getAuthorization();

        Assertions.assertNotNull(authorization);

        Collection<Permission> permissions = authorization.getPermissions();

        Assertions.assertNotNull(permissions);
        assertPermissions(permissions, "Resource A", "ScopeA", "ScopeB");
        Assertions.assertTrue(permissions.isEmpty());

        AuthorizationDeniedException ade = Assertions.assertThrows(AuthorizationDeniedException.class,
                () -> authorize("kolo", "password", resource.getId(), new String[] {"ScopeA"}));
        MatcherAssert.assertThat(ade.getMessage(), Matchers.containsString("Forbidden"));

        PermissionResource permissionResource = getAuthzClient().protection().permission();
        List<PermissionTicketRepresentation> permissionTickets = permissionResource.findByResource(resource.getId());

        Assertions.assertFalse(permissionTickets.isEmpty());
        Assertions.assertEquals(1, permissionTickets.size());

        PermissionTicketRepresentation ticket = permissionTickets.get(0);
        Assertions.assertFalse(ticket.isGranted());

        ticket.setGranted(true);

        permissionResource.update(ticket);

        response = authorize("kolo", "password", resource.getId(), new String[] {"ScopeA", "ScopeB"});
        rpt = response.getToken();

        Assertions.assertNotNull(rpt);
        Assertions.assertFalse(response.isUpgraded());

        accessToken = toAccessToken(rpt);
        authorization = accessToken.getAuthorization();

        Assertions.assertNotNull(authorization);

        permissions = authorization.getPermissions();

        Assertions.assertNotNull(permissions);
        assertPermissions(permissions, resource.getName(), "ScopeA");
        Assertions.assertTrue(permissions.isEmpty());

        permissionTickets = permissionResource.findByResource(resource.getId());

        Assertions.assertFalse(permissionTickets.isEmpty());
        // must have two permission tickets, one persisted during the first authorize call for ScopeA and another for the second call to authorize for ScopeB
        Assertions.assertEquals(2, permissionTickets.size());

        for (PermissionTicketRepresentation representation : new ArrayList<>(permissionTickets)) {
            if (representation.isGranted()) {
                permissionResource.delete(representation.getId());
            }
        }

        permissionTickets = permissionResource.findByResource(resource.getId());

        Assertions.assertEquals(1, permissionTickets.size());
    }

    @Test
    public void testPermissiveModePermissions() throws Exception {
        resource = addResource("Resource A");

        try {
            authorize("kolo", "password", resource.getId(), null);
            Assertions.fail("Access should be denied, server in enforcing mode");
        } catch (AuthorizationDeniedException ade) {

        }

        AuthorizationResource authorizationResource = getClient(getRealm()).authorization();
        ResourceServerRepresentation settings = authorizationResource.getSettings();

        settings.setPolicyEnforcementMode(PolicyEnforcementMode.PERMISSIVE);

        authorizationResource.update(settings);

        AuthorizationResponse response = authorize("marta", "password", "Resource A", null);
        String rpt = response.getToken();

        Assertions.assertNotNull(rpt);
        Assertions.assertFalse(response.isUpgraded());

        AccessToken accessToken = toAccessToken(rpt);
        AccessToken.Authorization authorization = accessToken.getAuthorization();

        Assertions.assertNotNull(authorization);

        Collection<Permission> permissions = authorization.getPermissions();

        Assertions.assertNotNull(permissions);
        assertPermissions(permissions, "Resource A");
        Assertions.assertTrue(permissions.isEmpty());
    }

    @Test
    public void testResourceIsUserManagedCheck() throws Exception {
        resource = addResource("Resource A", null, false, "ScopeA");

        PermissionTicketRepresentation ticket = new PermissionTicketRepresentation();
        ticket.setResource(resource.getId());
        ticket.setRequesterName("marta");
        ticket.setScopeName("ScopeA");
        ticket.setGranted(true);

        ProtectionResource protection = getAuthzClient().protection();

        RuntimeException re = Assertions.assertThrows(RuntimeException.class,
                () -> protection.permission().create(ticket));
        MatcherAssert.assertThat(re.getCause(), Matchers.instanceOf(HttpResponseException.class));
        Assertions.assertEquals(400, HttpResponseException.class.cast(re.getCause()).getStatusCode());
        HttpResponseException hre = HttpResponseException.class.cast(re.getCause());
        MatcherAssert.assertThat(hre.toString(), Matchers.containsString("invalid_permission"));
        MatcherAssert.assertThat(hre.toString(), Matchers.containsString("permission can only be created for resources with user-managed access enabled"));
    }

    private List<Permission> authorize(String userName, String password, AuthorizationRequest request) {
        AuthorizationResponse response = getAuthzClient().authorization(userName, password).authorize(request);
        AccessToken token = toAccessToken(response.getToken());
        AccessToken.Authorization authorization = token.getAuthorization();
        return new ArrayList<>(authorization.getPermissions());
    }
}