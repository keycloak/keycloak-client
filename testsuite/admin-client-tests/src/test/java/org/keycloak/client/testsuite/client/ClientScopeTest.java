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

package org.keycloak.client.testsuite.client;

import jakarta.ws.rs.ClientErrorException;
import jakarta.ws.rs.NotFoundException;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.Response.Status;

import org.junit.jupiter.api.Test;
import org.keycloak.admin.client.resource.ClientResource;
import org.keycloak.admin.client.resource.ClientScopesResource;
import org.keycloak.admin.client.resource.ProtocolMappersResource;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.admin.client.resource.RoleMappingResource;
import org.keycloak.client.testsuite.models.AccountRoles;
import org.keycloak.client.testsuite.models.Constants;
import org.keycloak.common.Profile;
import org.keycloak.common.util.ObjectUtil;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.representations.idm.ClientScopeRepresentation;
import org.keycloak.representations.idm.ErrorRepresentation;
import org.keycloak.representations.idm.MappingsRepresentation;
import org.keycloak.representations.idm.ProtocolMapperRepresentation;
import org.keycloak.representations.idm.RoleRepresentation;
import org.keycloak.testsuite.util.ApiUtil;
import org.keycloak.testsuite.util.ClientBuilder;
import org.keycloak.testsuite.util.RoleBuilder;
import org.keycloak.util.JsonSerialization;

import java.io.IOException;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.fail;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.keycloak.client.testsuite.Assert.assertNames;



/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class ClientScopeTest extends AbstractClientTest {

    @Test
    public void testAddFailureWithInvalidScopeName() {
        ClientScopeRepresentation scopeRep = new ClientScopeRepresentation();
        scopeRep.setName("マルチバイト");

        ErrorRepresentation error;
        try (Response response = clientScopes().create(scopeRep)) {
            assertEquals(400, response.getStatus());
            error = response.readEntity(ErrorRepresentation.class);
        }

        assertEquals("Unexpected name \"マルチバイト\" for ClientScope", error.getErrorMessage());
    }

    @Test
    public void testUpdateFailureWithInvalidScopeName() {
        // Creating first
        ClientScopeRepresentation scopeRep = new ClientScopeRepresentation();
        scopeRep.setName("scope1");
        scopeRep.setProtocol("openid-connect");
        String scope1Id = createClientScope(scopeRep);
        // Assert created
        scopeRep = clientScopes().get(scope1Id).toRepresentation();
        assertEquals("scope1", scopeRep.getName());

        // Test updating
        scopeRep.setName("マルチバイト");
        try {
            clientScopes().get(scope1Id).update(scopeRep);
        } catch (ClientErrorException e) {
            ErrorRepresentation error;
            try (Response response = e.getResponse()) {
                assertEquals(400, response.getStatus());
                error = response.readEntity(ErrorRepresentation.class);
            }
            assertEquals("Unexpected name \"マルチバイト\" for ClientScope", error.getErrorMessage());
        }

        removeClientScope(scope1Id);
    }

    @Test
    public void testAddDuplicatedClientScope() {
        ClientScopeRepresentation scopeRep = new ClientScopeRepresentation();
        scopeRep.setName("scope1");
        scopeRep.setProtocol("openid-connect");
        String scopeId = createClientScope(scopeRep);

        scopeRep = new ClientScopeRepresentation();
        scopeRep.setName("scope1");
        scopeRep.setProtocol("openid-connect");
        Response response = clientScopes().create(scopeRep);
        assertEquals(409, response.getStatus());

        ErrorRepresentation error = response.readEntity(ErrorRepresentation.class);
        assertEquals("Client Scope scope1 already exists", error.getErrorMessage());

        // Cleanup
        removeClientScope(scopeId);
    }

    @Test
    public void testGetUnknownScope() {
        try {
            String unknownId = UUID.randomUUID().toString();
            clientScopes().get(unknownId).toRepresentation();
            fail();
        }
        catch (NotFoundException e) {

        }
    }

    private List<String> getClientScopeNames(List<ClientScopeRepresentation> scopes) {
        return scopes.stream().map((ClientScopeRepresentation clientScope) -> {

            return clientScope.getName();

        }).collect(Collectors.toList());
    }

    @Test
    public void testRemoveClientScope() {
        // Create scope1
        ClientScopeRepresentation scopeRep = new ClientScopeRepresentation();
        scopeRep.setName("scope1");
        scopeRep.setProtocol("openid-connect");

        String scope1Id = createClientScope(scopeRep);

        List<ClientScopeRepresentation> clientScopes = clientScopes().findAll();
        assertTrue(getClientScopeNames(clientScopes).contains("scope1"));

        // Create scope2
        scopeRep = new ClientScopeRepresentation();
        scopeRep.setName("scope2");
        scopeRep.setProtocol("openid-connect");

        String scope2Id = createClientScope(scopeRep);

        clientScopes = clientScopes().findAll();
        assertTrue(getClientScopeNames(clientScopes).contains("scope2"));

        // Remove scope1
        removeClientScope(scope1Id);

        clientScopes = clientScopes().findAll();
        assertFalse(getClientScopeNames(clientScopes).contains("scope1"));
        assertTrue(getClientScopeNames(clientScopes).contains("scope2"));


        // Remove scope2
        removeClientScope(scope2Id);

        clientScopes = clientScopes().findAll();
        assertFalse(getClientScopeNames(clientScopes).contains("scope1"));
        assertFalse(getClientScopeNames(clientScopes).contains("scope2"));
    }


    @Test
    public void testUpdateScopeScope() {
        // Test creating
        ClientScopeRepresentation scopeRep = new ClientScopeRepresentation();
        scopeRep.setName("scope1");
        scopeRep.setDescription("scope1-desc");
        scopeRep.setProtocol("openid-connect");

        Map<String, String> attrs = new HashMap<>();
        attrs.put("someAttr", "someAttrValue");
        attrs.put("emptyAttr", "");
        scopeRep.setAttributes(attrs);
        String scope1Id = createClientScope(scopeRep);

        // Assert created attributes
        scopeRep = clientScopes().get(scope1Id).toRepresentation();
        assertEquals("scope1", scopeRep.getName());
        assertEquals("scope1-desc", scopeRep.getDescription());
        assertEquals("someAttrValue", scopeRep.getAttributes().get("someAttr"));
        assertTrue(ObjectUtil.isBlank(scopeRep.getAttributes().get("emptyAttr")));
        assertEquals("openid-connect", scopeRep.getProtocol());


        // Test updating
        scopeRep.setName("scope1-updated");
        scopeRep.setDescription("scope1-desc-updated");
        scopeRep.setProtocol("saml");

        // Test update attribute to some non-blank value
        scopeRep.getAttributes().put("emptyAttr", "someValue");

        clientScopes().get(scope1Id).update(scopeRep);

        // Assert updated attributes
        scopeRep = clientScopes().get(scope1Id).toRepresentation();
        assertEquals("scope1-updated", scopeRep.getName());
        assertEquals("scope1-desc-updated", scopeRep.getDescription());
        assertEquals("saml", scopeRep.getProtocol());
        assertEquals("someAttrValue", scopeRep.getAttributes().get("someAttr"));
        assertEquals("someValue", scopeRep.getAttributes().get("emptyAttr"));

        // Remove scope1
        clientScopes().get(scope1Id).remove();
    }
    
    @Test
    public void testRenameScope() {
        // Create two scopes
        ClientScopeRepresentation scope1Rep = new ClientScopeRepresentation();
        scope1Rep.setName("scope1");
        scope1Rep.setDescription("scope1-desc");
        scope1Rep.setProtocol("openid-connect");
        createClientScope(scope1Rep);

        ClientScopeRepresentation scope2Rep = new ClientScopeRepresentation();
        scope2Rep.setName("scope2");
        scope2Rep.setDescription("scope2-desc");
        scope2Rep.setProtocol("openid-connect");
        String scope2Id = createClientScope(scope2Rep);

        // Test updating
        scope2Rep.setName("scope1");

        try {
            clientScopes().get(scope2Id).update(scope2Rep);
        } catch (ClientErrorException ex) {
            assertTrue(ex.getResponse().getStatus() == Status.CONFLICT.getStatusCode());
        }
    }


    @Test
    public void testScopes() {
        RoleRepresentation realmCompositeRole = createRealmRole("realm-composite");
        RoleRepresentation realmChildRole = createRealmRole("realm-child");
        testRealmResource().roles().get("realm-composite").addComposites(Collections.singletonList(realmChildRole));

        // create client scope
        ClientScopeRepresentation scopeRep = new ClientScopeRepresentation();
        scopeRep.setName("bar-scope");
        scopeRep.setProtocol("openid-connect");
        String scopeId = createClientScope(scopeRep);

        // update with some scopes
        String accountMgmtId =
                testRealmResource().clients().findByClientId(Constants.ACCOUNT_MANAGEMENT_CLIENT_ID).get(0).getId();
        RoleRepresentation viewAccountRoleRep = testRealmResource().clients().get(accountMgmtId).roles()
                .get(AccountRoles.VIEW_PROFILE).toRepresentation();
        RoleMappingResource scopesResource = clientScopes().get(scopeId).getScopeMappings();

        scopesResource.realmLevel().add(Collections.singletonList(realmCompositeRole));

        scopesResource.clientLevel(accountMgmtId).add(Collections.singletonList(viewAccountRoleRep));

        // test that scopes are available (also through composite role)
        List<RoleRepresentation> allRealm = scopesResource.realmLevel().listAll();
        List<RoleRepresentation> availableRealm = scopesResource.realmLevel().listAvailable();
        List<RoleRepresentation> effectiveRealm = scopesResource.realmLevel().listEffective();
        List<RoleRepresentation> accountRoles = scopesResource.clientLevel(accountMgmtId).listAll();

        assertNames(allRealm, "realm-composite");
        assertNames(availableRealm, "attribute-role", "admin", "customer-user-premium", "realm-composite-role", "sample-realm-role", "user", "realm-child", "offline_access",
                Constants.AUTHZ_UMA_AUTHORIZATION, Constants.DEFAULT_ROLES_ROLE_PREFIX + "-test");
        assertNames(effectiveRealm, "realm-composite", "realm-child");
        assertNames(accountRoles, AccountRoles.VIEW_PROFILE);
        MappingsRepresentation mappingsRep = clientScopes().get(scopeId).getScopeMappings().getAll();
        assertNames(mappingsRep.getRealmMappings(), "realm-composite");
        assertNames(mappingsRep.getClientMappings().get(Constants.ACCOUNT_MANAGEMENT_CLIENT_ID).getMappings(),
                AccountRoles.VIEW_PROFILE);


        // remove scopes
        scopesResource.realmLevel().remove(Collections.singletonList(realmCompositeRole));

        scopesResource.clientLevel(accountMgmtId).remove(Collections.singletonList(viewAccountRoleRep));

        // assert scopes are removed
        allRealm = scopesResource.realmLevel().listAll();
        availableRealm = scopesResource.realmLevel().listAvailable();
        effectiveRealm = scopesResource.realmLevel().listEffective();
        accountRoles = scopesResource.clientLevel(accountMgmtId).listAll();
        assertNames(allRealm);
        assertNames(availableRealm, "attribute-role", "admin", "customer-user-premium", "realm-composite", "realm-composite-role", "sample-realm-role", "user", "realm-child", "offline_access",
                Constants.AUTHZ_UMA_AUTHORIZATION, Constants.DEFAULT_ROLES_ROLE_PREFIX + "-test");
        assertNames(effectiveRealm);
        assertNames(accountRoles);

        // remove scope
        removeClientScope(scopeId);
    }

    /**
     * Test for KEYCLOAK-10603.
     */
    @Test
    public void rolesCanBeAddedToScopeEvenWhenTheyAreAlreadyIndirectlyAssigned() {
        RealmResource realm = testRealmResource();
        ClientScopeRepresentation clientScopeRep = new ClientScopeRepresentation();
        clientScopeRep.setName("my-scope");
        clientScopeRep.setProtocol("openid-connect");

        String clientScopeId = createClientScope(clientScopeRep);

        createRealmRole("realm-composite");
        createRealmRole("realm-child");
        realm.roles().get("realm-composite")
                .addComposites(Collections.singletonList(realm.roles().get("realm-child").toRepresentation()));

        Response response = realm.clients().create(ClientBuilder.create().clientId("role-container-client").build());
        String roleContainerClientUuid = ApiUtil.getCreatedId(response);
        getCleanup("test").addClientUuid(roleContainerClientUuid);
        response.close();

        RoleRepresentation clientCompositeRole = RoleBuilder.create().name("client-composite").build();
        realm.clients().get(roleContainerClientUuid).roles().create(clientCompositeRole);
        realm.clients().get(roleContainerClientUuid).roles().create(RoleBuilder.create().name("client-child").build());
        realm.clients().get(roleContainerClientUuid).roles().get("client-composite").addComposites(Collections
                .singletonList(
                        realm.clients().get(roleContainerClientUuid).roles().get("client-child").toRepresentation()));

        // Make indirect assignments: assign composite roles
        RoleMappingResource scopesResource = realm.clientScopes().get(clientScopeId).getScopeMappings();
        scopesResource.realmLevel()
                .add(Collections.singletonList(realm.roles().get("realm-composite").toRepresentation()));
        scopesResource.clientLevel(roleContainerClientUuid).add(Collections
                .singletonList(realm.clients().get(roleContainerClientUuid).roles().get("client-composite")
                        .toRepresentation()));

        // check state before making the direct assignments
        assertNames(scopesResource.realmLevel().listAll(), "realm-composite");
        assertNames(scopesResource.realmLevel().listAvailable(), "attribute-role", "admin", "customer-user-premium", "realm-composite-role", "sample-realm-role", "user", "realm-child", "offline_access",
                Constants.AUTHZ_UMA_AUTHORIZATION, Constants.DEFAULT_ROLES_ROLE_PREFIX + "-test");
        assertNames(scopesResource.realmLevel().listEffective(), "realm-composite", "realm-child");

        assertNames(scopesResource.clientLevel(roleContainerClientUuid).listAll(), "client-composite");
        assertNames(scopesResource.clientLevel(roleContainerClientUuid).listAvailable(), "client-child");
        assertNames(scopesResource.clientLevel(roleContainerClientUuid).listEffective(), "client-composite",
                "client-child");

        // Make direct assignments for roles which are already indirectly assigned
        scopesResource.realmLevel().add(Collections.singletonList(realm.roles().get("realm-child").toRepresentation()));
        scopesResource.clientLevel(roleContainerClientUuid).add(Collections
                .singletonList(
                        realm.clients().get(roleContainerClientUuid).roles().get("client-child").toRepresentation()));

        // List realm roles
        assertNames(scopesResource.realmLevel().listAll(), "realm-composite", "realm-child");
        assertNames(scopesResource.realmLevel().listAvailable(), "attribute-role", "admin", "customer-user-premium", "realm-composite-role", "sample-realm-role", "user", "offline_access",
                Constants.AUTHZ_UMA_AUTHORIZATION, Constants.DEFAULT_ROLES_ROLE_PREFIX + "-test");
        assertNames(scopesResource.realmLevel().listEffective(), "realm-composite", "realm-child");

        // List client roles
        assertNames(scopesResource.clientLevel(roleContainerClientUuid).listAll(), "client-composite",
                "client-child");
        assertNames(scopesResource.clientLevel(roleContainerClientUuid).listAvailable());
        assertNames(scopesResource.clientLevel(roleContainerClientUuid).listEffective(), "client-composite",
                "client-child");
    }

    // KEYCLOAK-2809
    @Test
    public void testRemoveScopedRole() {
        // Add realm role
        RoleRepresentation roleRep = createRealmRole("foo-role");

        // Add client scope
        ClientScopeRepresentation scopeRep = new ClientScopeRepresentation();
        scopeRep.setName("bar-scope");
        scopeRep.setProtocol("openid-connect");

        String scopeId = createClientScope(scopeRep);

        // Add realm role to scopes of clientScope
        clientScopes().get(scopeId).getScopeMappings().realmLevel().add(Collections.singletonList(roleRep));

        List<RoleRepresentation> roleReps = clientScopes().get(scopeId).getScopeMappings().realmLevel().listAll();
        assertEquals(1, roleReps.size());
        assertEquals("foo-role", roleReps.get(0).getName());

        // Remove realm role
        testRealmResource().roles().deleteRole("foo-role");

        // Get scope mappings
        roleReps = clientScopes().get(scopeId).getScopeMappings().realmLevel().listAll();
        assertEquals(0, roleReps.size());

        // Cleanup
        removeClientScope(scopeId);
    }

    private RoleRepresentation createRealmRole(String roleName) {
        RoleRepresentation roleRep = new RoleRepresentation();
        roleRep.setName(roleName);
        testRealmResource().roles().create(roleRep);

        RoleRepresentation createdRole = testRealmResource().roles().get(roleName).toRepresentation();

        getCleanup("test").addRoleId(createdRole.getId());

        return createdRole;
    }

    @Test
    public void testRemoveClientScopeInUse() {
        // Add client scope
        ClientScopeRepresentation scopeRep = new ClientScopeRepresentation();
        scopeRep.setName("foo-scope");
        scopeRep.setProtocol("openid-connect");
        String scopeId = createClientScope(scopeRep);

        // Add client with the clientScope
        ClientRepresentation clientRep = new ClientRepresentation();
        clientRep.setClientId("bar-client");
        clientRep.setName("bar-client");
        clientRep.setProtocol("openid-connect");
        clientRep.setDefaultClientScopes(Collections.singletonList("foo-scope"));
        String clientDbId = createClient(clientRep);
        removeClientScope(scopeId);
        removeClient(clientDbId);
    }


    @Test
    public void testRealmDefaultClientScopes() {
        // Create 2 client scopes
        ClientScopeRepresentation scopeRep = new ClientScopeRepresentation();
        scopeRep.setName("scope-def");
        scopeRep.setProtocol("openid-connect");
        String scopeDefId = createClientScope(scopeRep);
        getCleanup("test").addClientScopeId(scopeDefId);

        scopeRep = new ClientScopeRepresentation();
        scopeRep.setName("scope-opt");
        scopeRep.setProtocol("openid-connect");
        String scopeOptId = createClientScope(scopeRep);
        getCleanup("test").addClientScopeId(scopeOptId);

        // Add scope-def as default and scope-opt as optional client scope
        testRealmResource().addDefaultDefaultClientScope(scopeDefId);
        testRealmResource().addDefaultOptionalClientScope(scopeOptId);

        // Ensure defaults and optional scopes are here
        List<String> realmDefaultScopes = getClientScopeNames(testRealmResource().getDefaultDefaultClientScopes());
        List<String> realmOptionalScopes = getClientScopeNames(testRealmResource().getDefaultOptionalClientScopes());
        assertTrue(realmDefaultScopes.contains("scope-def"));
        assertFalse(realmOptionalScopes .contains("scope-def"));
        assertFalse(realmDefaultScopes.contains("scope-opt"));
        assertTrue(realmOptionalScopes .contains("scope-opt"));

        // create client. Ensure that it has scope-def and scope-opt scopes assigned
        ClientRepresentation clientRep = new ClientRepresentation();
        clientRep.setClientId("bar-client");
        clientRep.setProtocol("openid-connect");
        String clientUuid = createClient(clientRep);
        getCleanup("test").addClientUuid(clientUuid);

        List<String> clientDefaultScopes = getClientScopeNames(testRealmResource().clients().get(clientUuid).getDefaultClientScopes());
        List<String> clientOptionalScopes = getClientScopeNames(testRealmResource().clients().get(clientUuid).getOptionalClientScopes());
        assertTrue(clientDefaultScopes.contains("scope-def"));
        assertFalse(clientOptionalScopes .contains("scope-def"));
        assertFalse(clientDefaultScopes.contains("scope-opt"));
        assertTrue(clientOptionalScopes .contains("scope-opt"));

        // Unassign scope-def and scope-opt from realm
        testRealmResource().removeDefaultDefaultClientScope(scopeDefId);
        testRealmResource().removeDefaultOptionalClientScope(scopeOptId);

        realmDefaultScopes = getClientScopeNames(testRealmResource().getDefaultDefaultClientScopes());
        realmOptionalScopes = getClientScopeNames(testRealmResource().getDefaultOptionalClientScopes());
        assertFalse(realmDefaultScopes.contains("scope-def"));
        assertFalse(realmOptionalScopes .contains("scope-def"));
        assertFalse(realmDefaultScopes.contains("scope-opt"));
        assertFalse(realmOptionalScopes .contains("scope-opt"));

        // Create another client. Check it doesn't have scope-def and scope-opt scopes assigned
        clientRep = new ClientRepresentation();
        clientRep.setClientId("bar-client-2");
        clientRep.setProtocol("openid-connect");
        clientUuid = createClient(clientRep);
        getCleanup("test").addClientUuid(clientUuid);

        clientDefaultScopes = getClientScopeNames(testRealmResource().clients().get(clientUuid).getDefaultClientScopes());
        clientOptionalScopes = getClientScopeNames(testRealmResource().clients().get(clientUuid).getOptionalClientScopes());
        assertFalse(clientDefaultScopes.contains("scope-def"));
        assertFalse(clientOptionalScopes .contains("scope-def"));
        assertFalse(clientDefaultScopes.contains("scope-opt"));
        assertFalse(clientOptionalScopes .contains("scope-opt"));
    }

    // KEYCLOAK-9999
    @Test
    public void defaultOptionalClientScopeCanBeAssignedToClientAsDefaultScope() {

        // Create optional client scope
        ClientScopeRepresentation optionalClientScope = new ClientScopeRepresentation();
        optionalClientScope.setName("optional-client-scope");
        optionalClientScope.setProtocol("openid-connect");
        String optionalClientScopeId = createClientScope(optionalClientScope);
        getCleanup("test").addClientScopeId(optionalClientScopeId);

        testRealmResource().addDefaultOptionalClientScope(optionalClientScopeId);

        // Ensure that scope is optional
        List<String> realmOptionalScopes = getClientScopeNames(testRealmResource().getDefaultOptionalClientScopes());
        assertTrue(realmOptionalScopes.contains("optional-client-scope"));

        // Create client
        ClientRepresentation client = new ClientRepresentation();
        client.setClientId("test-client");
        client.setDefaultClientScopes(Collections.singletonList("optional-client-scope"));
        String clientUuid = createClient(client);
        getCleanup("test").addClientUuid(clientUuid);

        // Ensure that default optional client scope is a default scope of the client
        List<String> clientDefaultScopes = getClientScopeNames(testRealmResource().clients().get(clientUuid).getDefaultClientScopes());
        assertTrue(clientDefaultScopes.contains("optional-client-scope"));

        // Ensure that no optional scopes are assigned to the client, even if there are default optional scopes!
        List<String> clientOptionalScopes = getClientScopeNames(testRealmResource().clients().get(clientUuid).getOptionalClientScopes());
        assertTrue(clientOptionalScopes.isEmpty());

        // Unassign optional client scope from realm for cleanup
        testRealmResource().removeDefaultOptionalClientScope(optionalClientScopeId);
    }

    // KEYCLOAK-18332
    @Test
    public void scopesRemainAfterClientUpdate() {
        // Create a bunch of scopes
        ClientScopeRepresentation scopeRep = new ClientScopeRepresentation();
        scopeRep.setName("scope-def");
        scopeRep.setProtocol("openid-connect");
        String scopeDefId = createClientScope(scopeRep);
        getCleanup("test").addClientScopeId(scopeDefId);

        scopeRep = new ClientScopeRepresentation();
        scopeRep.setName("scope-opt");
        scopeRep.setProtocol("openid-connect");
        String scopeOptId = createClientScope(scopeRep);
        getCleanup("test").addClientScopeId(scopeOptId);

        // Add scope-def as default and scope-opt as optional client scope
        testRealmResource().addDefaultDefaultClientScope(scopeDefId);
        testRealmResource().addDefaultOptionalClientScope(scopeOptId);

        // Create a client
        ClientRepresentation clientRep = new ClientRepresentation();
        clientRep.setClientId("bar-client");
        clientRep.setProtocol("openid-connect");
        String clientUuid = createClient(clientRep);
        ClientResource client = testRealmResource().clients().get(clientUuid);
        getCleanup("test").addClientUuid(clientUuid);
        assertTrue(getClientScopeNames(client.getDefaultClientScopes()).contains("scope-def"));
        assertTrue(getClientScopeNames(client.getOptionalClientScopes()).contains("scope-opt"));

        // Remove the scopes from client
        client.removeDefaultClientScope(scopeDefId);
        client.removeOptionalClientScope(scopeOptId);
        List<String> expectedDefScopes = getClientScopeNames(client.getDefaultClientScopes());
        List<String> expectedOptScopes = getClientScopeNames(client.getOptionalClientScopes());
        assertFalse(expectedDefScopes.contains("scope-def"));
        assertFalse(expectedOptScopes.contains("scope-opt"));

        // Update the client
        clientRep = client.toRepresentation();
        clientRep.setDescription("desc"); // Make a small change
        client.update(clientRep);

        // Assert scopes are intact
        assertEquals(expectedDefScopes, getClientScopeNames(client.getDefaultClientScopes()));
        assertEquals(expectedOptScopes, getClientScopeNames(client.getOptionalClientScopes()));
    }

    // KEYCLOAK-5863
    @Test
    public void testUpdateProtocolMappers() {
        ClientScopeRepresentation scopeRep = new ClientScopeRepresentation();
        scopeRep.setName("testUpdateProtocolMappers");
        scopeRep.setProtocol("openid-connect");


        String scopeId = createClientScope(scopeRep);

        ProtocolMapperRepresentation mapper = new ProtocolMapperRepresentation();
        mapper.setName("test");
        mapper.setProtocol("openid-connect");
        mapper.setProtocolMapper("oidc-usermodel-attribute-mapper");

        Map<String, String> m = new HashMap<>();
        m.put("user.attribute", "test");
        m.put("claim.name", "");
        m.put("jsonType.label", "");

        mapper.setConfig(m);

        ProtocolMappersResource protocolMappers = clientScopes().get(scopeId).getProtocolMappers();

        Response response = protocolMappers.createMapper(mapper);
        String mapperId = ApiUtil.getCreatedId(response);

        mapper = protocolMappers.getMapperById(mapperId);

        mapper.getConfig().put("claim.name", "claim");

        protocolMappers.update(mapperId, mapper);

        List<ProtocolMapperRepresentation> mappers = protocolMappers.getMappers();
        assertEquals(1, mappers.size());
        assertEquals(2, mappers.get(0).getConfig().size());
        assertEquals("test", mappers.get(0).getConfig().get("user.attribute"));
        assertEquals("claim", mappers.get(0).getConfig().get("claim.name"));

        clientScopes().get(scopeId).remove();
    }

    @Test
    public void updateClientWithDefaultScopeAssignedAsOptionalAndOpposite() {
        // create client
        ClientRepresentation clientRep = new ClientRepresentation();
        clientRep.setClientId("bar-client");
        clientRep.setProtocol("openid-connect");
        String clientUuid = createClient(clientRep);
        getCleanup("test").addClientUuid(clientUuid);

        // Create 2 client scopes
        ClientScopeRepresentation scopeRep = new ClientScopeRepresentation();
        scopeRep.setName("scope-def");
        scopeRep.setProtocol("openid-connect");
        String scopeDefId = createClientScope(scopeRep);
        getCleanup("test").addClientScopeId(scopeDefId);

        scopeRep = new ClientScopeRepresentation();
        scopeRep.setName("scope-opt");
        scopeRep.setProtocol("openid-connect");
        String scopeOptId = createClientScope(scopeRep);
        getCleanup("test").addClientScopeId(scopeOptId);

        // assign "scope-def" as optional client scope to client
        testRealmResource().clients().get(clientUuid).addOptionalClientScope(scopeDefId);

        // assign "scope-opt" as default client scope to client
        testRealmResource().clients().get(clientUuid).addDefaultClientScope(scopeOptId);

        // Add scope-def as default and scope-opt as optional client scope within the realm
        testRealmResource().addDefaultDefaultClientScope(scopeDefId);
        testRealmResource().addDefaultOptionalClientScope(scopeOptId);

        //update client - check it passes (it used to throw ModelDuplicateException before)
        clientRep.setDescription("new_description");
        testRealmResource().clients().get(clientUuid).update(clientRep);
    }

    @Test
    public void deleteAllClientScopesMustFail() {
        List<ClientScopeRepresentation> clientScopes = clientScopes().findAll();
        for (int i = 0; i < clientScopes.size(); i++) {
            ClientScopeRepresentation clientScope = clientScopes.get(i);
            if (i != clientScopes.size() - 1) {
                removeClientScope(clientScope.getId());
            } else {
                removeClientScopeMustFail(clientScope.getId());
            }
        }
    }

    private void handleExpectedCreateFailure(ClientScopeRepresentation scopeRep, int expectedErrorCode, String expectedErrorMessage) {
        try(Response resp = clientScopes().create(scopeRep)) {
            assertEquals(expectedErrorCode, resp.getStatus());
            String respBody = resp.readEntity(String.class);
            Map<String, String> responseJson = null;
            try {
                responseJson = JsonSerialization.readValue(respBody, Map.class);
                assertEquals(expectedErrorMessage, responseJson.get("errorMessage"));
            } catch (IOException e) {
                fail("Failed to extract the errorMessage from a CreateScope Response");
            }
        }
    }

    private ClientScopesResource clientScopes() {
        return testRealmResource().clientScopes();
    }

    private String createClientScope(ClientScopeRepresentation clientScopeRep) {
        Response resp = clientScopes().create(clientScopeRep);
        assertEquals(201, resp.getStatus());
        resp.close();
        String clientScopeId = ApiUtil.getCreatedId(resp);
        getCleanup("test").addClientScopeId(clientScopeId);


        return clientScopeId;
    }

    private void removeClientScope(String clientScopeId) {
        clientScopes().get(clientScopeId).remove();
    }

    private void removeClientScopeMustFail(String clientScopeId) {
        try {
            clientScopes().get(clientScopeId).remove();
        } catch (Exception expected) {

        }
    }

}
