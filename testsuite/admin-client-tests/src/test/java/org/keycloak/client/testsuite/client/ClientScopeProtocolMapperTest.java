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

import jakarta.ws.rs.NotFoundException;
import jakarta.ws.rs.core.Response;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.admin.client.resource.ClientScopeResource;
import org.keycloak.admin.client.resource.ClientScopesResource;
import org.keycloak.admin.client.resource.ProtocolMappersResource;

import org.keycloak.representations.idm.ClientScopeRepresentation;
import org.keycloak.representations.idm.ProtocolMapperRepresentation;

import org.keycloak.testsuite.util.ApiUtil;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class ClientScopeProtocolMapperTest extends AbstractProtocolMapperTest {

    private String oidcClientScopeId;
    private ProtocolMappersResource oidcMappersRsc;
    private String samlClientScopeId;
    private ProtocolMappersResource samlMappersRsc;

    @BeforeEach
    public void init() {
        oidcClientScopeId = createClientScope("oidcMapperClient-scope", "openid-connect");
        oidcMappersRsc = clientScopes().get(oidcClientScopeId).getProtocolMappers();

        samlClientScopeId = createClientScope("samlMapperClient-scope", "saml");
        samlMappersRsc = clientScopes().get(samlClientScopeId).getProtocolMappers();

        super.initBuiltinMappers();
    }

    @AfterEach
    public void tearDown() {
        removeClientScope(oidcClientScopeId);
        removeClientScope(samlClientScopeId);
    }

    @Test
    public void test01GetMappersList() {
        assertTrue(oidcMappersRsc.getMappers().isEmpty());
        assertTrue(samlMappersRsc.getMappers().isEmpty());
    }

    @Test
    public void test02CreateOidcMappersFromList() {
        testAddAllBuiltinMappers(oidcMappersRsc, "openid-connect");
    }

    @Test
    public void test03CreateSamlMappersFromList() {
        testAddAllBuiltinMappers(samlMappersRsc, "saml");
    }

    @Test
    public void test04CreateSamlProtocolMapper() {

        //{"protocol":"saml",
        // "config":{"role":"account.view-profile","new.role.name":"new-role-name"},
        // "consentRequired":true,
        // "consentText":"My consent text",
        // "name":"saml-role-name-maper",
        // "protocolMapper":"saml-role-name-mapper"}
        ProtocolMapperRepresentation rep = makeSamlMapper("saml-role-name-mapper");

        int totalMappers = samlMappersRsc.getMappers().size();
        int totalSamlMappers = samlMappersRsc.getMappersPerProtocol("saml").size();
        Response resp = samlMappersRsc.createMapper(rep);
        resp.close();
        String createdId = ApiUtil.getCreatedId(resp);


        assertEquals(totalMappers + 1, samlMappersRsc.getMappers().size());
        assertEquals(totalSamlMappers + 1, samlMappersRsc.getMappersPerProtocol("saml").size());

        ProtocolMapperRepresentation created = samlMappersRsc.getMapperById(createdId);
        assertEqualMappers(rep, created);
    }

    @Test
    public void test05CreateOidcProtocolMapper() {
        //{"protocol":"openid-connect",
        // "config":{"role":"myrole"},
        // "consentRequired":true,
        // "consentText":"My consent text",
        // "name":"oidc-hardcoded-role-mapper",
        // "protocolMapper":"oidc-hardcoded-role-mapper"}
        ProtocolMapperRepresentation rep = makeOidcMapper("oidc-hardcoded-role-mapper");

        int totalMappers = oidcMappersRsc.getMappers().size();
        int totalOidcMappers = oidcMappersRsc.getMappersPerProtocol("openid-connect").size();
        Response resp = oidcMappersRsc.createMapper(rep);
        resp.close();
        String createdId = ApiUtil.getCreatedId(resp);
        
        assertEquals(totalMappers + 1, oidcMappersRsc.getMappers().size());
        assertEquals(totalOidcMappers + 1, oidcMappersRsc.getMappersPerProtocol("openid-connect").size());

        ProtocolMapperRepresentation created = oidcMappersRsc.getMapperById(createdId);//findByName(samlMappersRsc, "saml-role-name-mapper");
        assertEqualMappers(rep, created);
    }

    @Test
    public void test06UpdateSamlMapper() {
        ProtocolMapperRepresentation rep = makeSamlMapper("saml-role-name-mapper2");

        Response resp = samlMappersRsc.createMapper(rep);
        resp.close();
        String createdId = ApiUtil.getCreatedId(resp);

        rep.getConfig().put("role", "account.manage-account");
        rep.setId(createdId);
        samlMappersRsc.update(createdId, rep);

        ProtocolMapperRepresentation updated = samlMappersRsc.getMapperById(createdId);
        assertEqualMappers(rep, updated);
    }

    @Test
    public void test07UpdateOidcMapper() {
        ProtocolMapperRepresentation rep = makeOidcMapper("oidc-hardcoded-role-mapper2");

        Response resp = oidcMappersRsc.createMapper(rep);
        resp.close();
        String createdId = ApiUtil.getCreatedId(resp);

        rep.getConfig().put("role", "myotherrole");
        rep.setId(createdId);
        oidcMappersRsc.update(createdId, rep);

        ProtocolMapperRepresentation updated = oidcMappersRsc.getMapperById(createdId);
        assertEqualMappers(rep, updated);
    }

    @Test
    public void test08EffectiveMappers() {
        ClientScopeResource rolesScope = ApiUtil.findClientScopeByName(testRealmResource(), "roles");
        ProtocolMapperRepresentation audienceMapper = findMapperByName(rolesScope.getProtocolMappers().getMappers(),
                "openid-connect", "audience resolve");

        String clientScopeID = rolesScope.toRepresentation().getId();
        String protocolMapperId = audienceMapper.getId();
        Map<String, String> origConfig = audienceMapper.getConfig();

        try {
            // Test default values available on the protocol mapper
            assertEquals("true", audienceMapper.getConfig().get("access.token.claim"));
            assertEquals("true", audienceMapper.getConfig().get("introspection.token.claim"));

            // Update mapper to not contain default values
            audienceMapper.getConfig().remove("access.token.claim");
            audienceMapper.getConfig().remove("introspection.token.claim");
            rolesScope.getProtocolMappers().update(protocolMapperId, audienceMapper);

            // Test configuration will contain "effective values", which are the default values of particular options
            audienceMapper = rolesScope.getProtocolMappers().getMapperById(protocolMapperId);
            assertEquals("true", audienceMapper.getConfig().get("access.token.claim"));
            assertEquals("true", audienceMapper.getConfig().get("introspection.token.claim"));

            // Override "includeInIntrospection"
            audienceMapper.getConfig().put("introspection.token.claim", "false");
            rolesScope.getProtocolMappers().update(protocolMapperId, audienceMapper);

            // Get mapper and check that "includeInIntrospection" is using overriden value instead of the default
            audienceMapper = rolesScope.getProtocolMappers().getMapperById(protocolMapperId);
            assertEquals("true", audienceMapper.getConfig().get("access.token.claim"));
            assertEquals("false", audienceMapper.getConfig().get("introspection.token.claim"));

        } finally {
            audienceMapper.getConfig().putAll(origConfig);
            rolesScope.getProtocolMappers().update(protocolMapperId, audienceMapper);
        }
    }

    @Test
    public void testDeleteSamlMapper() {
        ProtocolMapperRepresentation rep = makeSamlMapper("saml-role-name-mapper3");

        Response resp = samlMappersRsc.createMapper(rep);
        resp.close();
        String createdId = ApiUtil.getCreatedId(resp);

        samlMappersRsc.delete(createdId);

        try {
            samlMappersRsc.getMapperById(createdId);
            fail("Not expected to find mapper");
        } catch (NotFoundException nfe) {
            // Expected
        }
    }

    @Test
    public void testDeleteOidcMapper() {
        ProtocolMapperRepresentation rep = makeOidcMapper("oidc-hardcoded-role-mapper3");

        Response resp = oidcMappersRsc.createMapper(rep);
        resp.close();
        String createdId = ApiUtil.getCreatedId(resp);

        oidcMappersRsc.delete(createdId);

        try {
            oidcMappersRsc.getMapperById(createdId);
            fail("Not expected to find mapper");
        } catch (NotFoundException nfe) {
            // Expected
        }
    }


    private ClientScopesResource clientScopes() {
        return testRealmResource().clientScopes();
    }

    private String createClientScope(String clientScopeName, String protocol) {
        ClientScopeRepresentation rep = new ClientScopeRepresentation();
        rep.setName(clientScopeName);
        rep.setProtocol(protocol);
        Response resp = clientScopes().create(rep);
        assertEquals(201, resp.getStatus());
        resp.close();
        String scopeId = ApiUtil.getCreatedId(resp);
        
        return scopeId;
    }

    private void removeClientScope(String clientScopeId) {
        clientScopes().get(clientScopeId).remove();
    }

    private static ProtocolMapperRepresentation findMapperByName(List<ProtocolMapperRepresentation> mappers, String type, String name) {
        if (mappers == null) {
            return null;
        }

        for (ProtocolMapperRepresentation mapper : mappers) {
            if (mapper.getProtocol().equals(type) &&
                    mapper.getName().equals(name)) {
                return mapper;
            }
        }
        return null;
    }
}
