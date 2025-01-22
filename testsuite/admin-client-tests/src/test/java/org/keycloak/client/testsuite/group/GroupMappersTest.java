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

package org.keycloak.client.testsuite.group;

import jakarta.ws.rs.core.Response;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.admin.client.resource.ProtocolMappersResource;
import org.keycloak.admin.client.resource.RealmResource;

import org.keycloak.representations.AccessToken;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.representations.idm.GroupRepresentation;
import org.keycloak.representations.idm.ProtocolMapperRepresentation;
import org.keycloak.representations.idm.RealmRepresentation;
import org.keycloak.representations.idm.UserRepresentation;

import org.keycloak.testsuite.util.ApiUtil;
import org.keycloak.testsuite.util.KeycloakModelUtils;

import java.util.Collection;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.testcontainers.shaded.org.hamcrest.MatcherAssert.assertThat;
import static org.testcontainers.shaded.org.hamcrest.Matchers.containsInAnyOrder;

/**
 * @author <a href="mailto:mstrukel@redhat.com">Marko Strukelj</a>
 */
public class GroupMappersTest extends AbstractGroupTest {

    public static final String TOKEN_CLAIM_NAME = "claim.name";
    public static final String TOKEN_CLAIM_NAME_LABEL = "tokenClaimName.label";
    public static final String TOKEN_CLAIM_NAME_TOOLTIP = "tokenClaimName.tooltip";
    public static final String JSON_TYPE = "jsonType.label";
    public static final String JSON_TYPE_TOOLTIP = "jsonType.tooltip";
    public static final String INCLUDE_IN_ACCESS_TOKEN = "access.token.claim";
    public static final String INCLUDE_IN_ACCESS_TOKEN_LABEL = "includeInAccessToken.label";
    public static final String INCLUDE_IN_ACCESS_TOKEN_HELP_TEXT = "includeInAccessToken.tooltip";
    public static final String INCLUDE_IN_ID_TOKEN = "id.token.claim";
    private final String GRPUP_MEMBERSHIP_MAPPER_PROVIDER_ID = "oidc-group-membership-mapper";

    @BeforeEach
    public void updateTestRealms() {
        RealmRepresentation testRealmRep = adminClient.realm("test").toRepresentation();
        testRealmRep.setEventsEnabled(true);
        adminClient.realms().realm("test").update(testRealmRep);

        ClientRepresentation client = adminClient.realm("test").clients().findByClientId("test-app").get(0);
        assertNotNull(client);

        client.setDirectAccessGrantsEnabled(true);

        List<ProtocolMapperRepresentation> mappers = new LinkedList<>();
        ProtocolMapperRepresentation mapper = new ProtocolMapperRepresentation();
        mapper.setName("groups");
        mapper.setProtocolMapper(GRPUP_MEMBERSHIP_MAPPER_PROVIDER_ID);
        mapper.setProtocol("openid-connect");
        Map<String, String> config = new HashMap<>();
        config.put(TOKEN_CLAIM_NAME, "groups.groups");
        config.put(INCLUDE_IN_ACCESS_TOKEN, "true");
        config.put(INCLUDE_IN_ID_TOKEN, "true");
        mapper.setConfig(config);
        mappers.add(mapper);

        mapper = new ProtocolMapperRepresentation();
        mapper.setName("topAttribute");
        mapper.setProtocolMapper("oidc-usermodel-attribute-mapper");
        mapper.setProtocol("openid-connect");
        config = new HashMap<>();
        config.put("user.attribute", "topAttribute");
        config.put(TOKEN_CLAIM_NAME, "topAttribute");
        config.put(JSON_TYPE, "String");
        config.put(INCLUDE_IN_ACCESS_TOKEN, "true");
        config.put(INCLUDE_IN_ID_TOKEN, "true");
        mapper.setConfig(config);
        mappers.add(mapper);

        mapper = new ProtocolMapperRepresentation();
        mapper.setName("level2Attribute");
        mapper.setProtocolMapper("oidc-usermodel-attribute-mapper");
        mapper.setProtocol("openid-connect");
        config = new HashMap<>();
        config.put("user.attribute", "level2Attribute");
        config.put(TOKEN_CLAIM_NAME, "level2Attribute");
        config.put(JSON_TYPE, "String");
        config.put(INCLUDE_IN_ACCESS_TOKEN, "true");
        config.put(INCLUDE_IN_ID_TOKEN, "true");
        mapper.setConfig(config);
        mappers.add(mapper);

        client.setProtocolMappers(mappers);
        adminClient.realm("test").clients().get(client.getId()).update(client);
    }

    private ClientRepresentation getClientByAlias(RealmRepresentation testRealmRep, String alias) {
        for (ClientRepresentation client: testRealmRep.getClients()) {
            if (alias.equals(client.getClientId())) {
                return client;
            }
        }
        return null;
    }

    @Test
    @SuppressWarnings("unchecked")
    public void testGroupMappers() throws Exception {
        RealmResource realm = adminClient.realms().realm("test");
        {
            UserRepresentation user = realm.users().search("topGroupUser", -1, -1).get(0);

            AccessToken token = login(user.getUsername(), "test-app", "password", user.getId());
            assertTrue(token.getRealmAccess().getRoles().contains("user"));
            assertNotNull(token.getOtherClaims().get("groups"));
            Map<String, Collection<String>> groups = (Map<String, Collection<String>>) token.getOtherClaims().get("groups");
            assertTrue(groups.get("groups").contains("topGroup"));
            assertEquals("true", token.getOtherClaims().get("topAttribute"));
        }
        {
            UserRepresentation user = realm.users().search("level2GroupUser", -1, -1).get(0);

            AccessToken token = login(user.getUsername(), "test-app", "password", user.getId());
            assertTrue(token.getRealmAccess().getRoles().contains("user"));
            assertTrue(token.getRealmAccess().getRoles().contains("admin"));
            assertTrue(token.getResourceAccess("test-app").getRoles().contains("customer-user"));
            assertNotNull(token.getOtherClaims().get("groups"));
            Map<String, Collection<String>> groups = (Map<String, Collection<String>>) token.getOtherClaims().get("groups");
            assertTrue(groups.get("groups").contains("level2group"));
            assertEquals("true", token.getOtherClaims().get("topAttribute"));
            assertEquals("true", token.getOtherClaims().get("level2Attribute"));
        }
    }

    @Test
    public void testGroupMappersWithSlash() throws Exception {
        RealmResource realm = adminClient.realms().realm("test");
        GroupRepresentation topGroup = realm.getGroupByPath("/topGroup");
        assertNotNull(topGroup);
        GroupRepresentation childSlash = new GroupRepresentation();
        childSlash.setName("child/slash");
        try (Response response = realm.groups().group(topGroup.getId()).subGroup(childSlash)) {
            assertEquals(Response.Status.CREATED.getStatusCode(), response.getStatus());
            childSlash.setId(ApiUtil.getCreatedId(response));
        }
        List<UserRepresentation> users = realm.users().search("level2GroupUser", true);
        assertEquals(1, users.size());
        UserRepresentation user = users.iterator().next();
        realm.users().get(user.getId()).joinGroup(childSlash.getId());


        ProtocolMappersResource protocolMappers = ApiUtil.findClientResourceByClientId(realm, "test-app").getProtocolMappers();
        ProtocolMapperRepresentation groupsMapper = protocolMappers.getMappersPerProtocol("openid-connect").stream().filter(mapper-> mapper.getName().equals("groups")).findFirst().get();


        groupsMapper.getConfig().put("full.path", Boolean.TRUE.toString());
        protocolMappers.update(groupsMapper.getId(), groupsMapper);

        try {
            AccessToken token = login(user.getUsername(), "test-app", "password", user.getId());
            assertNotNull(token.getOtherClaims().get("groups"));
            Map<String, Collection<String>> groups = (Map<String, Collection<String>>) token.getOtherClaims().get("groups");
            assertThat(groups.get("groups"), containsInAnyOrder(
                    KeycloakModelUtils.buildGroupPath(false, "topGroup", "level2group"),
                    KeycloakModelUtils.buildGroupPath(false, "topGroup", "child/slash")));
        } finally {
            realm.users().get(user.getId()).leaveGroup(childSlash.getId());
            realm.groups().group(childSlash.getId()).remove();
            groupsMapper.getConfig().remove("full.path");
            protocolMappers.update(groupsMapper.getId(), groupsMapper);
        }
    }
}
