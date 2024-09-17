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
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.admin.client.resource.AuthorizationResource;
import org.keycloak.admin.client.resource.ClientResource;
import org.keycloak.admin.client.resource.ClientsResource;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.authorization.client.AuthorizationDeniedException;
import org.keycloak.authorization.client.AuthzClient;
import org.keycloak.representations.idm.GroupRepresentation;
import org.keycloak.representations.idm.ProtocolMapperRepresentation;
import org.keycloak.representations.idm.RealmRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.keycloak.representations.idm.authorization.AuthorizationRequest;
import org.keycloak.representations.idm.authorization.AuthorizationResponse;
import org.keycloak.representations.idm.authorization.GroupPolicyRepresentation;
import org.keycloak.representations.idm.authorization.PermissionRequest;
import org.keycloak.representations.idm.authorization.ResourcePermissionRepresentation;
import org.keycloak.representations.idm.authorization.ResourceRepresentation;
import org.keycloak.testsuite.util.ClientBuilder;
import org.keycloak.testsuite.util.GroupBuilder;
import org.keycloak.testsuite.util.RealmBuilder;
import org.keycloak.testsuite.util.RoleBuilder;
import org.keycloak.testsuite.util.RolesBuilder;
import org.keycloak.testsuite.util.UserBuilder;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class GroupNamePolicyTest extends AbstractAuthzTest {

    @Override
    public List<RealmRepresentation> getRealmsForImport() {
        List<RealmRepresentation> testRealms = new ArrayList<>();
        ProtocolMapperRepresentation groupProtocolMapper = new ProtocolMapperRepresentation();

        groupProtocolMapper.setName("groups");
        groupProtocolMapper.setProtocolMapper("oidc-group-membership-mapper");
        groupProtocolMapper.setProtocol("openid-connect");
        Map<String, String> config = new HashMap<>();
        config.put("claim.name", "groups");
        config.put("access.token.claim", "true");
        config.put("id.token.claim", "true");
        groupProtocolMapper.setConfig(config);

        testRealms.add(RealmBuilder.create().name("authz-test")
                .roles(RolesBuilder.create()
                        .realmRole(RoleBuilder.create().name("uma_authorization").build())
                )
                .group(GroupBuilder.create().name("Group A")
                    .subGroups(Arrays.asList("Group B", "Group D").stream().map(name -> {
                        if ("Group B".equals(name)) {
                            return GroupBuilder.create().name(name).subGroups(Arrays.asList("Group C", "Group E").stream().map((String name1)
                                    -> GroupBuilder.create().name(name1).build()).collect(Collectors.toList())).build();
                        }
                        return GroupBuilder.create().name(name).build();
                    }).collect(Collectors.toList())).build())
                .group(GroupBuilder.create().name("Group E").build())
                .user(UserBuilder.create().username("marta").password("password").addRoles("uma_authorization").addGroups("Group A"))
                .user(UserBuilder.create().username("alice").password("password").addRoles("uma_authorization"))
                .user(UserBuilder.create().username("kolo").password("password").addRoles("uma_authorization"))
                .client(ClientBuilder.create().clientId("resource-server-test")
                    .secret("secret")
                    .authorizationServicesEnabled(true)
                    .redirectUris("http://localhost/resource-server-test")
                    .defaultRoles("uma_protection")
                    .directAccessGrants()
                    .protocolMapper(groupProtocolMapper)
                    .serviceAccountsEnabled(true))
                .build());
        return testRealms;
    }

    @BeforeEach
    public void configureAuthorization() throws Exception {
        createResource("Resource A");
        createResource("Resource B");
        createResource("Resource C");

        createGroupPolicy("Only Group A Policy", "/Group A", true);
        createGroupPolicy("Only Group B Policy", "/Group A/Group B", false);
        createGroupPolicy("Only Group C Policy", "/Group A/Group B/Group C", false);

        createResourcePermission("Resource A Permission", "Resource A", "Only Group A Policy");
        createResourcePermission("Resource B Permission", "Resource B", "Only Group B Policy");
        createResourcePermission("Resource C Permission", "Resource C", "Only Group C Policy");

        RealmResource realm = getRealm();
        GroupRepresentation group = getGroup("/Group A/Group B/Group C");
        UserRepresentation user = realm.users().search("kolo").get(0);

        realm.users().get(user.getId()).joinGroup(group.getId());

        group = getGroup("/Group A/Group B");
        user = realm.users().search("alice").get(0);

        realm.users().get(user.getId()).joinGroup(group.getId());
    }

    @Test
    public void testExactNameMatch() {
        AuthzClient authzClient = getAuthzClient();
        PermissionRequest request = new PermissionRequest("Resource A");
        String ticket = authzClient.protection().permission().create(request).getTicket();
        AuthorizationResponse response = authzClient.authorization("marta", "password").authorize(new AuthorizationRequest(ticket));

        Assertions.assertNotNull(response.getToken());

        try {
            authzClient.authorization("kolo", "password").authorize(new AuthorizationRequest(ticket));
            Assertions.fail("Should fail because user is not granted with expected group");
        } catch (AuthorizationDeniedException ignore) {

        }

        try {
            authzClient.authorization("alice", "password").authorize(new AuthorizationRequest(ticket));
            Assertions.fail("Should fail because user is not granted with expected group");
        } catch (AuthorizationDeniedException ignore) {

        }

        try {
            authzClient.authorization(authzClient.obtainAccessToken().getToken()).authorize(new AuthorizationRequest(ticket));
            Assertions.fail("Should fail because service account is not granted with expected group");
        } catch (AuthorizationDeniedException ignore) {

        }
    }

    @Test
    public void testOnlyChildrenPolicy() throws Exception {
        AuthzClient authzClient = getAuthzClient();
        PermissionRequest request = new PermissionRequest("Resource B");
        String ticket = authzClient.protection().permission().create(request).getTicket();

        try {
            authzClient.authorization("kolo", "password").authorize(new AuthorizationRequest(ticket));
            Assertions.fail("Should fail because user is not granted with expected group");
        } catch (AuthorizationDeniedException ignore) {

        }

        AuthorizationResponse response = authzClient.authorization("alice", "password").authorize(new AuthorizationRequest(ticket));

        Assertions.assertNotNull(response.getToken());

        try {
            authzClient.authorization("marta", "password").authorize(new AuthorizationRequest(ticket));
            Assertions.fail("Should fail because user is not granted with expected role");
        } catch (AuthorizationDeniedException ignore) {

        }

        request = new PermissionRequest("Resource C");
        ticket = authzClient.protection().permission().create(request).getTicket();
        response = authzClient.authorization("kolo", "password").authorize(new AuthorizationRequest(ticket));
        Assertions.assertNotNull(response.getToken());
    }

    private void createGroupPolicy(String name, String groupPath, boolean extendChildren) {
        GroupPolicyRepresentation policy = new GroupPolicyRepresentation();

        policy.setName(name);
        policy.setGroupsClaim("groups");
        policy.addGroupPath(groupPath, extendChildren);

        getClient().authorization().policies().group().create(policy).close();
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

    private GroupRepresentation getGroup(String path) {
        String[] parts = path.split("/");
        RealmResource realm = getRealm();
        GroupRepresentation parent = null;

        for (String part : parts) {
            if ("".equals(part)) {
                continue;
            }
            if (parent == null) {
                parent = realm.groups().groups().stream().filter((GroupRepresentation groupRepresentation)
                        -> part.equals(groupRepresentation.getName())).findFirst().get();
                continue;
            }

            GroupRepresentation group = getGroup(part, realm.groups().group(parent.getId()).getSubGroups(0, 10, true));

            if (path.endsWith(group.getName())) {
                return group;
            }

            parent = group;
        }

        return null;
    }

    private GroupRepresentation getGroup(String name, List<GroupRepresentation> groups) {
        RealmResource realm = getRealm();
        for (GroupRepresentation group : groups) {
            if (name.equals(group.getName())) {
                return group;
            }

            GroupRepresentation child = getGroup(name, realm.groups().group(group.getId()).getSubGroups(0, 10, true));

            if (child != null && name.equals(child.getName())) {
                return child;
            }
        }

        return null;
    }
}