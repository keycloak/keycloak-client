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

import com.google.common.collect.Comparators;
import jakarta.ws.rs.ClientErrorException;
import jakarta.ws.rs.NotFoundException;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.Response.Status;

import org.junit.jupiter.api.Test;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.resource.GroupResource;
import org.keycloak.admin.client.resource.GroupsResource;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.admin.client.resource.RoleMappingResource;
import org.keycloak.admin.client.resource.UserProfileResource;
import org.keycloak.admin.client.resource.UserResource;
import org.keycloak.admin.client.resource.UsersResource;
import org.keycloak.client.testsuite.common.Creator;
import org.keycloak.client.testsuite.models.Constants;

import org.keycloak.representations.AccessToken;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.representations.idm.ErrorRepresentation;
import org.keycloak.representations.idm.GroupRepresentation;
import org.keycloak.representations.idm.MappingsRepresentation;
import org.keycloak.representations.idm.RealmRepresentation;
import org.keycloak.representations.idm.RoleRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.keycloak.representations.userprofile.config.UPConfig;

import org.keycloak.testsuite.util.AdminClientUtil;
import org.keycloak.testsuite.util.ApiUtil;
import org.keycloak.testsuite.util.ClientBuilder;
import org.keycloak.testsuite.util.GroupBuilder;
import org.keycloak.testsuite.util.KeycloakModelUtils;
import org.keycloak.testsuite.util.RoleBuilder;
import org.keycloak.testsuite.util.UserBuilder;
import org.keycloak.util.JsonSerialization;

import java.io.IOException;
import java.net.URI;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;

import static io.smallrye.common.constraint.Assert.assertFalse;
import static io.smallrye.common.constraint.Assert.assertTrue;
import static org.keycloak.client.testsuite.Assert.assertNames;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.fail;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.testcontainers.shaded.org.hamcrest.MatcherAssert.assertThat;
import static org.testcontainers.shaded.org.hamcrest.Matchers.is;
import static org.testcontainers.shaded.org.hamcrest.Matchers.containsInAnyOrder;
import static org.testcontainers.shaded.org.hamcrest.Matchers.hasEntry;
import static org.testcontainers.shaded.org.hamcrest.Matchers.contains;
import static org.testcontainers.shaded.org.hamcrest.Matchers.not;
import static org.testcontainers.shaded.org.hamcrest.Matchers.empty;
import static org.testcontainers.shaded.org.hamcrest.Matchers.notNullValue;
import static org.testcontainers.shaded.org.hamcrest.Matchers.anEmptyMap;
import static org.testcontainers.shaded.org.hamcrest.Matchers.hasSize;
import static org.testcontainers.shaded.org.hamcrest.Matchers.equalTo;



/**
 * @author <a href="mailto:mstrukel@redhat.com">Marko Strukelj</a>
 */
public class GroupTest extends AbstractGroupTest {

    /**
     * KEYCLOAK-2716
     * @throws Exception
     */
    @Test
    public void testClientRemoveWithClientRoleGroupMapping() throws Exception {
        RealmResource realm = adminClient.realms().realm("test");

        ClientRepresentation client = new ClientRepresentation();
        client.setClientId("foo");
        client.setRootUrl("http://foo");
        client.setProtocol("openid-connect");
        Response response = realm.clients().create(client);
        response.close();
        String clientUuid = ApiUtil.getCreatedId(response);
        client = realm.clients().findByClientId("foo").get(0);

        RoleRepresentation role = new RoleRepresentation();
        role.setName("foo-role");
        realm.clients().get(client.getId()).roles().create(role);
        role = realm.clients().get(client.getId()).roles().get("foo-role").toRepresentation();

        GroupRepresentation group = new GroupRepresentation();
        group.setName("2716");
        group = createGroup(realm, group);

        List<RoleRepresentation> list = new LinkedList<>();
        list.add(role);
        realm.groups().group(group.getId()).roles().clientLevel(client.getId()).add(list);

        assertEquals(realm.groups().group(group.getId()).roles().clientLevel(client.getId()).listAll().get(0).getName(), role.getName());

        realm.clients().get(client.getId()).remove();
    }

    @Test
    // KEYCLOAK-16888 Error messages for groups with same name in the same level
    public void doNotAllowSameGroupNameAtSameLevel() throws Exception {
        RealmResource realm = adminClient.realms().realm("test");

        GroupRepresentation topGroup = new GroupRepresentation();
        topGroup.setName("top");
        topGroup = createGroup(realm, topGroup);

        GroupRepresentation anotherTopGroup = new GroupRepresentation();
        anotherTopGroup.setName("top");
        Response response = realm.groups().add(anotherTopGroup);
        assertSameNameNotAllowed(response,"Top level group named 'top' already exists.");
        response.close();

        // allow moving the group to top level (nothing is done)
        response = realm.groups().add(topGroup);
        assertEquals(Status.NO_CONTENT, response.getStatusInfo());
        response.close();

        GroupRepresentation level2Group = new GroupRepresentation();
        level2Group.setName("level2");
        response = realm.groups().group(topGroup.getId()).subGroup(level2Group);
        assertEquals(201, response.getStatus()); // created status
        level2Group.setId(ApiUtil.getCreatedId(response));
        response.close();

        GroupRepresentation anotherlevel2Group = new GroupRepresentation();
        anotherlevel2Group.setName("level2");
        response = realm.groups().group(topGroup.getId()).subGroup(anotherlevel2Group);
        assertSameNameNotAllowed(response,"Sibling group named 'level2' already exists.");
        response.close();

        // allow moving the group to the same parent (nothing is done)
        response = realm.groups().group(topGroup.getId()).subGroup(level2Group);
        assertEquals(Status.NO_CONTENT, response.getStatusInfo());
        response.close();
    }

    @Test
    // KEYCLOAK-11412 Unintended Groups with same names
    public void doNotAllowSameGroupNameAtSameLevelWhenUpdatingName() throws Exception {
        RealmResource realm = adminClient.realms().realm("test");

        GroupRepresentation topGroup = new GroupRepresentation();
        topGroup.setName("top1");
        topGroup = createGroup(realm, topGroup);

        GroupRepresentation anotherTopGroup = new GroupRepresentation();
        anotherTopGroup.setName("top2");
        anotherTopGroup = createGroup(realm, anotherTopGroup);

        anotherTopGroup.setName("top1");

        try {
            realm.groups().group(anotherTopGroup.getId()).update(anotherTopGroup);
            fail("Expected ClientErrorException");
        } catch (ClientErrorException e) {
            // conflict status 409 - same name not allowed
            assertSameNameNotAllowed(e.getResponse(),"Sibling group named 'top1' already exists.");
        }

        GroupRepresentation level2Group = new GroupRepresentation();
        level2Group.setName("level2-1");
        addSubGroup(realm, topGroup, level2Group);

        GroupRepresentation anotherlevel2Group = new GroupRepresentation();
        anotherlevel2Group.setName("level2-2");
        addSubGroup(realm, topGroup, anotherlevel2Group);

        anotherlevel2Group.setName("level2-1");

        try {
            realm.groups().group(anotherlevel2Group.getId()).update(anotherlevel2Group);
            fail("Expected ClientErrorException");
        } catch (ClientErrorException e) {
            // conflict status 409 - same name not allowed
            assertSameNameNotAllowed(e.getResponse(),"Sibling group named 'level2-1' already exists.");
        }
    }

    @Test
    public void allowSameGroupNameAtDifferentLevel() throws Exception {
        RealmResource realm = adminClient.realms().realm("test");

        // creating "/test-group"
        GroupRepresentation topGroup = new GroupRepresentation();
        topGroup.setName("test-group");
        topGroup = createGroup(realm, topGroup);
        getCleanup().addGroupId(topGroup.getId());

        // creating "/test-group/test-group"
        GroupRepresentation childGroup = new GroupRepresentation();
        childGroup.setName("test-group");
        try (Response response = realm.groups().group(topGroup.getId()).subGroup(childGroup)) {
            assertEquals(201, response.getStatus());
            getCleanup().addGroupId(ApiUtil.getCreatedId(response));
        }

        assertNotNull(realm.getGroupByPath("/test-group/test-group"));
    }

    @Test
    public void doNotAllowSameGroupNameAtTopLevel() throws Exception {
        RealmResource realm = adminClient.realms().realm("test");

        // creating "/test-group"
        GroupRepresentation topGroup = new GroupRepresentation();
        topGroup.setName("test-group");
        topGroup = createGroup(realm, topGroup);
        getCleanup("test").addGroupId(topGroup.getId());

        GroupRepresentation group2 = new GroupRepresentation();
        group2.setName("test-group");
        try (Response response = realm.groups().add(group2)) {
            assertEquals(Status.CONFLICT.getStatusCode(), response.getStatus());
        }
    }

    // KEYCLOAK-17581
    @Test
    public void createGroupWithEmptyNameShouldFail() {

        RealmResource realm = adminClient.realms().realm("test");

        GroupRepresentation group = new GroupRepresentation();
        group.setName("");
        try (Response response = realm.groups().add(group)){
            if (response.getStatus() != 400) {
                fail("Creating a group with empty name should fail");
            }
        } catch (Exception expected) {
            assertNotNull(expected);
        }

        group.setName(null);
        try (Response response = realm.groups().add(group)){
            if (response.getStatus() != 400) {
                fail("Creating a group with null name should fail");
            }
        } catch (Exception expected) {
            assertNotNull(expected);
        }
    }

    // KEYCLOAK-17581
    @Test
    public void updatingGroupWithEmptyNameShouldFail() {

        RealmResource realm = adminClient.realms().realm("test");

        GroupRepresentation group = new GroupRepresentation();
        group.setName("groupWithName");

        String groupId = null;
        try (Response response = realm.groups().add(group)) {
            groupId = ApiUtil.getCreatedId(response);
        }

        try {
            group.setName("");
            realm.groups().group(groupId).update(group);
            fail("Updating a group with empty name should fail");
        } catch(Exception expected) {
            assertNotNull(expected);
        }

        try {
            group.setName(null);
            realm.groups().group(groupId).update(group);
            fail("Updating a group with null name should fail");
        } catch(Exception expected) {
            assertNotNull(expected);
        }
    }

    @Test
    public void createAndTestGroups() throws Exception {
        RealmResource realm = adminClient.realms().realm("test");
        RoleRepresentation topRole = createRealmRole(realm, RoleBuilder.create().name("topRole").build());
        RoleRepresentation level2Role = createRealmRole(realm, RoleBuilder.create().name("level2Role").build());
        RoleRepresentation level3Role = createRealmRole(realm, RoleBuilder.create().name("level3Role").build());


        GroupRepresentation topGroup = new GroupRepresentation();
        topGroup.setName("top");
        topGroup = createGroup(realm, topGroup);

        List<RoleRepresentation> roles = new LinkedList<>();
        roles.add(topRole);
        realm.groups().group(topGroup.getId()).roles().realmLevel().add(roles);

        GroupRepresentation level2Group = new GroupRepresentation();
        level2Group.setName("level2");
        Response response = realm.groups().group(topGroup.getId()).subGroup(level2Group);
        response.close();

        URI location = response.getLocation();
        final String level2Id = ApiUtil.getCreatedId(response);
        final GroupRepresentation level2GroupById = realm.groups().group(level2Id).toRepresentation();
        assertEquals(level2Id, level2GroupById.getId());
        assertEquals(level2Group.getName(), level2GroupById.getName());

        level2Group = realm.getGroupByPath("/top/level2");
        assertNotNull(level2Group);
        roles.clear();
        roles.add(level2Role);
        realm.groups().group(level2Group.getId()).roles().realmLevel().add(roles);

        GroupRepresentation level3Group = new GroupRepresentation();
        level3Group.setName("level3");
        response = realm.groups().group(level2Group.getId()).subGroup(level3Group);
        response.close();

        level3Group = realm.getGroupByPath("/top/level2/level3");
        assertNotNull(level3Group);
        roles.clear();
        roles.add(level3Role);
        realm.groups().group(level3Group.getId()).roles().realmLevel().add(roles);

        topGroup = realm.getGroupByPath("/top");
        assertEquals(1, topGroup.getRealmRoles().size());
        assertTrue(topGroup.getRealmRoles().contains("topRole"));
        assertEquals(1, realm.groups().group(topGroup.getId()).getSubGroups(0, null, false).size());

        level2Group = realm.getGroupByPath("/top/level2");
        assertEquals("level2", level2Group.getName());
        assertEquals(1, level2Group.getRealmRoles().size());
        assertTrue(level2Group.getRealmRoles().contains("level2Role"));
        assertEquals(1, realm.groups().group(level2Group.getId()).getSubGroups(0, null, false).size());

        level3Group = realm.getGroupByPath("/top/level2/level3");
        assertEquals("level3", level3Group.getName());
        assertEquals(1, level3Group.getRealmRoles().size());
        assertTrue(level3Group.getRealmRoles().contains("level3Role"));

        UserRepresentation user = realm.users().search("direct-login", -1, -1).get(0);
        realm.users().get(user.getId()).roles().realmLevel().remove(realm.users().get(user.getId()).roles().realmLevel().listAll());

        realm.users().get(user.getId()).joinGroup(level3Group.getId());

        List<GroupRepresentation> membership = realm.users().get(user.getId()).groups();
        assertEquals(1, membership.size());
        assertEquals("level3", membership.get(0).getName());

        oauth.realm("test");
        AccessToken token = login("direct-login", "resource-owner", "secret", user.getId());
        assertTrue(token.getRealmAccess().getRoles().contains("topRole"));
        assertTrue(token.getRealmAccess().getRoles().contains("level2Role"));
        assertTrue(token.getRealmAccess().getRoles().contains("level3Role"));

        realm.addDefaultGroup(level3Group.getId());

        List<GroupRepresentation> defaultGroups = realm.getDefaultGroups();
        assertEquals(1, defaultGroups.size());
        assertEquals(defaultGroups.get(0).getId(), level3Group.getId());

        UserRepresentation newUser = new UserRepresentation();
        newUser.setUsername("groupUser");
        newUser.setEmail("group@group.com");
        response = realm.users().create(newUser);
        String userId = ApiUtil.getCreatedId(response);
        response.close();

        membership = realm.users().get(userId).groups();
        assertEquals(1, membership.size());
        assertEquals("level3", membership.get(0).getName());

        realm.removeDefaultGroup(level3Group.getId());

        defaultGroups = realm.getDefaultGroups();
        assertEquals(0, defaultGroups.size());

        realm.groups().group(topGroup.getId()).remove();

        try {
            realm.getGroupByPath("/top/level2/level3");
            fail("Group should not have been found");
        }
        catch (NotFoundException e) {}

        try {
            realm.getGroupByPath("/top/level2");
            fail("Group should not have been found");
        }
        catch (NotFoundException e) {}

        try {
            realm.getGroupByPath("/top");
            fail("Group should not have been found");
        }
        catch (NotFoundException e) {}

        assertNull(login("direct-login", "resource-owner", "secret", user.getId()).getRealmAccess());
    }

    @Test
    public void updateGroup() {
        RealmResource realm = adminClient.realms().realm("test");
        final String groupName = "group-" + UUID.randomUUID();

        GroupRepresentation group = GroupBuilder.create()
          .name(groupName)
          .singleAttribute("attr1", "attrval1")
          .singleAttribute("attr2", "attrval2")
          .build();
        createGroup(realm, group);
        group = realm.getGroupByPath("/" + groupName);

        assertNotNull(group);
        assertThat(group.getName(), is(groupName));
        assertThat(group.getAttributes().keySet(), containsInAnyOrder("attr1", "attr2"));
        assertThat(group.getAttributes(), hasEntry(is("attr1"), contains("attrval1")));
        assertThat(group.getAttributes(), hasEntry(is("attr2"), contains("attrval2")));

        final String groupNewName = "group-" + UUID.randomUUID();
        group.setName(groupNewName);

        group.getAttributes().remove("attr1");
        group.getAttributes().get("attr2").add("attrval2-2");
        group.getAttributes().put("attr3", Collections.singletonList("attrval2"));

        realm.groups().group(group.getId()).update(group);

        group = realm.getGroupByPath("/" + groupNewName);

        assertThat(group.getName(), is(groupNewName));
        assertThat(group.getAttributes().keySet(), containsInAnyOrder("attr2", "attr3"));
        assertThat(group.getAttributes(), hasEntry(is("attr2"), containsInAnyOrder("attrval2", "attrval2-2")));
        assertThat(group.getAttributes(), hasEntry(is("attr3"), contains("attrval2")));
    }

    @Test
    public void moveGroups() {
        RealmResource realm = adminClient.realms().realm("test");

        // Create 2 top level groups "mygroup1" and "mygroup2"
        GroupRepresentation group = GroupBuilder.create()
                .name("mygroup1")
                .build();
        GroupRepresentation group1 = createGroup(realm, group);

        group = GroupBuilder.create()
                .name("mygroup2")
                .build();
        GroupRepresentation group2 = createGroup(realm, group);

        // Move "mygroup2" as child of "mygroup1" . Assert it was moved
        Response response = realm.groups().group(group1.getId()).subGroup(group2);
        assertEquals(204, response.getStatus());
        response.close();

        // Assert "mygroup2" was moved
        List<GroupRepresentation> group1Children = realm.groups().group(group1.getId()).getSubGroups(0, 10, false);
        List<GroupRepresentation> group2Children = realm.groups().group(group2.getId()).getSubGroups(0, 10, false);

        assertNames(group1Children, "mygroup2");
        assertEquals("/mygroup1/mygroup2", realm.groups().group(group2.getId()).toRepresentation().getPath());


        // Create top level group with the same name
        group = GroupBuilder.create()
                .name("mygroup2")
                .build();
        GroupRepresentation group3 = createGroup(realm, group);
        // Try to move top level "mygroup2" as child of "mygroup1". It should fail as there is already a child group
        // of "mygroup1" with name "mygroup2"
        response = realm.groups().group(group1.getId()).subGroup(group3);
        assertEquals(409, response.getStatus());
        realm.groups().group(group3.getId()).remove();

        // Move "mygroup2" back under parent
        response = realm.groups().add(group2);
        assertEquals(204, response.getStatus());
        response.close();

        // Assert "mygroup2" was moved
        group1Children = realm.groups().group(group1.getId()).getSubGroups(0, 10, false);
        group2Children = realm.groups().group(group2.getId()).getSubGroups(0, 10, false);
        assertEquals(0, group1Children.size());
        assertEquals("/mygroup2", realm.groups().group(group2.getId()).toRepresentation().getPath());
    }

    @Test
    public void groupMembership() {
        RealmResource realm = adminClient.realms().realm("test");

        GroupRepresentation group = new GroupRepresentation();
        group.setName("group");
        String groupId = createGroup(realm, group).getId();

        Response response = realm.users().create(UserBuilder.create().username("user-a").build());
        String userAId = ApiUtil.getCreatedId(response);
        response.close();

        response = realm.users().create(UserBuilder.create().username("user-b").build());
        String userBId = ApiUtil.getCreatedId(response);
        response.close();

        realm.users().get(userAId).joinGroup(groupId);

        List<UserRepresentation> members = realm.groups().group(groupId).members(0, 10);
        assertNames(members, "user-a");

        realm.users().get(userBId).joinGroup(groupId);

        members = realm.groups().group(groupId).members(0, 10);
        assertNames(members, "user-a", "user-b");

        realm.users().get(userAId).leaveGroup(groupId);

        members = realm.groups().group(groupId).members(0, 10);
        assertNames(members, "user-b");

        List<GroupRepresentation> groups = realm.users().get(userAId).groups(null, null);
        assertNames(groups, new String[] {});
    }


    @Test
    //KEYCLOAK-6300
    public void groupMembershipUsersOrder() {
        RealmResource realm = adminClient.realms().realm("test");

        GroupRepresentation group = new GroupRepresentation();
        group.setName("group");
        String groupId = createGroup(realm, group).getId();

        List<String> usernames = new ArrayList<>();
        for (int i = 0; i < 9; i++) {
            UserRepresentation user = UserBuilder.create().username("user" + i).build();
            usernames.add(user.getUsername());

            try (Response create = realm.users().create(user)) {
                assertEquals(Status.CREATED, create.getStatusInfo());

                String userAId = ApiUtil.getCreatedId(create);
                realm.users().get(userAId).joinGroup(groupId);
            }
        }

        List<String> memberUsernames = new ArrayList<>();
        for (UserRepresentation member : realm.groups().group(groupId).members(0, 10)) {
            memberUsernames.add(member.getUsername());
        }
        assertArrayEquals(usernames.toArray(), memberUsernames.toArray(), "Expected: " + usernames + ", was: " + memberUsernames);
    }

    @Test
    // KEYCLOAK-2700
    public void deleteRealmWithDefaultGroups() throws IOException {
        RealmRepresentation rep = new RealmRepresentation();
        rep.setRealm("foo");

        GroupRepresentation group = new GroupRepresentation();
        group.setName("default1");
        group.setPath("/default1");

        rep.setGroups(Collections.singletonList(group));
        rep.setDefaultGroups(Collections.singletonList("/default1"));

        adminClient.realms().create(rep);

        adminClient.realm(rep.getRealm()).remove();
    }

    @Test
    public void roleMappings() {
        RealmResource realm = adminClient.realms().realm("test");
        createRealmRole(realm, RoleBuilder.create().name("realm-role").build());
        createRealmRole(realm, RoleBuilder.create().name("realm-composite").build());
        createRealmRole(realm, RoleBuilder.create().name("realm-child").build());
        realm.roles().get("realm-composite").addComposites(Collections.singletonList(realm.roles().get("realm-child").toRepresentation()));

        try (Response response = realm.clients().create(ClientBuilder.create().clientId("myclient").build())) {
            String clientId = ApiUtil.getCreatedId(response);
            getCleanup("test").addClientUuid(clientId);

            realm.clients().get(clientId).roles().create(RoleBuilder.create().name("client-role").build());
            realm.clients().get(clientId).roles().create(RoleBuilder.create().name("client-role2").build());
            realm.clients().get(clientId).roles().create(RoleBuilder.create().name("client-composite").build());
            realm.clients().get(clientId).roles().create(RoleBuilder.create().name("client-child").build());
            realm.clients().get(clientId).roles().get("client-composite").addComposites(Collections.singletonList(realm.clients().get(clientId).roles().get("client-child").toRepresentation()));
            

            GroupRepresentation group = new GroupRepresentation();
            group.setName("group");
            String groupId = createGroup(realm, group).getId();

            RoleMappingResource roles = realm.groups().group(groupId).roles();
            assertEquals(0, roles.realmLevel().listAll().size());

            // Add realm roles
            List<RoleRepresentation> l = new LinkedList<>();
            l.add(realm.roles().get("realm-role").toRepresentation());
            l.add(realm.roles().get("realm-composite").toRepresentation());
            roles.realmLevel().add(l);

            // Add client roles
            RoleRepresentation clientRole = realm.clients().get(clientId).roles().get("client-role").toRepresentation();
            RoleRepresentation clientComposite = realm.clients().get(clientId).roles().get("client-composite").toRepresentation();
            roles.clientLevel(clientId).add(Collections.singletonList(clientRole));
            roles.clientLevel(clientId).add(Collections.singletonList(clientComposite));
            // List realm roles
            assertNames(roles.realmLevel().listAll(), "realm-role", "realm-composite");
            assertNames(roles.realmLevel().listAvailable(), "realm-child", "admin", "offline_access", Constants.AUTHZ_UMA_AUTHORIZATION, "user", "customer-user-premium", "realm-composite-role", "sample-realm-role", "attribute-role", Constants.DEFAULT_ROLES_ROLE_PREFIX + "-test");
            assertNames(roles.realmLevel().listEffective(), "realm-role", "realm-composite", "realm-child");

            // List client roles
            assertNames(roles.clientLevel(clientId).listAll(), "client-role", "client-composite");
            assertNames(roles.clientLevel(clientId).listAvailable(), "client-role2", "client-child");
            assertNames(roles.clientLevel(clientId).listEffective(), "client-role", "client-composite", "client-child");

            // Get mapping representation
            MappingsRepresentation all = roles.getAll();
            assertNames(all.getRealmMappings(), "realm-role", "realm-composite");
            assertEquals(1, all.getClientMappings().size());
            assertNames(all.getClientMappings().get("myclient").getMappings(), "client-role", "client-composite");

            // Remove realm role
            RoleRepresentation realmRoleRep = realm.roles().get("realm-role").toRepresentation();
            roles.realmLevel().remove(Collections.singletonList(realmRoleRep));
            assertNames(roles.realmLevel().listAll(), "realm-composite");

            // Remove client role
            RoleRepresentation clientRoleRep = realm.clients().get(clientId).roles().get("client-role").toRepresentation();
            roles.clientLevel(clientId).remove(Collections.singletonList(clientRoleRep));
            assertNames(roles.clientLevel(clientId).listAll(), "client-composite");
        }
    }

    /**
     * Test for KEYCLOAK-10603.
     */
    @Test
    public void rolesCanBeAssignedEvenWhenTheyAreAlreadyIndirectlyAssigned() {
        RealmResource realm = adminClient.realms().realm("test");

         createRealmRole(realm, RoleBuilder.create().name("realm-composite").build());
        createRealmRole(realm, RoleBuilder.create().name("realm-child").build());
        realm.roles().get("realm-composite")
                .addComposites(Collections.singletonList(realm.roles().get("realm-child").toRepresentation()));

        getCleanup("test").addRoleId(realm.roles().get("realm-composite").toRepresentation().getId());
        getCleanup("test").addRoleId(realm.roles().get("realm-child").toRepresentation().getId());


        try (Response response = realm.clients().create(ClientBuilder.create().clientId("myclient").build())) {
            String clientId = ApiUtil.getCreatedId(response);
            getCleanup("test").addClientUuid(clientId);

            realm.clients().get(clientId).roles().create(RoleBuilder.create().name("client-composite").build());
            realm.clients().get(clientId).roles().create(RoleBuilder.create().name("client-child").build());
            realm.clients().get(clientId).roles().get("client-composite").addComposites(Collections
                    .singletonList(realm.clients().get(clientId).roles().get("client-child").toRepresentation()));

            GroupRepresentation group = new GroupRepresentation();
            group.setName("group");
            

            String groupId = createGroup(realm, group).getId();

            RoleMappingResource roles = realm.groups().group(groupId).roles();
            // Make indirect assignments: assign composite roles
            roles.realmLevel()
                    .add(Collections.singletonList(realm.roles().get("realm-composite").toRepresentation()));
            RoleRepresentation clientComposite =
                    realm.clients().get(clientId).roles().get("client-composite").toRepresentation();
            roles.clientLevel(clientId).add(Collections.singletonList(clientComposite));

            // Check state before making the direct assignments
            assertNames(roles.realmLevel().listAll(), "realm-composite");
            assertNames(roles.realmLevel().listAvailable(), "realm-child", "admin", "offline_access",
                    Constants.AUTHZ_UMA_AUTHORIZATION, "user", "customer-user-premium", "realm-composite-role",
                    "sample-realm-role", "attribute-role", Constants.DEFAULT_ROLES_ROLE_PREFIX + "-test");
            assertNames(roles.realmLevel().listEffective(), "realm-composite", "realm-child");

            assertNames(roles.clientLevel(clientId).listAll(), "client-composite");
            assertNames(roles.clientLevel(clientId).listAvailable(), "client-child");
            assertNames(roles.clientLevel(clientId).listEffective(), "client-composite", "client-child");

            // Make direct assignments for roles which are already indirectly assigned
            roles.realmLevel().add(Collections.singletonList(realm.roles().get("realm-child").toRepresentation()));
            RoleRepresentation clientChild =
                    realm.clients().get(clientId).roles().get("client-child").toRepresentation();
            roles.clientLevel(clientId).add(Collections.singletonList(clientChild));

            // List realm roles
            assertNames(roles.realmLevel().listAll(), "realm-composite", "realm-child");
            assertNames(roles.realmLevel().listAvailable(), "admin", "offline_access",
                    Constants.AUTHZ_UMA_AUTHORIZATION, "user", "customer-user-premium", "realm-composite-role",
                    "sample-realm-role", "attribute-role", Constants.DEFAULT_ROLES_ROLE_PREFIX + "-test");
            assertNames(roles.realmLevel().listEffective(), "realm-composite", "realm-child");

            // List client roles
            assertNames(roles.clientLevel(clientId).listAll(), "client-composite", "client-child");
            assertNames(roles.clientLevel(clientId).listAvailable());
            assertNames(roles.clientLevel(clientId).listEffective(), "client-composite", "client-child");

            // Get mapping representation
            MappingsRepresentation all = roles.getAll();
            assertNames(all.getRealmMappings(), "realm-composite", "realm-child");
            assertEquals(1, all.getClientMappings().size());
            assertNames(all.getClientMappings().get("myclient").getMappings(), "client-composite", "client-child");
        }
    }

    /**
     * Verifies that the user does not have access to Keycloak Admin endpoint when role is not
     * assigned to that user.
     * @link https://issues.jboss.org/browse/KEYCLOAK-2964
     */
    @Test
    public void noAdminEndpointAccessWhenNoRoleAssigned() {
        String userName = "user-" + UUID.randomUUID();
        final String realmName = "master";
        String userId = createUser(realmName, userName, "pwd");

        try (Keycloak userClient = AdminClientUtil.createAdminClient(true, realmName, userName, "pwd", Constants.ADMIN_CLI_CLIENT_ID, null)) {
            userClient.realms().findAll();  // Any admin operation will do
            fail();
        }
        catch (ClientErrorException e) {
            assertTrue(e.getMessage().contains(String.valueOf(Status.FORBIDDEN.getStatusCode())));
        }
    }

    /**
     * Verifies that the role assigned to a user is correctly handled by Keycloak Admin endpoint.
     * @link https://issues.jboss.org/browse/KEYCLOAK-2964
     */
    @Test
    public void adminEndpointAccessibleWhenAdminRoleAssignedToUser() {
        String userName = "user-" + UUID.randomUUID();

        final String realmName = "master";
        RealmResource realm = adminClient.realms().realm(realmName);
        RoleRepresentation adminRole = realm.roles().get("admin").toRepresentation();
        assertThat(adminRole, notNullValue());
        assertThat(adminRole.getId(), notNullValue());

        String userId = createUser(realmName, userName, "pwd");
        assertThat(userId, notNullValue());

        RoleMappingResource mappings = realm.users().get(userId).roles();
        mappings.realmLevel().add(Collections.singletonList(adminRole));


        try (Keycloak userClient = AdminClientUtil.createAdminClient(true, realmName, userName, "pwd", Constants.ADMIN_CLI_CLIENT_ID, null)) {
            assertThat(userClient.realms().findAll(),  // Any admin operation will do
                    not(empty()));
        }
    }

    /**
     * Verifies that the role assigned to a user's group is correctly handled by Keycloak Admin endpoint.
     * @link https://issues.jboss.org/browse/KEYCLOAK-2964
     */
    @Test
    public void adminEndpointAccessibleWhenAdminRoleAssignedToGroup() {
        String userName = "user-" + UUID.randomUUID();
        String groupName = "group-" + UUID.randomUUID();

        final String realmName = "master";
        RealmResource realm = adminClient.realms().realm(realmName);
        RoleRepresentation adminRole = realm.roles().get("admin").toRepresentation();
        assertThat(adminRole, notNullValue());
        assertThat(adminRole.getId(), notNullValue());

        String userId = createUser(realmName, userName, "pwd");
        GroupRepresentation group = GroupBuilder.create().name(groupName).build();
        try (Response response = realm.groups().add(group)) {
            String groupId = ApiUtil.getCreatedId(response);

            RoleMappingResource mappings = realm.groups().group(groupId).roles();
            mappings.realmLevel().add(Collections.singletonList(adminRole));

            realm.users().get(userId).joinGroup(groupId);
        }

        try (Keycloak userClient = AdminClientUtil.createAdminClient(true, realmName, userName, "pwd", Constants.ADMIN_CLI_CLIENT_ID, null)) {
            assertThat(userClient.realms().findAll(),  // Any admin operation will do
                    not(empty()));
        }
    }

    /**
     * Groups search with query returns unwanted groups
     * @link https://issues.redhat.com/browse/KEYCLOAK-18380
     */
    @Test
    public void searchForGroupsShouldOnlyReturnMatchingElementsOrIntermediatePaths() {

        /*
         * /g1/g1.1-gugu
         * /g1/g1.2-test1234
         * /g2-test1234
         * /g3/g3.1-test1234/g3.1.1
         */
        String needle = "test1234";
        GroupRepresentation g1 = GroupBuilder.create().name("g1").build();
        GroupRepresentation g1_1 = GroupBuilder.create().name("g1.1-bubu").build();
        GroupRepresentation g1_2 = GroupBuilder.create().name("g1.2-" + needle).build();
        GroupRepresentation g2 = GroupBuilder.create().name("g2-" + needle).build();
        GroupRepresentation g3 = GroupBuilder.create().name("g3").build();
        GroupRepresentation g3_1 = GroupBuilder.create().name("g3.1-" + needle).build();
        GroupRepresentation g3_1_1 = GroupBuilder.create().name("g3.1.1").build();

        String realmName = "test";
        RealmResource realm = adminClient.realms().realm(realmName);

        createGroup(realm, g1);
        createGroup(realm, g2);
        createGroup(realm, g3);
        addSubGroup(realm, g1, g1_1);
        addSubGroup(realm, g1, g1_2);
        addSubGroup(realm, g3, g3_1);
        addSubGroup(realm, g3_1, g3_1_1);

        try {
            // we search for "test1234" and expect only /g1/g1.2-test1234, /g2-test1234 and /g3/g3.1-test1234 as a result
            List<GroupRepresentation> result = realm.groups().groups(needle, 0, 100);

            assertEquals(3, result.size());
            assertEquals("g1", result.get(0).getName());
            assertEquals(1, result.get(0).getSubGroups().size());
            assertEquals("g1.2-" + needle, result.get(0).getSubGroups().get(0).getName());
            assertEquals("g2-" + needle, result.get(1).getName());
            assertEquals("g3", result.get(2).getName());
            assertEquals(1, result.get(2).getSubGroups().size());
            assertEquals("g3.1-" + needle, result.get(2).getSubGroups().get(0).getName());
        } finally {
            if (g1.getId() != null) {
                realm.groups().group(g1.getId()).remove();
            }

            if (g2.getId() != null) {
                realm.groups().group(g2.getId()).remove();
            }

            if (g3.getId() != null) {
                realm.groups().group(g3.getId()).remove();
            }
        }
    }

    /**
     * Verifies that the role assigned to a user's group is correctly handled by Keycloak Admin endpoint.
     * @link https://issues.jboss.org/browse/KEYCLOAK-2964
     */
    @Test
    public void adminEndpointAccessibleWhenAdminRoleAssignedToGroupAfterUserJoinedIt() {
        String userName = "user-" + UUID.randomUUID();
        String groupName = "group-" + UUID.randomUUID();

        final String realmName = "master";
        RealmResource realm = adminClient.realms().realm(realmName);
        RoleRepresentation adminRole = realm.roles().get("admin").toRepresentation();
        assertThat(adminRole, notNullValue());
        assertThat(adminRole.getId(), notNullValue());

        String userId = createUser(realmName, userName, "pwd");
        GroupRepresentation group = GroupBuilder.create().name(groupName).build();
        try (Response response = realm.groups().add(group)) {
            String groupId = ApiUtil.getCreatedId(response);

            realm.users().get(userId).joinGroup(groupId);

            RoleMappingResource mappings = realm.groups().group(groupId).roles();

            mappings.realmLevel().add(Collections.singletonList(adminRole));
        }

        try (Keycloak userClient = AdminClientUtil.createAdminClient(true, realmName, userName, "pwd", Constants.ADMIN_CLI_CLIENT_ID, null)) {
            assertThat(userClient.realms().findAll(),  // Any admin operation will do
                    not(empty()));
        }
    }

    @Test
    public void defaultMaxResults() {
        GroupsResource groups = adminClient.realms().realm("test").groups();
        try (Response response = groups.add(GroupBuilder.create().name("test").build())) {
            String groupId = ApiUtil.getCreatedId(response);

            GroupResource group = groups.group(groupId);

            UsersResource users = adminClient.realms().realm("test").users();

            for (int i = 0; i < 110; i++) {
                try (Response r = users.create(UserBuilder.create().username("test-" + i).build())) {
                    users.get(ApiUtil.getCreatedId(r)).joinGroup(groupId);
                }
            }

            assertEquals(100, group.members(null, null).size());
            assertEquals(100, group.members().size());
            assertEquals(105, group.members(0, 105).size());
            assertEquals(110, group.members(0, 1000).size());
            assertEquals(110, group.members(-1, -2).size());
        }
    }

    @Test
    public void getGroupsWithFullRepresentation() {
        RealmResource realm = adminClient.realms().realm("test");
        GroupsResource groupsResource = adminClient.realms().realm("test").groups();

        GroupRepresentation group = new GroupRepresentation();
        group.setName("groupWithAttribute");

        Map<String, List<String>> attributes = new HashMap<String, List<String>>();
        attributes.put("attribute1", Arrays.asList("attribute1","attribute2"));
		group.setAttributes(attributes);
        group = createGroup(realm, group);

        List<GroupRepresentation> groups = groupsResource.groups("groupWithAttribute", 0, 20, false);

        assertFalse(groups.isEmpty());
        assertTrue(groups.get(0).getAttributes().containsKey("attribute1"));
    }

    @Test
    public void searchGroupsByNameContaining() {
        RealmResource realm = adminClient.realms().realm("test");
        try(Creator<GroupResource> g = Creator.create(realm, GroupBuilder.create().name("group-name-1").build());
            Creator<GroupResource> g1 = Creator.create(realm, GroupBuilder.create().name("group-name-2").build())) {
            GroupsResource groupsResource = adminClient.realms().realm("test").groups();
            List<GroupRepresentation> groups = groupsResource.groups("group-name", false, 0, 20, false);
            assertThat(groups, hasSize(2));
        }
    }

    @Test
    public void searchGroupsByNameExactSuccess() {
        RealmResource realm = adminClient.realms().realm("test");
        try(Creator<GroupResource> g = Creator.create(realm, GroupBuilder.create().name("group-name-1").build());
            Creator<GroupResource> g1 = Creator.create(realm, GroupBuilder.create().name("group-name-2").build())) {
            GroupsResource groupsResource = adminClient.realms().realm("test").groups();
            List<GroupRepresentation> groups = groupsResource.groups("group-name-1", true, 0, 20, false);
            assertThat(groups, hasSize(1));
        }
    }

    @Test
    public void searchGroupsByNameExactFailure() {
        RealmResource realm = adminClient.realms().realm("test");
        try(Creator<GroupResource> g = Creator.create(realm, GroupBuilder.create().name("group-name-1").build());
            Creator<GroupResource> g1 = Creator.create(realm, GroupBuilder.create().name("group-name-2").build())) {
            GroupsResource groupsResource = adminClient.realms().realm("test").groups();
            List<GroupRepresentation> groups = groupsResource.groups("group-name", true, 0, 20, false);
            assertThat(groups, empty());
        }
    }

    @Test
    public void getGroupsWithBriefRepresentation() {
        RealmResource realm = adminClient.realms().realm("test");
        GroupsResource groupsResource = adminClient.realms().realm("test").groups();

        GroupRepresentation group = new GroupRepresentation();
        group.setName("groupWithAttribute");

        Map<String, List<String>> attributes = new HashMap<String, List<String>>();
        attributes.put("attribute1", Arrays.asList("attribute1","attribute2"));
		group.setAttributes(attributes);
        group = createGroup(realm, group);

        List<GroupRepresentation> groups = groupsResource.groups("groupWithAttribute", 0, 20);

        assertFalse(groups.isEmpty());
        assertNull(groups.get(0).getAttributes());
    }

    @Test
    public void getSubGroups() throws Exception {
        RealmResource realm = adminClient.realms().realm("test");

        GroupRepresentation parent = new GroupRepresentation();
        parent.setName("parent");
        parent = createGroup(realm, parent);

        GroupRepresentation child = new GroupRepresentation();
        child.setName("child");
        Map<String, List<String>> attributes = new HashMap<String, List<String>>();
        attributes.put("attribute1", Arrays.asList("value1", "value2"));
        child.setAttributes(attributes);

        addSubGroup(realm, parent, child);

        // Check brief and full retrieval of subgroups of parent
        boolean briefRepresentation = true;
        assertNull(realm.groups().group(parent.getId()).getSubGroups(null, null, briefRepresentation).get(0).getAttributes());

        briefRepresentation = false;
        assertThat(realm.groups().group(parent.getId()).getSubGroups(null, null, briefRepresentation).get(0).getAttributes().get("attribute1"), containsInAnyOrder("value1", "value2"));
    }

    @Test
    public void searchAndCountGroups() throws Exception {
        String firstGroupId = "";

        RealmResource realm = adminClient.realms().realm("test");

        // Clean up all test groups
        for (GroupRepresentation group : realm.groups().groups()) {
            GroupResource resource = realm.groups().group(group.getId());
            resource.remove();
        }

        // Add 20 new groups with known names
        for (int i=0;i<20;i++) {
            GroupRepresentation group = new GroupRepresentation();
            group.setName("group"+i);
            group = createGroup(realm, group);
            if(i== 0) {
                firstGroupId = group.getId();
            }
        }

        // Get groups by search and pagination
        List<GroupRepresentation> allGroups = realm.groups().groups();
        assertEquals(20, allGroups.size());

        List<GroupRepresentation> slice = realm.groups().groups(0, 7);
        assertEquals(7, slice.size());

        slice = realm.groups().groups(null, 7);
        assertEquals(7, slice.size());

        slice = realm.groups().groups(10, null);
        assertEquals(10, slice.size());

        slice = realm.groups().groups(5, 7);
        assertEquals(7, slice.size());

        slice = realm.groups().groups(15, 7);
        assertEquals(5, slice.size());

        List<GroupRepresentation> search = realm.groups().groups("group1",0,20);
        assertEquals(11, search.size());
        for(GroupRepresentation group : search) {
            assertTrue(group.getName().contains("group1"));
        }

        List<GroupRepresentation> noResultSearch = realm.groups().groups("abcd",0,20);
        assertEquals(0, noResultSearch.size());

        // Count
        assertEquals(Long.valueOf(allGroups.size()), realm.groups().count().get("count"));
        assertEquals(Long.valueOf(search.size()), realm.groups().count("group1").get("count"));
        assertEquals(Long.valueOf(noResultSearch.size()), realm.groups().count("abcd").get("count"));

        // Add a subgroup for onlyTopLevel flag testing
        GroupRepresentation level2Group = new GroupRepresentation();
        level2Group.setName("group1111");
        Response response = realm.groups().group(firstGroupId).subGroup(level2Group);
        response.close();

        assertEquals(Long.valueOf(allGroups.size()), realm.groups().count(true).get("count"));
        assertEquals(Long.valueOf(allGroups.size() + 1), realm.groups().count(false).get("count"));
        //add another subgroup
        GroupRepresentation level2Group2 = new GroupRepresentation();
        level2Group2.setName("group111111");
        realm.groups().group(firstGroupId).subGroup(level2Group2);
        //search and count for group with string group11 -> return 2 top level group, group11 and group0 having subgroups group1111 and group111111
        search = realm.groups().groups("group11",0,10);
        assertEquals(2, search.size());
        GroupRepresentation group0 = search.stream().filter(group -> "group0".equals(group.getName())).findAny().orElseGet(null);
        assertNotNull(group0);
        assertEquals(2,group0.getSubGroups().size());
        assertThat(group0.getSubGroups().stream().map(GroupRepresentation::getName).collect(Collectors.toList()), containsInAnyOrder("group1111", "group111111"));
        assertEquals(countLeafGroups(search), realm.groups().count("group11").get("count"));
    }

    private Long countLeafGroups(List<GroupRepresentation> search) {
        long counter = 0;
        for(GroupRepresentation group : search) {
            if(group.getSubGroups().isEmpty()) {
                counter += 1;
                continue;
            }
            counter += countLeafGroups(group.getSubGroups());
        }
        return counter;
    }

    @Test
    public void orderGroupsByName() throws Exception {
        RealmResource realm = this.adminClient.realms().realm("test");

        // Clean up all test groups
        for (GroupRepresentation group : realm.groups().groups()) {
            GroupResource resource = realm.groups().group(group.getId());
            resource.remove();
        }

        // Create two pages worth of groups in a random order
        List<GroupRepresentation> testGroups = new ArrayList<>();
        for (int i = 0; i < 40; i++) {
            GroupRepresentation group = new GroupRepresentation();
            group.setName("group" + i);
            testGroups.add(group);
        }

        Collections.shuffle(testGroups);

        for (GroupRepresentation group : testGroups) {
            group = createGroup(realm, group);
        }

        // Groups should be ordered by name
        Comparator<GroupRepresentation> compareByName = Comparator.comparing(GroupRepresentation::getName);

        // Assert that all groups are returned in order
        List<GroupRepresentation> allGroups = realm.groups().groups(0, 100);
        assertEquals(40, allGroups.size());
        assertTrue(Comparators.isInStrictOrder(allGroups, compareByName));

        // Assert that pagination results are returned in order
        List<GroupRepresentation> firstPage = realm.groups().groups(0, 20);
        assertEquals(20, firstPage.size());
        assertTrue(Comparators.isInStrictOrder(firstPage, compareByName));

        List<GroupRepresentation> secondPage = realm.groups().groups(20, 20);
        assertEquals(20, secondPage.size());
        assertTrue(Comparators.isInStrictOrder(secondPage, compareByName));

        // Check that the ordering of groups across multiple pages is correct
        // Since the individual pages are ordered it is sufficient to compare
        // every group from the first page to the first group of the second page
        GroupRepresentation firstGroupOnSecondPage = secondPage.get(0);
        for (GroupRepresentation firstPageGroup : firstPage) {
            int comparisonResult = compareByName.compare(firstPageGroup, firstGroupOnSecondPage);
            assertTrue(comparisonResult < 0);
        }
    }

    @Test
    public void removeAllGroupAttributes() {
        final var realm = adminClient.realms().realm("test");
        final var groupName = "remove-all-attributes-group";

        final Map<String, List<String>> initialAttributes = Map.of("test-key", List.of("test-val"));
        final var groupToCreate =
                GroupBuilder.create().name(groupName).attributes(initialAttributes).build();
        final var groupsResource = realm.groups();
        try (final Response response = groupsResource.add(groupToCreate)) {
            final var groupId = ApiUtil.getCreatedId(response);

            final var groupResource = groupsResource.group(groupId);
            final var createdGroup = groupResource.toRepresentation();
            assertThat(createdGroup.getAttributes(), equalTo(initialAttributes));

            final var groupToUpdate =
                    GroupBuilder.create().name(groupName).attributes(Collections.emptyMap()).build();
            groupResource.update(groupToUpdate);

            final var updatedGroup = groupResource.toRepresentation();
            assertThat(updatedGroup.getAttributes(), anEmptyMap());
        }
    }

    @Test
    public void testBriefRepresentationOnGroupMembers() {
        RealmResource realm = adminClient.realms().realm("test");
        String groupName = "brief-grouptest-group";
        String userName = "brief-grouptest-user";

        // enable user profile unmanaged attributes
        UserProfileResource upResource = realm.users().userProfile();
        UPConfig cfg = upResource.getConfiguration();
        cfg.setUnmanagedAttributePolicy(UPConfig.UnmanagedAttributePolicy.ENABLED);
        upResource.update(cfg);

        GroupsResource groups = realm.groups();
        try (Response response = groups.add(GroupBuilder.create().name(groupName).build())) {
            String groupId = ApiUtil.getCreatedId(response);

            GroupResource group = groups.group(groupId);

            UsersResource users = realm.users();

            UserRepresentation userRepresentation = UserBuilder.create()
                    .username(userName)
                    .addAttribute("myattribute", "myvalue")
                    .build();

            Response r = users.create(userRepresentation);
            UserResource user = users.get(ApiUtil.getCreatedId(r));
            user.joinGroup(groupId);

            UserRepresentation defaultRepresentation = group.members(null, null).get(0);
            UserRepresentation fullRepresentation = group.members(null, null, false).get(0);
            UserRepresentation briefRepresentation = group.members(null, null, true).get(0);

            assertEquals(fullRepresentation.getAttributes(), userRepresentation.getAttributes(), "full group member representation includes attributes");
            assertEquals(defaultRepresentation.getAttributes(), userRepresentation.getAttributes(), "default group member representation is full");
            assertNull(briefRepresentation.getAttributes(), "brief group member representation omits attributes");

            group.remove();
            user.remove();
        } finally {
            cfg.setUnmanagedAttributePolicy(null);
            upResource.update(cfg);
        }
    }

    /**
     * Verifies that the group search works the same across group provider implementations for hierarchies
     * @link https://issues.jboss.org/browse/KEYCLOAK-18390
     */
    @Test
    public void searchGroupsOnGroupHierarchies() throws Exception {
        final RealmResource realm = this.adminClient.realms().realm("test");

        final String searchFor = UUID.randomUUID().toString();

        final GroupRepresentation g1 = new GroupRepresentation();
        g1.setName("g1");
        final GroupRepresentation g1_1 = new GroupRepresentation();
        g1_1.setName("g1.1-" + searchFor);

        createGroup(realm, g1);
        addSubGroup(realm, g1, g1_1);

        final GroupRepresentation expectedRootGroup = realm.groups().group(g1.getId()).toRepresentation();
        final GroupRepresentation expectedChildGroup = realm.groups().group(g1_1.getId()).toRepresentation();

        final List<GroupRepresentation> searchResultGroups = realm.groups().groups(searchFor, 0, 10);

        assertFalse(searchResultGroups.isEmpty());
        assertEquals(expectedRootGroup.getId(), searchResultGroups.get(0).getId());
        assertEquals(expectedRootGroup.getName(), searchResultGroups.get(0).getName());

        List<GroupRepresentation> searchResultSubGroups = searchResultGroups.get(0).getSubGroups();
        assertEquals(expectedChildGroup.getId(), searchResultSubGroups.get(0).getId());
        assertEquals(expectedChildGroup.getName(), searchResultSubGroups.get(0).getName());

        searchResultSubGroups.remove(0);
        assertTrue(searchResultSubGroups.isEmpty());
        searchResultGroups.remove(0);
        assertTrue(searchResultGroups.isEmpty());
    }

    public void testParentAndChildGroup(String parentName, String childName) {
        RealmResource realm = adminClient.realms().realm("test");
        GroupRepresentation parentGroup = new GroupRepresentation();
        parentGroup.setName(parentName);
        parentGroup = createGroup(realm, parentGroup);
        GroupRepresentation childGroup = new GroupRepresentation();
        childGroup.setName(childName);
        try (Response response = realm.groups().group(parentGroup.getId()).subGroup(childGroup)) {
            assertEquals(201, response.getStatus()); // created status
            childGroup.setId(ApiUtil.getCreatedId(response));
        }

        List<GroupRepresentation> groupsFound = realm.groups().groups(parentGroup.getName(), true, 0, 1, true);
        assertEquals(1, groupsFound.size());
        assertEquals(parentGroup.getId(), groupsFound.iterator().next().getId());
        assertEquals(0, groupsFound.iterator().next().getSubGroups().size());
        parentGroup = groupsFound.iterator().next();
        assertEquals(KeycloakModelUtils.buildGroupPath(false, parentName),
                parentGroup.getPath());

        groupsFound = realm.groups().groups(childGroup.getName(), true, 0, 1, true);
        assertEquals(1, groupsFound.size());
        assertEquals(parentGroup.getId(), groupsFound.iterator().next().getId());
        assertEquals(1, groupsFound.iterator().next().getSubGroups().size());
        assertEquals(childGroup.getId(), groupsFound.iterator().next().getSubGroups().iterator().next().getId());
        childGroup = groupsFound.iterator().next().getSubGroups().iterator().next();
        assertEquals(KeycloakModelUtils.normalizeGroupPath(
                KeycloakModelUtils.buildGroupPath(false, parentName, childName)),
                childGroup.getPath());

        GroupRepresentation groupFound = realm.getGroupByPath(parentGroup.getPath());
        assertNotNull(groupFound);
        assertEquals(parentGroup.getId(), groupFound.getId());
        groupFound = realm.getGroupByPath(childGroup.getPath());
        assertNotNull(groupFound);
        assertEquals(childGroup.getId(), groupFound.getId());

        realm.groups().group(childGroup.getId()).remove();
        realm.groups().group(parentGroup.getId()).remove();
    }

    @Test
    public void testGroupsWithSpaces() {
         testParentAndChildGroup("parent space", "child space");
    }

    @Test
    public void testGroupsWithSlashes() {
         testParentAndChildGroup("parent/slash", "child/slash");
    }

    /**
     * Assert that when you create/move/update a group name, the response is not Http 409 Conflict and the message does not
     * correspond to the returned user-friendly message in such cases
     */
    private void assertSameNameNotAllowed(Response response, String expectedErrorMessage) {
        assertEquals(409, response.getStatus());
        ErrorRepresentation error = response.readEntity(ErrorRepresentation.class);
        assertEquals(expectedErrorMessage, error.getErrorMessage());
    }
}
