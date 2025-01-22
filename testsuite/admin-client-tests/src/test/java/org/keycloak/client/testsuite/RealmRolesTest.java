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

package org.keycloak.client.testsuite;

import jakarta.ws.rs.BadRequestException;
import jakarta.ws.rs.ClientErrorException;
import jakarta.ws.rs.NotFoundException;
import jakarta.ws.rs.core.Response;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.admin.client.resource.RoleResource;
import org.keycloak.admin.client.resource.RolesResource;
import org.keycloak.admin.client.resource.UserResource;
import org.keycloak.client.testsuite.models.Constants;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.representations.idm.GroupRepresentation;
import org.keycloak.representations.idm.RoleRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.keycloak.testsuite.util.ApiUtil;
import org.keycloak.testsuite.util.ClientBuilder;
import org.keycloak.testsuite.util.RoleBuilder;

import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;
import static org.testcontainers.shaded.org.hamcrest.MatcherAssert.assertThat;
import static org.testcontainers.shaded.org.hamcrest.Matchers.hasItem;
import static org.testcontainers.shaded.org.hamcrest.Matchers.empty;
import static org.testcontainers.shaded.org.hamcrest.Matchers.is;
import static org.testcontainers.shaded.org.hamcrest.Matchers.not;
import static org.testcontainers.shaded.org.hamcrest.Matchers.hasSize;
import static org.testcontainers.shaded.org.hamcrest.Matchers.allOf;


/**
 * @author <a href="mailto:sthorger@redhat.com">Stian Thorgersen</a>
 */
public class RealmRolesTest extends AbstractAdminClientTest {


    RoleRepresentation roleA = RoleBuilder.create().name("role-a").description("Role A").attributes(ROLE_A_ATTRIBUTES).build();
    RoleRepresentation roleB = RoleBuilder.create().name("role-b").description("Role B").build();
    RoleRepresentation roleWithUsers = RoleBuilder.create().name("role-with-users").description("Role with users").build();
    RoleRepresentation roleWithoutUsers = RoleBuilder.create().name("role-without-users").description("role-without-users").build();

    RoleRepresentation roleC = RoleBuilder.create().name("role-c").description("Role C").build();

    UserRepresentation userRoleMember;
    GroupRepresentation groupMember;

    private static final Map<String, List<String>> ROLE_A_ATTRIBUTES =
            Collections.singletonMap("role-a-attr-key1", Collections.singletonList("role-a-attr-val1"));

    private RolesResource resource;

    private Map<String, String> ids = new HashMap<>();
    private String clientUuid;

    @BeforeEach
    public void before() {
        roleA = createRealmRole(roleA);
        roleB = createRealmRole(roleB);
        roleWithUsers = createRealmRole(roleWithUsers);
        roleWithoutUsers = createRealmRole(roleWithoutUsers);

        ClientRepresentation clientRep = ClientBuilder.create().clientId("client-a").build();
        try (Response response = adminClient.realm(REALM_NAME).clients().create(clientRep)) {
            clientUuid = ApiUtil.getCreatedId(response);
        }

        adminClient.realm(REALM_NAME).clients().get(clientUuid).roles().create(roleC);
        roleC = adminClient.realm(REALM_NAME).clients().get(clientUuid).roles().get(roleC.getName()).toRepresentation();

        for (RoleRepresentation r : adminClient.realm(REALM_NAME).roles().list()) {
            ids.put(r.getName(), r.getId());
        }

        for (RoleRepresentation r : adminClient.realm(REALM_NAME).clients().get(clientUuid).roles().list()) {
            ids.put(r.getName(), r.getId());
        }

        userRoleMember = new UserRepresentation();
        userRoleMember.setUsername("test-role-member");
        userRoleMember.setEmail("test-role-member@test-role-member.com");
        userRoleMember.setRequiredActions(Collections.<String>emptyList());
        userRoleMember.setEnabled(true);
        adminClient.realm(REALM_NAME).users().create(userRoleMember);
        userRoleMember = adminClient.realms().realm(REALM_NAME).users().search(userRoleMember.getUsername()).get(0);
        groupMember = new GroupRepresentation();
        groupMember.setName("test-role-group");
        groupMember.setPath("/test-role-group");
        adminClient.realm(REALM_NAME).groups().add(groupMember);
        groupMember = adminClient.realm(REALM_NAME).groups().groups().get(0);
        resource = adminClient.realm(REALM_NAME).roles();
    }

    @AfterEach
    public void after() {
        try {
            realm.clients().get(clientUuid).remove();
            realm.rolesById().deleteRole(roleA.getId());
            realm.rolesById().deleteRole(roleB.getId());
            realm.rolesById().deleteRole(roleWithUsers.getId());
            realm.rolesById().deleteRole(roleWithoutUsers.getId());

            String groupId = adminClient.realm(REALM_NAME).groups().groups().get(0).getId();

            adminClient.realm(REALM_NAME).groups().group(groupId).remove();
            adminClient.realms().realm(REALM_NAME).users().get(userRoleMember.getId()).remove();

        }
        catch (Exception e) {

        }
    }

    private RoleRepresentation makeRole(String name) {
        RoleRepresentation role = new RoleRepresentation();
        role.setName(name);
        return role;
    }

    @Test
    public void getRole() {
        RoleRepresentation role = resource.get("role-a").toRepresentation();
        assertNotNull(role);
        assertEquals("role-a", role.getName());
        assertEquals("Role A", role.getDescription());
        assertEquals(ROLE_A_ATTRIBUTES, role.getAttributes());
        assertFalse(role.isComposite());
    }

    @Test
    public void createRoleWithSameName() {
        try {
            resource.create(RoleBuilder.create().name("role-a").build());
            fail();
        }
        catch (ClientErrorException e) {
        }
    }

    @Test
    public void updateRole() {
        RoleRepresentation roleOrig = resource.get("role-a").toRepresentation();
        RoleRepresentation role = resource.get("role-a").toRepresentation();

        role.setName("role-a-new");
        role.setDescription("Role A New");
        Map<String, List<String>> newAttributes = Collections.singletonMap("attrKeyNew", Collections.singletonList("attrValueNew"));
        role.setAttributes(newAttributes);

        resource.get("role-a").update(role);
        role = resource.get("role-a-new").toRepresentation();

        assertNotNull(role);
        assertEquals("role-a-new", role.getName());
        assertEquals("Role A New", role.getDescription());
        assertEquals(newAttributes, role.getAttributes());
        assertFalse(role.isComposite());

        resource.get("role-a-new").update(roleOrig);
    }

    @Test
    public void deleteRole() {
        assertNotNull(resource.get("role-a"));
        resource.deleteRole("role-a");
        try {
            resource.get("role-a").toRepresentation();
            fail("Expected 404");
        } catch (NotFoundException e) {
            // expected
        }
    }

    @Test
    public void composites() {
        assertFalse(resource.get("role-a").toRepresentation().isComposite());
        assertEquals(0, resource.get("role-a").getRoleComposites().size());

        List<RoleRepresentation> l = new LinkedList<>();
        l.add(RoleBuilder.create().id(ids.get("role-b")).build());
        l.add(RoleBuilder.create().id(ids.get("role-c")).build());
        resource.get("role-a").addComposites(l);

        Set<RoleRepresentation> composites = resource.get("role-a").getRoleComposites();

        assertTrue(resource.get("role-a").toRepresentation().isComposite());
        Assert.assertNames(composites, "role-b", "role-c");

        Set<RoleRepresentation> realmComposites = resource.get("role-a").getRealmRoleComposites();
        Assert.assertNames(realmComposites, "role-b");

        Set<RoleRepresentation> clientComposites = resource.get("role-a").getClientRoleComposites(clientUuid);
        Assert.assertNames(clientComposites, "role-c");

        resource.get("role-a").deleteComposites(l);
        assertFalse(resource.get("role-a").toRepresentation().isComposite());
        assertEquals(0, resource.get("role-a").getRoleComposites().size());
    }

    /**
     * KEYCLOAK-2035 Verifies that Users assigned to Role are being properly retrieved as members in API endpoint for role membership
     */
    @Test
    public void testUsersInRole() {
        RoleResource role = resource.get("role-with-users");

        List<UserRepresentation> users = adminClient.realm(REALM_NAME).users().search("test-role-member");
        assertEquals(1, users.size());
        UserResource user = adminClient.realm(REALM_NAME).users().get(users.get(0).getId());
        UserRepresentation userRep = user.toRepresentation();

        RoleResource roleResource = adminClient.realm(REALM_NAME).roles().get(role.toRepresentation().getName());
        List<RoleRepresentation> rolesToAdd = new LinkedList<>();
        rolesToAdd.add(roleResource.toRepresentation());
        adminClient.realm(REALM_NAME).users().get(userRep.getId()).roles().realmLevel().add(rolesToAdd);

        roleResource = adminClient.realm(REALM_NAME).roles().get(role.toRepresentation().getName());
        assertEquals(Collections.singletonList("test-role-member"), extractUsernames(roleResource.getUserMembers()));
    }

    private static List<String> extractUsernames(Collection<UserRepresentation> users) {
        return users.stream().map(UserRepresentation::getUsername).collect(Collectors.toList());
    }

    /**
     * KEYCLOAK-2035  Verifies that Role with no users assigned is being properly retrieved without members in API endpoint for role membership
     */
    @Test
    public void testUsersNotInRole() {
        RoleResource role = resource.get("role-without-users");

        role = adminClient.realm(REALM_NAME).roles().get(role.toRepresentation().getName());
        assertEquals(role.getUserMembers(), Collections.emptyList());
    }


    /**
     * KEYCLOAK-4978 Verifies that Groups assigned to Role are being properly retrieved as members in API endpoint for role membership
     */
    @Test
    public void testGroupsInRole() {
        RoleResource role = resource.get("role-with-users");

        List<GroupRepresentation> groups = adminClient.realm(REALM_NAME).groups().groups();
        GroupRepresentation groupRep = groups.stream().filter(g -> g.getPath().equals("/test-role-group")).findFirst().get();

        RoleResource roleResource = adminClient.realm(REALM_NAME).roles().get(role.toRepresentation().getName());
        List<RoleRepresentation> rolesToAdd = new LinkedList<>();
        rolesToAdd.add(roleResource.toRepresentation());
        adminClient.realm(REALM_NAME).groups().group(groupRep.getId()).roles().realmLevel().add(rolesToAdd);

        roleResource = adminClient.realm(REALM_NAME).roles().get(role.toRepresentation().getName());

        Set<GroupRepresentation> groupsInRole = roleResource.getRoleGroupMembers();
        assertTrue(groupsInRole.stream().filter(g -> g.getPath().equals("/test-role-group")).findFirst().isPresent());
    }

    /**
     * KEYCLOAK-4978  Verifies that Role with no users assigned is being properly retrieved without groups in API endpoint for role membership
     */
    @Test
    public void testGroupsNotInRole() {
        RoleResource role = resource.get("role-without-users");

        role = adminClient.realm(REALM_NAME).roles().get(role.toRepresentation().getName());

        Set<GroupRepresentation> groupsInRole = role.getRoleGroupMembers();
        assertTrue(groupsInRole.isEmpty());
    }

    /**
     * KEYCLOAK-2035 Verifies that Role Membership is ok after user removal
     */
    @Test
    public void roleMembershipAfterUserRemoval() {
        RoleResource role = resource.get("role-with-users");

        List<UserRepresentation> users = adminClient.realm(REALM_NAME).users().search("test-role-member", null, null, null, null, null);
        assertEquals(1, users.size());
        UserResource user = adminClient.realm(REALM_NAME).users().get(users.get(0).getId());
        UserRepresentation userRep = user.toRepresentation();

        RoleResource roleResource = adminClient.realm(REALM_NAME).roles().get(role.toRepresentation().getName());
        List<RoleRepresentation> rolesToAdd = new LinkedList<>();
        rolesToAdd.add(roleResource.toRepresentation());
        adminClient.realm(REALM_NAME).users().get(userRep.getId()).roles().realmLevel().add(rolesToAdd);

        roleResource = adminClient.realm(REALM_NAME).roles().get(role.toRepresentation().getName());
        assertEquals(Collections.singletonList("test-role-member"), extractUsernames(roleResource.getUserMembers()));

        adminClient.realm(REALM_NAME).users().delete(userRep.getId());
        assertEquals(role.getUserMembers(), Collections.emptyList());
    }

    @Test
    public void testRoleMembershipWithPagination() {
        RoleResource role = resource.get("role-with-users");

        // Add a second user
        UserRepresentation userRep2 = new UserRepresentation();
        userRep2.setUsername("test-role-member2");
        userRep2.setEmail("test-role-member2@test-role-member.com");
        userRep2.setRequiredActions(Collections.<String>emptyList());
        userRep2.setEnabled(true);
        adminClient.realm(REALM_NAME).users().create(userRep2);

        List<UserRepresentation> users = adminClient.realm(REALM_NAME).users().search("test-role-member", null, null, null, null, null);
        assertThat(users, hasSize(2));
        for (UserRepresentation userRepFromList : users) {
            UserResource user = adminClient.realm(REALM_NAME).users().get(userRepFromList.getId());
            UserRepresentation userRep = user.toRepresentation();

            RoleResource roleResource = adminClient.realm(REALM_NAME).roles().get(role.toRepresentation().getName());
            List<RoleRepresentation> rolesToAdd = new LinkedList<>();
            rolesToAdd.add(roleResource.toRepresentation());
            adminClient.realm(REALM_NAME).users().get(userRep.getId()).roles().realmLevel().add(rolesToAdd);
        }

        RoleResource roleResource = adminClient.realm(REALM_NAME).roles().get(role.toRepresentation().getName());

        List<UserRepresentation> roleUserMembers = roleResource.getUserMembers(0, 1);
        assertEquals(Collections.singletonList("test-role-member"), extractUsernames(roleUserMembers));
        Assert.assertNotNull(roleUserMembers.get(0).getNotBefore(), "Not in full representation");

        roleUserMembers = roleResource.getUserMembers(true, 1, 1);
        assertThat(roleUserMembers, hasSize(1));
        assertEquals(Collections.singletonList("test-role-member2"), extractUsernames(roleUserMembers));

        roleUserMembers = roleResource.getUserMembers(true, 2, 1);
        assertEquals(roleUserMembers, Collections.emptyList());
    }

    // issue #9587
    @Test
    public void testSearchForRealmRoles() {
        resource.list("role-", true).stream().forEach(role -> assertThat("There is client role '" + role.getName() + "' among realm roles.", role.getClientRole(), is(false)));
    }

    @Test
    public void testSearchForRoles() {

        for(int i = 0; i<15; i++) {
            String roleName = "testrole"+i;
            RoleRepresentation role = makeRole(roleName);
            resource.create(role);
        }

        String roleNameA = "abcdefg";
        RoleRepresentation roleA = makeRole(roleNameA);
        resource.create(roleA);

        String roleNameB = "defghij";
        RoleRepresentation roleB = makeRole(roleNameB);
        resource.create(roleB);

        List<RoleRepresentation> resultSearch = resource.list("defg", -1, -1);
        assertEquals(2,resultSearch.size());

        List<RoleRepresentation> resultSearch2 = resource.list("testrole", -1, -1);
        assertEquals(15,resultSearch2.size());

        List<RoleRepresentation> resultSearchPagination = resource.list("testrole", 1, 5);
        assertEquals(5,resultSearchPagination.size());
    }

    @Test
    public void testPaginationRoles() {

        for(int i = 0; i<15; i++) {
            String roleName = "role"+i;
            RoleRepresentation role = makeRole(roleName);
            resource.create(role);
        }

        List<RoleRepresentation> resultSearchPagination = resource.list(1, 5);
        assertEquals(5,resultSearchPagination.size());

        List<RoleRepresentation> resultSearchPagination2 = resource.list(5, 5);
        assertEquals(5,resultSearchPagination2.size());

        List<RoleRepresentation> resultSearchPagination3 = resource.list(1, 5);
        assertEquals(5,resultSearchPagination3.size());

        List<RoleRepresentation> resultSearchPaginationIncoherentParams = resource.list(1, null);
        assertTrue(resultSearchPaginationIncoherentParams.size() > 15);
    }

    @Test
    public void testPaginationRolesCache() {

        for(int i = 0; i<5; i++) {
            String roleName = "paginaterole"+i;
            RoleRepresentation role = makeRole(roleName);
            resource.create(role);
        }

        List<RoleRepresentation> resultBeforeAddingRoleToTestCache = resource.list(1, 1000);

        // after a first call which init the cache, we add a new role to see if the result change

        RoleRepresentation role = makeRole("anewrole");
        resource.create(role);

        List<RoleRepresentation> resultafterAddingRoleToTestCache = resource.list(1, 1000);

        assertEquals(resultBeforeAddingRoleToTestCache.size()+1, resultafterAddingRoleToTestCache.size());
    }

    @Test
    public void getRolesWithFullRepresentation() {
        for(int i = 0; i<5; i++) {
            String roleName = "attributesrole"+i;
            RoleRepresentation role = makeRole(roleName);

            Map<String, List<String>> attributes = new HashMap<>();
            attributes.put("attribute1", Arrays.asList("value1","value2"));
            role.setAttributes(attributes);

            resource.create(role);
        }

        List<RoleRepresentation> roles = resource.list("attributesrole", false);
        assertTrue(roles.get(0).getAttributes().containsKey("attribute1"));
    }

    @Test
    public void getRolesWithBriefRepresentation() {
        for(int i = 0; i<5; i++) {
            String roleName = "attributesrolebrief"+i;
            RoleRepresentation role = makeRole(roleName);

            Map<String, List<String>> attributes = new HashMap<>();
            attributes.put("attribute1", Arrays.asList("value1","value2"));
            role.setAttributes(attributes);

            resource.create(role);
        }

        List<RoleRepresentation> roles = resource.list("attributesrolebrief", true);
        assertNull(roles.get(0).getAttributes());
    }

    @Test
    public void testDefaultRoles() {
        RoleResource defaultRole = adminClient.realm(REALM_NAME).roles().get(Constants.DEFAULT_ROLES_ROLE_PREFIX + "-" + REALM_NAME);

        UserRepresentation user = adminClient.realm(REALM_NAME).users().search("test-role-member").get(0);

        UserResource userResource = adminClient.realm(REALM_NAME).users().get(user.getId());
        assertThat(convertRolesToNames(userResource.roles().realmLevel().listAll()), hasItem(Constants.DEFAULT_ROLES_ROLE_PREFIX + "-" + REALM_NAME));
        assertThat(convertRolesToNames(userResource.roles().realmLevel().listEffective()), allOf(
                hasItem(Constants.DEFAULT_ROLES_ROLE_PREFIX + "-" + REALM_NAME),
                hasItem(Constants.OFFLINE_ACCESS_ROLE),
                hasItem(Constants.AUTHZ_UMA_AUTHORIZATION)
        ));

        defaultRole.addComposites(Collections.singletonList(resource.get("role-a").toRepresentation()));

        userResource = adminClient.realm(REALM_NAME).users().get(user.getId());
        assertThat(convertRolesToNames(userResource.roles().realmLevel().listAll()), allOf(
                hasItem(Constants.DEFAULT_ROLES_ROLE_PREFIX + "-" + REALM_NAME),
                not(hasItem("role-a"))
        ));
        assertThat(convertRolesToNames(userResource.roles().realmLevel().listEffective()), allOf(
                hasItem(Constants.DEFAULT_ROLES_ROLE_PREFIX + "-" + REALM_NAME),
                hasItem(Constants.OFFLINE_ACCESS_ROLE),
                hasItem(Constants.AUTHZ_UMA_AUTHORIZATION),
                hasItem("role-a")
        ));

        assertThat(userResource.roles().clientLevel(clientUuid).listAll(), empty());
        assertThat(userResource.roles().clientLevel(clientUuid).listEffective(), empty());

        defaultRole.addComposites(Collections.singletonList(adminClient.realm(REALM_NAME).clients().get(clientUuid).roles().get("role-c").toRepresentation()));

        userResource = adminClient.realm(REALM_NAME).users().get(user.getId());

        assertThat(userResource.roles().clientLevel(clientUuid).listAll(), empty());
        assertThat(convertRolesToNames(userResource.roles().clientLevel(clientUuid).listEffective()),
                hasItem("role-c")
        );
    }

    @Test
    public void testDeleteDefaultRole() {
        try {
            adminClient.realm(REALM_NAME).roles().deleteRole(Constants.DEFAULT_ROLES_ROLE_PREFIX + "-" + REALM_NAME);
            fail();
        }
        catch (BadRequestException e) {
        }

    }

    private List<String> convertRolesToNames(List<RoleRepresentation> roles) {
        return roles.stream().map(RoleRepresentation::getName).collect(Collectors.toList());
    }
}
