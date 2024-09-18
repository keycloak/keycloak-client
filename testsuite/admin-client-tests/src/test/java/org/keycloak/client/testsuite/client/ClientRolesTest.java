/*
 * Copyright 2016 Red Hat Inc. and/or its affiliates and other contributors
 * as indicated by the @author tags. All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */

package org.keycloak.client.testsuite.client;

import jakarta.ws.rs.ClientErrorException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.admin.client.resource.ClientResource;
import org.keycloak.admin.client.resource.RoleByIdResource;
import org.keycloak.admin.client.resource.RoleResource;
import org.keycloak.admin.client.resource.RolesResource;

import org.keycloak.representations.idm.RoleRepresentation;
import org.keycloak.representations.idm.UserRepresentation;

import org.keycloak.testsuite.util.RoleBuilder;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.fail;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.keycloak.client.testsuite.Assert.assertNames;
import static org.testcontainers.shaded.org.hamcrest.MatcherAssert.assertThat;
import static org.testcontainers.shaded.org.hamcrest.Matchers.hasSize;


/**
 * @author Stan Silvert ssilvert@redhat.com (C) 2016 Red Hat Inc.
 */
public class ClientRolesTest extends AbstractClientTest {

    private ClientResource clientRsc;
    private String clientDbId;
    private RolesResource rolesRsc;

    @BeforeEach
    public void init() {
        clientDbId = createOidcClient("roleClient");
        clientRsc = findClientResource("roleClient");
        rolesRsc = clientRsc.roles();
    }

    @AfterEach
    public void tearDown() {
        clientRsc.remove();
    }

    private RoleRepresentation makeRole(String name) {
        RoleRepresentation role = new RoleRepresentation();
        role.setName(name);
        return role;
    }

    private boolean hasRole(RolesResource rolesRsc, String name) {
        for (RoleRepresentation role : rolesRsc.list()) {
            if (role.getName().equals(name)) return true;
        }

        return false;
    }

    @Test
    public void testAddRole() {
        RoleRepresentation role1 = makeRole("role1");
        role1.setDescription("role1-description");
        role1.setAttributes(Collections.singletonMap("role1-attr-key", Collections.singletonList("role1-attr-val")));
        rolesRsc.create(role1);

        RoleRepresentation addedRole = rolesRsc.get(role1.getName()).toRepresentation();
        assertEquals(role1.getName(), addedRole.getName());
        assertEquals(role1.getDescription(), addedRole.getDescription());
        assertEquals(role1.getAttributes(), addedRole.getAttributes());
    }

    @Test
    public void createRoleWithSameName() {
        try {
            RoleRepresentation role = RoleBuilder.create().name("role-a").build();
            rolesRsc.create(role);
            rolesRsc.create(role);
            fail();
        }
        catch (ClientErrorException e) {

        }
    }

    @Test
    public void createRoleWithNamePattern() {
        RoleRepresentation role = RoleBuilder.create().name("role-a-{pattern}").build();
        rolesRsc.create(role);
    }

    @Test
    public void testRemoveRole() {
        RoleRepresentation role2 = makeRole("role2");
        rolesRsc.create(role2);

        rolesRsc.deleteRole("role2");

        assertFalse(hasRole(rolesRsc, "role2"));
    }

    @Test
    public void testComposites() {
        RoleRepresentation roleA = makeRole("role-a");
        rolesRsc.create(roleA);

        assertFalse(rolesRsc.get("role-a").toRepresentation().isComposite());
        assertEquals(0, rolesRsc.get("role-a").getRoleComposites().size());

        RoleRepresentation roleB = makeRole("role-b");
        rolesRsc.create(roleB);

        RoleRepresentation roleC = makeRole("role-c");
        testRealmResource().roles().create(roleC);

        List<RoleRepresentation> l = new LinkedList<>();
        l.add(rolesRsc.get("role-b").toRepresentation());
        l.add(testRealmResource().roles().get("role-c").toRepresentation());
        rolesRsc.get("role-a").addComposites(l);

        Set<RoleRepresentation> composites = rolesRsc.get("role-a").getRoleComposites();

        assertTrue(rolesRsc.get("role-a").toRepresentation().isComposite());
        assertNames(composites, "role-b", "role-c");

        Set<RoleRepresentation> realmComposites = rolesRsc.get("role-a").getRealmRoleComposites();
        assertNames(realmComposites, "role-c");

        Set<RoleRepresentation> clientComposites = rolesRsc.get("role-a").getClientRoleComposites(clientRsc.toRepresentation().getId());
        assertNames(clientComposites, "role-b");

        rolesRsc.get("role-a").deleteComposites(l);

        assertFalse(rolesRsc.get("role-a").toRepresentation().isComposite());
        assertEquals(0, rolesRsc.get("role-a").getRoleComposites().size());
    }


    @Test
    public void testCompositeRolesSearch() {
        // Create main-role we will work on
        RoleRepresentation mainRole = makeRole("main-role");
        rolesRsc.create(mainRole);

        RoleResource mainRoleRsc = rolesRsc.get("main-role");

        // Add composites
        List<RoleRepresentation> createdRoles = IntStream.range(0, 20)
                .boxed()
                .map(i -> makeRole("role" + i))
                .peek(rolesRsc::create)
                .map(role -> rolesRsc.get(role.getName()).toRepresentation())
                .collect(Collectors.toList());

        mainRoleRsc.addComposites(createdRoles);
        mainRole = mainRoleRsc.toRepresentation();
        RoleByIdResource roleByIdResource = adminClient.realm("test").rolesById();

        // Search for all composites
        Set<RoleRepresentation> foundRoles = roleByIdResource.getRoleComposites(mainRole.getId());
        assertThat(foundRoles, hasSize(createdRoles.size()));

        // Search paginated composites
        foundRoles = roleByIdResource.searchRoleComposites(mainRole.getId(), null, 0, 10);
        assertThat(foundRoles, hasSize(10));

        // Search for composites by string role1 (should be role1, role10-role19) without pagination
        foundRoles = roleByIdResource.searchRoleComposites(mainRole.getId(), "role1", null, null);
        assertThat(foundRoles, hasSize(11));

        // Search for role1 with pagination
        foundRoles.forEach(System.out::println);
        foundRoles = roleByIdResource.searchRoleComposites(mainRole.getId(), "role1", 5, 5);
        assertThat(foundRoles, hasSize(5));
    }

    @Test
    public void usersInRole() {
        String clientID = clientRsc.toRepresentation().getId();

        // create test role on client
        String roleName = "test-role";
        RoleRepresentation role = makeRole(roleName);
        rolesRsc.create(role);
        assertTrue(hasRole(rolesRsc, roleName));
        List<RoleRepresentation> roleToAdd = Collections.singletonList(rolesRsc.get(roleName).toRepresentation());

        //create users and assign test role
        List<String> usernames = createUsernames(0, 10);
        usernames.forEach(username -> {
            UserRepresentation user = new UserRepresentation();
            user.setUsername(username);
            testRealmResource().users().create(user);
            user = getFullUserRep(username);
            testRealmResource().users().get(user.getId()).roles().clientLevel(clientID).add(roleToAdd);
        });

        // check if users have test role assigned
        RoleResource roleResource = rolesRsc.get(roleName);
        List<UserRepresentation> usersInRole = roleResource.getUserMembers();
        assertEquals(usernames, extractUsernames(usersInRole));

        // pagination
        List<UserRepresentation> usersInRole1 = roleResource.getUserMembers(0, 5);
        assertEquals(createUsernames(0, 5), extractUsernames(usersInRole1));
        assertNotNull(usersInRole1.get(0).getNotBefore(), "Not in full representation");
        List<UserRepresentation> usersInRole2 = roleResource.getUserMembers(true, 5, 10);
        assertEquals(createUsernames(5, 10), extractUsernames(usersInRole2));
    }

    private static List<String> createUsernames(int startIndex, int endIndex) {
        List<String> usernames = new ArrayList<>();
        for (int i = startIndex; i < endIndex; i++) {
            String userName = "user" + i;
            usernames.add(userName);
        }
        return usernames;
    }

    private static List<String> extractUsernames(Collection<UserRepresentation> users) {
        return users.stream().map(UserRepresentation::getUsername).collect(Collectors.toList());
    }

    @Test
    public void testSearchForRoles() {
        
        for(int i = 0; i<15; i++) {
            String roleName = "role"+i;
            RoleRepresentation role = makeRole(roleName);
            rolesRsc.create(role);
        }
        
        String roleNameA = "abcdef";
        RoleRepresentation roleA = makeRole(roleNameA);
        rolesRsc.create(roleA);

        String roleNameB = "defghi";
        RoleRepresentation roleB = makeRole(roleNameB);
        rolesRsc.create(roleB);

        List<RoleRepresentation> resultSearch = rolesRsc.list("def", -1, -1);
        assertEquals(2,resultSearch.size());
        
        List<RoleRepresentation> resultSearch2 = rolesRsc.list("role", -1, -1);
        assertEquals(15,resultSearch2.size());
        
        List<RoleRepresentation> resultSearchPagination = rolesRsc.list("role", 1, 5);
        assertEquals(5,resultSearchPagination.size());
    }
    
    @Test
    public void testPaginationRoles() {
        
        for(int i = 0; i<15; i++) {
            String roleName = "role"+i;
            RoleRepresentation role = makeRole(roleName);
            rolesRsc.create(role);
        }
        
        List<RoleRepresentation> resultSearchWithoutPagination = rolesRsc.list();
        assertEquals(15,resultSearchWithoutPagination.size());
        
        List<RoleRepresentation> resultSearchPagination = rolesRsc.list(1, 5);
        assertEquals(5,resultSearchPagination.size());
        
        List<RoleRepresentation> resultSearchPaginationIncoherentParams = rolesRsc.list(1, null);
        assertTrue(resultSearchPaginationIncoherentParams.size() >= 15);
    }
    
    @Test
    public void testPaginationRolesCache() {
        
        for(int i = 0; i<5; i++) {
            String roleName = "paginaterole"+i;
            RoleRepresentation role = makeRole(roleName);
            rolesRsc.create(role);
        }
       
        List<RoleRepresentation> resultBeforeAddingRoleToTestCache = rolesRsc.list(1, 1000);  
        
        // after a first call which init the cache, we add a new role to see if the result change
        
        RoleRepresentation role = makeRole("anewrole");
        rolesRsc.create(role);

        List<RoleRepresentation> resultafterAddingRoleToTestCache = rolesRsc.list(1, 1000);
        
        assertEquals(resultBeforeAddingRoleToTestCache.size()+1, resultafterAddingRoleToTestCache.size());
    }
    
    @Test
    public void getRolesWithFullRepresentation() {
        for(int i = 0; i<5; i++) {
            String roleName = "attributesrole"+i;
            RoleRepresentation role = makeRole(roleName);
            
            Map<String, List<String>> attributes = new HashMap<String, List<String>>();
            attributes.put("attribute1", Arrays.asList("value1","value2"));
            role.setAttributes(attributes);
                    
            rolesRsc.create(role);
        }
        
        List<RoleRepresentation> roles = rolesRsc.list(false);
        assertTrue(roles.get(0).getAttributes().containsKey("attribute1"));
    }

    @Test
    public void getRolesWithBriefRepresentation() {
        for(int i = 0; i<5; i++) {
            String roleName = "attributesrole"+i;
            RoleRepresentation role = makeRole(roleName);
            
            Map<String, List<String>> attributes = new HashMap<String, List<String>>();
            attributes.put("attribute1", Arrays.asList("value1","value2"));
            role.setAttributes(attributes);
                    
            rolesRsc.create(role);
        }
        
        List<RoleRepresentation> roles = rolesRsc.list();
        assertNull(roles.get(0).getAttributes());
    }
}
