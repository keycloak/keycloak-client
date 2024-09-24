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
package org.keycloak.client.testsuite.authz.admin;

import jakarta.ws.rs.NotFoundException;
import jakarta.ws.rs.core.Response;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.keycloak.admin.client.resource.AuthorizationResource;
import org.keycloak.admin.client.resource.PolicyResource;
import org.keycloak.admin.client.resource.UserPoliciesResource;
import org.keycloak.admin.client.resource.UserPolicyResource;
import org.keycloak.admin.client.resource.UsersResource;
import org.keycloak.representations.idm.UserRepresentation;
import org.keycloak.representations.idm.authorization.DecisionStrategy;
import org.keycloak.representations.idm.authorization.Logic;
import org.keycloak.representations.idm.authorization.PolicyRepresentation;
import org.keycloak.representations.idm.authorization.UserPolicyRepresentation;
import org.keycloak.testsuite.util.RealmBuilder;
import org.keycloak.testsuite.util.UserBuilder;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class UserPolicyManagementTest extends AbstractPolicyManagementTest {

    @Override
    protected RealmBuilder createTestRealm() {
        return super.createTestRealm()
                .user(UserBuilder.create().username("User A"))
                .user(UserBuilder.create().username("User B"))
                .user(UserBuilder.create().username("User C"))
                .user(UserBuilder.create().username("User D"))
                .user(UserBuilder.create().username("User E"))
                .user(UserBuilder.create().username("User F"));
    }

    @Test
    public void testCreate() {
        AuthorizationResource authorization = getClient().authorization();
        UserPolicyRepresentation representation = new UserPolicyRepresentation();

        representation.setName("Realm User Policy");
        representation.setDescription("description");
        representation.setDecisionStrategy(DecisionStrategy.CONSENSUS);
        representation.setLogic(Logic.NEGATIVE);
        representation.addUser("User A");
        representation.addUser("User B");

        assertCreated(authorization, representation);
    }

    @Test
    public void testUpdate() {
        AuthorizationResource authorization = getClient().authorization();
        UserPolicyRepresentation representation = new UserPolicyRepresentation();

        representation.setName("Update Test User Policy");
        representation.setDescription("description");
        representation.setDecisionStrategy(DecisionStrategy.CONSENSUS);
        representation.setLogic(Logic.NEGATIVE);
        representation.addUser("User A");
        representation.addUser("User B");
        representation.addUser("User C");

        assertCreated(authorization, representation);

        representation.setName("changed");
        representation.setDescription("changed");
        representation.setDecisionStrategy(DecisionStrategy.AFFIRMATIVE);
        representation.setLogic(Logic.POSITIVE);
        representation.setUsers(representation.getUsers().stream().filter(userName -> !userName.equals("User A")).collect(Collectors.toSet()));

        UserPoliciesResource policies = authorization.policies().user();
        UserPolicyResource permission = policies.findById(representation.getId());

        permission.update(representation);
        assertRepresentation(representation, permission);

        representation.setUsers(representation.getUsers().stream().filter(userName -> !userName.equals("User C")).collect(Collectors.toSet()));

        permission.update(representation);
        assertRepresentation(representation, permission);
    }

    @Test
    public void testDelete() {
        AuthorizationResource authorization = getClient().authorization();
        UserPolicyRepresentation representation = new UserPolicyRepresentation();

        representation.setName("Test Delete Permission");
        representation.addUser("User A");

        UserPoliciesResource policies = authorization.policies().user();

        try (Response response = policies.create(representation)) {
            UserPolicyRepresentation created = response.readEntity(UserPolicyRepresentation.class);

            policies.findById(created.getId()).remove();

            UserPolicyResource removed = policies.findById(created.getId());

            NotFoundException nfe = Assertions.assertThrows(NotFoundException.class, () -> removed.toRepresentation());
            Assertions.assertEquals(404, nfe.getResponse().getStatus());
        }
    }

    @Test
    public void testDeleteUser() {
        AuthorizationResource authorization = getClient().authorization();
        UserPolicyRepresentation representation = new UserPolicyRepresentation();

        representation.setName("Realm User Policy Delete");
        representation.setDescription("description");
        representation.setDecisionStrategy(DecisionStrategy.CONSENSUS);
        representation.setLogic(Logic.NEGATIVE);
        representation.addUser("User D");
        representation.addUser("User E");
        representation.addUser("User F");

        assertCreated(authorization, representation);

        UsersResource users = getRealm().users();
        UserRepresentation user = users.search("User D").get(0);

        users.get(user.getId()).remove();

        representation = authorization.policies().user().findById(representation.getId()).toRepresentation();

        Assertions.assertEquals(2, representation.getUsers().size());
        Assertions.assertFalse(representation.getUsers().contains(user.getId()));

        user = users.search("User E").get(0);
        users.get(user.getId()).remove();

        representation = authorization.policies().user().findById(representation.getId()).toRepresentation();

        Assertions.assertEquals(1, representation.getUsers().size());
        Assertions.assertFalse(representation.getUsers().contains(user.getId()));

        user = users.search("User F").get(0);
        users.get(user.getId()).remove();

        representation = authorization.policies().user().findById(representation.getId()).toRepresentation();

        Assertions.assertEquals(0, representation.getUsers().size());
        Assertions.assertFalse(representation.getUsers().contains(user.getId()));
    }

    @Test
    public void testGenericConfig() {
        AuthorizationResource authorization = getClient().authorization();
        UserPolicyRepresentation representation = new UserPolicyRepresentation();

        representation.setName("Test Generic Config Permission");
        representation.addUser("User A");

        UserPoliciesResource policies = authorization.policies().user();

        try (Response response = policies.create(representation)) {
            UserPolicyRepresentation created = response.readEntity(UserPolicyRepresentation.class);

            PolicyResource policy = authorization.policies().policy(created.getId());
            PolicyRepresentation genericConfig = policy.toRepresentation();

            Assertions.assertNotNull(genericConfig.getConfig());
            Assertions.assertNotNull(genericConfig.getConfig().get("users"));

            UserRepresentation user = getRealm().users().search("User A").get(0);

            Assertions.assertTrue(genericConfig.getConfig().get("users").contains(user.getId()));
        }
    }

    @Test
    public void failInvalidUser() {
        AuthorizationResource authorization = getClient().authorization();

        PolicyRepresentation policy = new PolicyRepresentation();

        policy.setName("User Policy-Malformed");
        policy.setDescription("Description of a malformed user Policy");
        policy.setDecisionStrategy(DecisionStrategy.UNANIMOUS);
        policy.setType("user");

        Map<String, String> config = new HashMap<>();

        // here we put something invalid ... a user ID would be needed
        config.put("users", "[\"doesnotexist\"]");

        policy.setConfig(config);

        try (Response response = authorization.policies().create(policy)) {
            Assertions.assertEquals(Response.Status.INTERNAL_SERVER_ERROR, response.getStatusInfo());
        }

        config.put("users", "");

        policy.setConfig(config);

        try (Response response = authorization.policies().create(policy)) {
            Assertions.assertEquals(Response.Status.INTERNAL_SERVER_ERROR, response.getStatusInfo());
        }

        config.clear();

        policy.setConfig(config);

        try (Response response = authorization.policies().create(policy)) {
            Assertions.assertEquals(Response.Status.INTERNAL_SERVER_ERROR, response.getStatusInfo());
        }
    }

    private void assertCreated(AuthorizationResource authorization, UserPolicyRepresentation representation) {
        UserPoliciesResource permissions = authorization.policies().user();

        try (Response response = permissions.create(representation)) {
            Assertions.assertEquals(201, response.getStatus());
            UserPolicyRepresentation created = response.readEntity(UserPolicyRepresentation.class);
            UserPolicyResource permission = permissions.findById(created.getId());
            assertRepresentation(representation, permission);
        }
    }

    private void assertRepresentation(UserPolicyRepresentation representation, UserPolicyResource permission) {
        UserPolicyRepresentation actual = permission.toRepresentation();
        assertRepresentation(representation, actual, () -> permission.resources(), () -> Collections.emptyList(), () -> permission.associatedPolicies());
        Assertions.assertEquals(representation.getUsers().size(), actual.getUsers().size());
        Assertions.assertEquals(0, actual.getUsers().stream().filter(userId -> !representation.getUsers().stream()
                .filter(userName -> getUserName(userId).equalsIgnoreCase(userName))
                .findFirst().isPresent())
                .count());
    }

    private String getUserName(String id) {
        return getRealm().users().get(id).toRepresentation().getUsername();
    }
}
