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
import jakarta.ws.rs.WebApplicationException;
import jakarta.ws.rs.core.Response;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.keycloak.client.testsuite.Assert.assertNames;
import static org.testcontainers.shaded.org.hamcrest.MatcherAssert.assertThat;
import static org.testcontainers.shaded.org.hamcrest.Matchers.hasEntry;
import static org.testcontainers.shaded.org.hamcrest.Matchers.containsInAnyOrder;
import static org.testcontainers.shaded.org.hamcrest.Matchers.nullValue;
import static org.testcontainers.shaded.org.hamcrest.Matchers.contains;
import static org.testcontainers.shaded.org.hamcrest.Matchers.equalTo;
import static org.testcontainers.shaded.org.hamcrest.Matchers.hasSize;
import static org.testcontainers.shaded.org.hamcrest.Matchers.notNullValue;
import static org.testcontainers.shaded.org.hamcrest.Matchers.is;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.resource.GroupResource;
import org.keycloak.admin.client.resource.IdentityProviderResource;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.admin.client.resource.RoleMappingResource;
import org.keycloak.admin.client.resource.UserProfileResource;
import org.keycloak.admin.client.resource.UserResource;
import org.keycloak.admin.client.resource.UsersResource;
import org.keycloak.client.testsuite.common.Creator;
import org.keycloak.client.testsuite.framework.KeycloakVersion;
import org.keycloak.client.testsuite.models.Constants;
import org.keycloak.common.util.Base64;
import org.keycloak.common.util.ObjectUtil;


import org.keycloak.client.testsuite.models.credential.dto.PasswordCredentialData;
import org.keycloak.client.testsuite.models.credential.dto.PasswordSecretData;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.representations.idm.ComponentRepresentation;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.representations.idm.ErrorRepresentation;
import org.keycloak.representations.idm.FederatedIdentityRepresentation;
import org.keycloak.representations.idm.GroupRepresentation;
import org.keycloak.representations.idm.IdentityProviderRepresentation;
import org.keycloak.representations.idm.MappingsRepresentation;
import org.keycloak.representations.idm.RealmRepresentation;
import org.keycloak.representations.idm.RequiredActionProviderRepresentation;
import org.keycloak.representations.idm.RoleRepresentation;
import org.keycloak.representations.idm.UserProfileAttributeMetadata;
import org.keycloak.representations.idm.UserProfileMetadata;
import org.keycloak.representations.idm.UserRepresentation;
import org.keycloak.representations.userprofile.config.UPAttribute;
import org.keycloak.representations.userprofile.config.UPAttributePermissions;
import org.keycloak.representations.userprofile.config.UPAttributeRequired;
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
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.function.Function;
import java.util.stream.Collectors;


/**
 * @author <a href="mailto:sthorger@redhat.com">Stian Thorgersen</a>
 */
public class UserTest extends AbstractAdminClientTest {

    public static final String DEFAULT_MAX_LENGTH_ATTRIBUTES = "2048";

    protected Set<String> managedAttributes = new HashSet<>();

    {
        managedAttributes.add("test");
        managedAttributes.add("attr");
        managedAttributes.add("attr1");
        managedAttributes.add("attr2");
        managedAttributes.add("attr3");
        managedAttributes.add("foo");
        managedAttributes.add("bar");
        managedAttributes.add("phoneNumber");
        managedAttributes.add("usercertificate");
        managedAttributes.add("saml.persistent.name.id.for.foo");
        managedAttributes.add("LDAP_ID");
        managedAttributes.add("LDap_Id");
        managedAttributes.add("deniedSomeAdmin");

        for (int i = 1; i < 10; i++) {
            managedAttributes.add("test" + i);
        }
    }


    @BeforeEach
    public void beforeUserTest() throws IOException {
        createAppClientInRealm(REALM_NAME);

        setUserProfileConfiguration(realm, null);
        UPConfig upConfig = realm.users().userProfile().getConfiguration();

        for (String name : managedAttributes) {
            upConfig.addOrReplaceAttribute(createAttributeMetadata(name));
        }

        setUserProfileConfiguration(realm, JsonSerialization.writeValueAsString(upConfig));
    }

    @AfterEach
    public void after() {
        realm.identityProviders().findAll()
                .forEach(ip -> realm.identityProviders().get(ip.getAlias()).remove());

        realm.groups().groups()
                .forEach(g -> realm.groups().group(g.getId()).remove());
       // realm.users().get(userId).remove();
    }

    public String createUser() {
        return createUser("user1", "user1@localhost");
    }

    public String createUser(String username, String email) {
        UserRepresentation user = new UserRepresentation();
        user.setUsername(username);
        user.setEmail(email);
        user.setRequiredActions(Collections.emptyList());
        user.setEnabled(true);

        return createUser(user);
    }

    private String createUser(UserRepresentation userRep) {
        return createUser(userRep, true);
    }


    private String createUser(UserRepresentation userRep, boolean assertAdminEvent) {
        final String createdId;
        try (Response response = realm.users().create(userRep)) {
            createdId = ApiUtil.getCreatedId(response);
        }

        getCleanup().addUserId(createdId);

        return createdId;
    }

    private void updateUser(UserResource user, UserRepresentation userRep) {
        user.update(userRep);
        List<CredentialRepresentation> credentials = userRep.getCredentials();
        userRep.setCredentials(credentials);
    }

    @Test
    public void verifyCreateUser() {
        createUser();
    }

    /**
     * See KEYCLOAK-11003
     */
    @Test
    public void createUserWithTemporaryPasswordWithAdditionalPasswordUpdateShouldRemoveUpdatePasswordRequiredAction() {

        String userId = createUser();

        CredentialRepresentation credTmp = new CredentialRepresentation();
        credTmp.setType(CredentialRepresentation.PASSWORD);
        credTmp.setValue("temp");
        credTmp.setTemporary(Boolean.TRUE);

        realm.users().get(userId).resetPassword(credTmp);

        CredentialRepresentation credPerm = new CredentialRepresentation();
        credPerm.setType(CredentialRepresentation.PASSWORD);
        credPerm.setValue("perm");
        credPerm.setTemporary(null);

        realm.users().get(userId).resetPassword(credPerm);

        UserRepresentation userRep = realm.users().get(userId).toRepresentation();

        Assert.assertFalse(userRep.getRequiredActions().contains("UPDATE_PASSWORD"));
    }


    @Test
    public void createDuplicatedUser1() {
        createUser();

        UserRepresentation user = new UserRepresentation();
        user.setUsername("user1");
        try (Response response = realm.users().create(user)) {
            assertEquals(409, response.getStatus());

            // Just to show how to retrieve underlying error message
            ErrorRepresentation error = response.readEntity(ErrorRepresentation.class);
            Assert.assertEquals("User exists with same username", error.getErrorMessage());
        }
    }

    @Test
    public void createDuplicatedUser2() {
        createUser();

        UserRepresentation user = new UserRepresentation();
        user.setUsername("user2");
        user.setEmail("user1@localhost");

        try (Response response = realm.users().create(user)) {
            assertEquals(409, response.getStatus());

            ErrorRepresentation error = response.readEntity(ErrorRepresentation.class);
            assertEquals("User exists with same email", error.getErrorMessage());
        }
    }

    @Test
    public void createDuplicatedUsernameWithEmail() {
        createUser("user1@local.com", "user1@local.org");

        UserRepresentation user = new UserRepresentation();
        user.setUsername("user1@local.org");
        user.setEmail("user2@localhost");
        try (Response response = realm.users().create(user)) {
            assertEquals(409, response.getStatus());

            ErrorRepresentation error = response.readEntity(ErrorRepresentation.class);
            Assert.assertEquals("User exists with same username", error.getErrorMessage());
        }
    }

    @Test
    public void createDuplicatedEmailWithUsername() {
        createUser("user1@local.com", "user1@local.org");

        UserRepresentation user = new UserRepresentation();
        user.setUsername("user2");
        user.setEmail("user1@local.com");

        try (Response response = realm.users().create(user)) {
            assertEquals(409, response.getStatus());

            ErrorRepresentation error = response.readEntity(ErrorRepresentation.class);
            Assert.assertEquals("User exists with same email", error.getErrorMessage());
        }
    }

    @Test
    public void createDuplicateEmailWithExistingDuplicates() {
        //Allow duplicate emails
        RealmRepresentation rep = realm.toRepresentation();
        rep.setDuplicateEmailsAllowed(true);
        realm.update(rep);

        //Create 2 users with the same email
        UserRepresentation user = new UserRepresentation();
        user.setEmail("user1@localhost");
        user.setUsername("user1");
        createUser(user, false);
        user.setUsername("user2");
        createUser(user, false);

        //Disallow duplicate emails
        rep.setDuplicateEmailsAllowed(false);
        realm.update(rep);

        //Create a third user with the same email
        user.setUsername("user3");

        try (Response response = realm.users().create(user)) {
            assertEquals(409, response.getStatus());
            ErrorRepresentation error = response.readEntity(ErrorRepresentation.class);
            Assert.assertEquals("User exists with same username or email", error.getErrorMessage());
        }
    }

    @Test
    public void createUserWithHashedCredentials() throws IOException {
        UserRepresentation user = new UserRepresentation();
        user.setUsername("user_creds");
        user.setEmail("email@localhost");

        PasswordCredentialData credentialData = new PasswordCredentialData(22, "my-algorithm", null);
        PasswordSecretData secretData = new PasswordSecretData("ABC", "theSalt".getBytes());

        try {
            CredentialRepresentation hashedPassword = new CredentialRepresentation();
            hashedPassword.setType("password");
            hashedPassword.setSecretData(JsonSerialization.writeValueAsString(secretData));
            hashedPassword.setCredentialData(JsonSerialization.writeValueAsString(credentialData));
            hashedPassword.setCreatedDate(1001L);
            hashedPassword.setUserLabel("deviceX");
            hashedPassword.setType(CredentialRepresentation.PASSWORD);
            user.setCredentials(Arrays.asList(hashedPassword));
            String userId = createUser(user);
            CredentialRepresentation credentialHashed = realm.users().get(userId).credentials().get(0);
            assertNotNull(credentialHashed, "Expecting credential");
            assertNotNull(credentialHashed.getCredentialData());
            realm.users().get(userId).remove();
        } catch (IOException e) {
            fail();
        }
    }

    @Test
    public void createUserWithDeprecatedCredentialsFormat() throws IOException {
        UserRepresentation user = new UserRepresentation();
        user.setUsername("user_creds");
        user.setEmail("email@localhost");

        PasswordCredentialData credentialData = new PasswordCredentialData(22, "my-algorithm", null);
        PasswordSecretData secretData = new PasswordSecretData("ABC", "theSalt".getBytes());

        String deprecatedCredential = "{\n" +
                "      \"type\" : \"password\",\n" +
                "      \"hashedSaltedValue\" : \"" + secretData.getValue() + "\",\n" +
                "      \"salt\" : \"" + Base64.encodeBytes(secretData.getSalt()) + "\",\n" +
                "      \"hashIterations\" : " + credentialData.getHashIterations() + ",\n" +
                "      \"algorithm\" : \"" + credentialData.getAlgorithm() + "\"\n" +
                "    }";

        CredentialRepresentation deprecatedHashedPassword = JsonSerialization.readValue(deprecatedCredential, CredentialRepresentation.class);
        Assert.assertNotNull(deprecatedHashedPassword.getHashedSaltedValue());
        Assert.assertNull(deprecatedHashedPassword.getCredentialData());

        deprecatedHashedPassword.setCreatedDate(1001l);
        deprecatedHashedPassword.setUserLabel("deviceX");
        deprecatedHashedPassword.setType(CredentialRepresentation.PASSWORD);

        user.setCredentials(Arrays.asList(deprecatedHashedPassword));

        String userId = createUser(user, false);

        CredentialRepresentation credentialHashed = realm.users().get(userId).credentials().get(0);
        assertNotNull(credentialHashed, "Expecting credential");
        assertNotNull(credentialHashed.getCredentialData());

        realm.users().get(userId).remove();
    }

    @Test
    public void createUserWithTempolaryCredentials() {
        UserRepresentation user = new UserRepresentation();
        user.setUsername("user_temppw");
        user.setEmail("email.temppw@localhost");

        CredentialRepresentation password = new CredentialRepresentation();
        password.setValue("password");
        password.setType(CredentialRepresentation.PASSWORD);
        password.setTemporary(true);
        user.setCredentials(Arrays.asList(password));

        String userId = createUser(user);

        UserRepresentation userRep = realm.users().get(userId).toRepresentation();
        Assert.assertEquals(1, userRep.getRequiredActions().size());
        Assert.assertEquals("UPDATE_PASSWORD", userRep.getRequiredActions().get(0));
    }

    @Test
    public void createUserWithRawCredentials() {
        UserRepresentation user = new UserRepresentation();
        user.setUsername("user_rawpw");
        user.setEmail("email.raw@localhost");

        CredentialRepresentation rawPassword = new CredentialRepresentation();
        rawPassword.setValue("ABCD");
        rawPassword.setType(CredentialRepresentation.PASSWORD);
        user.setCredentials(Arrays.asList(rawPassword));

        String userId = createUser(user);

        CredentialRepresentation credentialHashed = realm.users().get(userId).credentials().get(0);
        assertNotNull(credentialHashed, "Expecting credential");
        assertEquals(CredentialRepresentation.PASSWORD, credentialHashed.getType());
    }

    @Test
    public void createDuplicatedUser3() {
        createUser();

        UserRepresentation user = new UserRepresentation();
        user.setUsername("User1");

        try (Response response = realm.users().create(user)) {
            assertEquals(409, response.getStatus());
        }
    }

    @Test
    public void createDuplicatedUser4() {
        createUser();

        UserRepresentation user = new UserRepresentation();
        user.setUsername("USER1");

        try (Response response = realm.users().create(user)) {
            assertEquals(409, response.getStatus());
        }
    }

    @Test
    public void createDuplicatedUser5() {
        createUser();

        UserRepresentation user = new UserRepresentation();
        user.setUsername("user2");
        user.setEmail("User1@localhost");

        try (Response response = realm.users().create(user)) {
            assertEquals(409, response.getStatus());
        }
    }

    @Test
    public void createDuplicatedUser6() {
        createUser();

        UserRepresentation user = new UserRepresentation();
        user.setUsername("user2");
        user.setEmail("user1@LOCALHOST");

        try (Response response = realm.users().create(user)) {
            assertEquals(409, response.getStatus());
        }
    }

    @Test
    public void createDuplicatedUser7() {
        createUser("user1", "USer1@Localhost");

        UserRepresentation user = new UserRepresentation();
        user.setUsername("user2");
        user.setEmail("user1@localhost");

        try (Response response = realm.users().create(user)) {
            assertEquals(409, response.getStatus());
        }
    }

    // KEYCLOAK-7015
    @Test
    public void createTwoUsersWithEmptyStringEmails() {
        createUser("userEmail1", "");
        createUser("userEmail2", "");
    }

    @Test
    public void createUserWithFederationLink() {

        // add a dummy federation provider
        ComponentRepresentation dummyFederationProvider = new ComponentRepresentation();
        String componentId = KeycloakModelUtils.generateId();
        dummyFederationProvider.setId(componentId);
        dummyFederationProvider.setName("adsf");
        dummyFederationProvider.setProviderId("adsf");
        dummyFederationProvider.setProviderType("adsfdasf");
        adminClient.realms().realm(REALM_NAME).components().add(dummyFederationProvider);


        UserRepresentation user = new UserRepresentation();
        user.setUsername("userProvider");
        user.setEmail("userProvider@localhost");
      //  user.setFederationLink(componentId);

        String userId = createUser(user);

        // fetch user again and see federation link filled in
        UserRepresentation createdUser = realm.users().get(userId).toRepresentation();
        assertNotNull(createdUser);
        assertEquals(user.getFederationLink(), createdUser.getFederationLink());
    }

    @Test
    public void createUserWithoutUsername() {
        UserRepresentation user = new UserRepresentation();
        user.setEmail("user1@localhost");

        Response response = realm.users().create(user);
        assertEquals(400, response.getStatus());
        ErrorRepresentation error = response.readEntity(ErrorRepresentation.class);
        Assert.assertEquals("User name is missing", error.getErrorMessage());

    }

    @Test
    public void createUserWithEmailAsUsername() {
        RealmRepresentation realmRep = realm.toRepresentation();
        Boolean registrationEmailAsUsername = realmRep.isRegistrationEmailAsUsername();
        Boolean editUsernameAllowed = realmRep.isEditUsernameAllowed();
        getCleanup().addCleanup(() -> {
            realmRep.setRegistrationEmailAsUsername(registrationEmailAsUsername);
            realm.update(realmRep);
        });
        getCleanup().addCleanup(() -> {
            realmRep.setEditUsernameAllowed(editUsernameAllowed);
            realm.update(realmRep);
        });

        switchRegistrationEmailAsUsername(true);
        switchEditUsernameAllowedOn(false);
        String id = createUser();
        UserResource user = realm.users().get(id);
        UserRepresentation userRep = user.toRepresentation();
        assertEquals("user1@localhost", userRep.getEmail());
        assertEquals(userRep.getEmail(), userRep.getUsername());
        deleteUser(id);

        switchRegistrationEmailAsUsername(true);
        switchEditUsernameAllowedOn(true);
        id = createUser();
        user = realm.users().get(id);
        userRep = user.toRepresentation();
        assertEquals("user1@localhost", userRep.getEmail());
        assertEquals(userRep.getEmail(), userRep.getUsername());
        deleteUser(id);

        switchRegistrationEmailAsUsername(false);
        switchEditUsernameAllowedOn(true);
        id = createUser();
        user = realm.users().get(id);
        userRep = user.toRepresentation();
        assertEquals("user1", userRep.getUsername());
        assertEquals("user1@localhost", userRep.getEmail());
        deleteUser(id);

        switchRegistrationEmailAsUsername(false);
        switchEditUsernameAllowedOn(false);
        id = createUser();
        user = realm.users().get(id);
        userRep = user.toRepresentation();
        assertEquals("user1", userRep.getUsername());
        assertEquals("user1@localhost", userRep.getEmail());
    }

    @Test
    public void createUserWithEmptyUsername() {
        UserRepresentation user = new UserRepresentation();
        user.setUsername("");
        user.setEmail("user2@localhost");

        try (Response response = realm.users().create(user)) {
            assertEquals(400, response.getStatus());
            ErrorRepresentation error = response.readEntity(ErrorRepresentation.class);
            Assert.assertEquals("User name is missing", error.getErrorMessage());
        }
    }

    @Test
    public void createUserWithInvalidPolicyPassword() {
        RealmRepresentation rep = realm.toRepresentation();
        String passwordPolicy = rep.getPasswordPolicy();
        rep.setPasswordPolicy("length(8)");
        realm.update(rep);
        UserRepresentation user = new UserRepresentation();
        user.setUsername("user4");
        user.setEmail("user4@localhost");
        CredentialRepresentation rawPassword = new CredentialRepresentation();
        rawPassword.setValue("ABCD");
        rawPassword.setType(CredentialRepresentation.PASSWORD);
        user.setCredentials(Collections.singletonList(rawPassword));

        try (Response response = realm.users().create(user)) {
            assertEquals(400, response.getStatus());
            rep.setPasswordPolicy(passwordPolicy);
            realm.update(rep);
        }
        rep.setPasswordPolicy("");
        realm.update(rep);
    }

    @Test
    public void createUserWithCreateTimestamp() {
        UserRepresentation user = new UserRepresentation();
        user.setUsername("userTimestamp1");
        user.setEmail("userTimestamp1@localhost");
        Long createdTimestamp = 1695238476L;
        user.setCreatedTimestamp(createdTimestamp);

        String userId = createUser(user);

        // fetch user again and see created timestamp filled in
        UserRepresentation createdUser = realm.users().get(userId).toRepresentation();
        assertNotNull(createdUser);
        assertEquals(user.getCreatedTimestamp(), createdUser.getCreatedTimestamp());
    }

    @Test
    public void countUsersByEnabledFilter() {

        // create 2 enabled and 1 disabled user
        UserRepresentation enabledUser1 = new UserRepresentation();
        enabledUser1.setUsername("enabled1");
        enabledUser1.setEmail("enabled1@enabledfilter.com");
        enabledUser1.setEnabled(true);
        createUser(enabledUser1);

        UserRepresentation enabledUser2 = new UserRepresentation();
        enabledUser2.setUsername("enabled2");
        enabledUser2.setEmail("enabled2@enabledfilter.com");
        enabledUser2.setEnabled(true);
        createUser(enabledUser2);

        UserRepresentation disabledUser1 = new UserRepresentation();
        disabledUser1.setUsername("disabled1");
        disabledUser1.setEmail("disabled1@enabledfilter.com");
        disabledUser1.setEnabled(false);
        createUser(disabledUser1);

        Boolean enabled = true;
        Boolean disabled = false;

        // count all users with @enabledfilter.com
        assertThat(realm.users().count(null, null, null, "@enabledfilter.com", null, null, null, null), is(3));

        // count users that are enabled and have username enabled1
        assertThat(realm.users().count(null, null, null, "@enabledfilter.com", null, "enabled1", enabled, null),is(1));

        // count users that are disabled
        assertThat(realm.users().count(null, null, null, "@enabledfilter.com", null, null, disabled, null), is(1));

        // count users that are enabled
        assertThat(realm.users().count(null, null, null, "@enabledfilter.com", null, null, enabled, null), is(2));
    }

    @Test
    public void searchByEmail() {
        createUsers();

        List<UserRepresentation> users = realm.users().search(null, null, null, "user1@localhost", null, null);
        assertEquals(1, users.size());

        users = realm.users().search(null, null, null, "@localhost", null, null);
        assertEquals(9, users.size());
    }

    @Test
    public void searchByEmailExactMatch() {
        createUsers();
        List<UserRepresentation> users = realm.users().searchByEmail("user1@localhost", true);
        assertEquals(1, users.size());

        users = realm.users().search("@localhost", true);
        assertEquals(0, users.size());
    }

    @Test
    public void searchByUsername() {
        createUsers();

        List<UserRepresentation> users = realm.users().search("username1", null, null, null, null, null);
        assertEquals(1, users.size());

        users = realm.users().search("username", null, null, null, null, null);
        assertEquals(9, users.size());
    }

    private String mapToSearchQuery(Map<String, String> search) {
        return search.entrySet()
                .stream()
                .map(e -> String.format("%s:%s", e.getKey(), e.getValue()))
                .collect(Collectors.joining(" "));
    }

    @Test
    public void searchByAttribute() {
        createUsers();

        Map<String, String> attributes = new HashMap<>();
        attributes.put("test", "test1");
        List<UserRepresentation> users = realm.users().searchByAttributes(mapToSearchQuery(attributes));
        assertEquals(1, users.size());

        attributes.clear();
        attributes.put("attr", "common");

        users = realm.users().searchByAttributes(mapToSearchQuery(attributes));
        assertEquals(9, users.size());

        attributes.clear();
        attributes.put("x", "common");
        users = realm.users().searchByAttributes(mapToSearchQuery(attributes));
        assertEquals(0, users.size());
    }

    @Test
    public void searchByMultipleAttributes() {
        List<String> usersId = createUsers();

        Map<String, String> attributes = new HashMap<>();
        attributes.put("test", "test1");
        attributes.put("attr", "common");
        attributes.put("test1", "test1");

        List<UserRepresentation> users = realm.users().searchByAttributes(mapToSearchQuery(attributes));
        assertEquals(1, users.size());
        usersId.forEach(id-> realm.users().get(id).remove());
    }

    @Test
    public void searchByAttributesWithPagination() {
        List<String> usersId = createUsers();

        Map<String, String> attributes = new HashMap<>();
        attributes.put("attr", "Common");
        for (int i = 1; i < 10; i++) {
            List<UserRepresentation> users = realm.users().searchByAttributes(i - 1, 1, null, false, mapToSearchQuery(attributes));
            assertEquals(1, users.size());
            assertTrue(users.get(0).getAttributes().keySet().stream().anyMatch(attributes::containsKey));
        }
        usersId.forEach(id-> realm.users().get(id).remove());
    }

    @Test
    public void storeAndReadUserWithLongAttributeValue() {
        String longValue = randomAlphanumericString(Integer.parseInt(DEFAULT_MAX_LENGTH_ATTRIBUTES));

        getCleanup().addUserId(createUser(REALM_NAME, "user1", "password", "user1FirstName", "user1LastName", "user1@example.com",
                user -> {
                    Map<String, List<String>> attributes = new HashMap<>();
                    attributes.put("attr", Arrays.asList(longValue));
                    user.setAttributes(attributes);
                }));


        List<UserRepresentation> users = realm.users().search("user1", true);

        assertThat(users, hasSize(1));
        assertThat(users.get(0).getAttributes().get("attr").get(0), equalTo(longValue));

        WebApplicationException ex = assertThrows(WebApplicationException.class, () -> getCleanup().addUserId(createUser(REALM_NAME, "user2", "password", "user2FirstName", "user2LastName", "user2@example.com",
                user -> {
                    Map<String, List<String>> attributes = new HashMap<>();
                    attributes.put("attr", Arrays.asList(longValue + "a"));
                    user.setAttributes(attributes);
                })));
        assertThat(ex.getResponse().getStatusInfo().getStatusCode(), equalTo(400));
        assertThat(ex.getResponse().readEntity(ErrorRepresentation.class).getErrorMessage(), equalTo("error-invalid-length"));
    }

    @Test
    public void searchByLongAttributes() {
        // random string with suffix that makes it case-sensitive and distinct
        String longValue = randomAlphanumericString(Integer.parseInt(DEFAULT_MAX_LENGTH_ATTRIBUTES) - 1) + "u";
        String longValue2 = randomAlphanumericString(Integer.parseInt(DEFAULT_MAX_LENGTH_ATTRIBUTES) - 1) + "v";

        getCleanup().addUserId(createUser(REALM_NAME, "user1", "password", "user1FirstName", "user1LastName", "user1@example.com",
                user -> {
                    Map<String, List<String>> attributes = new HashMap<>();
                    attributes.put("test1", Arrays.asList(longValue, "v2"));
                    attributes.put("test2", Arrays.asList("v2"));
                    user.setAttributes(attributes);
                }));

        getCleanup().addUserId(createUser(REALM_NAME, "user2", "password", "user2FirstName", "user2LastName", "user2@example.com",
                user -> {
                    Map<String, List<String>> attributes = new HashMap<>();
                    attributes.put("test1", Arrays.asList(longValue, "v2"));
                    attributes.put("test2", Arrays.asList(longValue2));
                    user.setAttributes(attributes);
                }));

        getCleanup().addUserId(createUser(REALM_NAME, "user3", "password", "user3FirstName", "user3LastName", "user3@example.com",
                user -> {
                    Map<String, List<String>> attributes = new HashMap<>();
                    attributes.put("test2", Arrays.asList(longValue, "v3"));
                    attributes.put("test4", Arrays.asList("v4"));
                    user.setAttributes(attributes);
                }));

        assertThat(realm.users().searchByAttributes(mapToSearchQuery(Collections.singletonMap("test1", longValue)))
                        .stream().map(UserRepresentation::getUsername).collect(Collectors.toList()),
                containsInAnyOrder("user1", "user2"));

        Map<String, String> searchAttributes = new HashMap<>();
        searchAttributes.put("test1", longValue);
        searchAttributes.put("test2", longValue2);

        assertThat(realm.users().searchByAttributes(mapToSearchQuery(searchAttributes)).stream().map(UserRepresentation::getUsername).collect(Collectors.toList()),
                contains("user2"));

        // case-insensitive search
        assertThat(realm.users().searchByAttributes(mapToSearchQuery(searchAttributes)).stream().map(UserRepresentation::getUsername).collect(Collectors.toList()),
                contains("user2"));
    }


    @Test
    public void searchByUsernameExactMatch() {
        List<String> usersId = createUsers();

        UserRepresentation user = new UserRepresentation();
        user.setUsername("username11");

        createUser(user);

        List<UserRepresentation> users = realm.users().search("username1", true);
        assertEquals(1, users.size());

        users = realm.users().searchByUsername("username1", true);
        assertEquals(1, users.size());

        users = realm.users().search("user", true);
        assertEquals(0, users.size());
    }

    @Test
    public void searchByFirstNameExact() {
        createUsers();
        List<UserRepresentation> users = realm.users().searchByFirstName("First1", true);
        assertEquals(1, users.size());
    }

    @Test
    public void searchByLastNameExact() {
        createUsers();
        List<UserRepresentation> users = realm.users().searchByLastName("Last1", true);
        assertEquals(1, users.size());
    }

    @Test
    public void searchByFirstNameNullForLastName() {
        UserRepresentation user = new UserRepresentation();
        user.setUsername("user1");
        user.setFirstName("Erik");
        user.setRequiredActions(Collections.emptyList());
        user.setEnabled(true);

        createUser(user);

        List<UserRepresentation> users = realm.users().search("Erik", 0, 50);
        assertEquals(1, users.size());
    }

    @Test
    public void searchByLastNameNullForFirstName() {
        UserRepresentation user = new UserRepresentation();
        user.setUsername("user1");
        user.setLastName("de Wit");
        user.setRequiredActions(Collections.emptyList());
        user.setEnabled(true);

        createUser(user);

        List<UserRepresentation> users = realm.users().search("*wit*", null, null);
        assertEquals(1, users.size());
    }

    @Test
    public void searchByEnabled() {
        String userCommonName = "enabled-disabled-user";

        UserRepresentation user1 = new UserRepresentation();
        user1.setUsername(userCommonName + "1");
        user1.setRequiredActions(Collections.emptyList());
        user1.setEnabled(true);
        createUser(user1);

        UserRepresentation user2 = new UserRepresentation();
        user2.setUsername(userCommonName + "2");
        user2.setRequiredActions(Collections.emptyList());
        user2.setEnabled(false);
        createUser(user2);


        List<UserRepresentation> enabledUsersWithFilter = realm.users().search(userCommonName, null, null, null, null, null, true, true);
        assertEquals(1, enabledUsersWithFilter.size());
        assertEquals(user1.getUsername(), enabledUsersWithFilter.get(0).getUsername());

        List<UserRepresentation> disabledUsers = realm.users().search(userCommonName, null, null, null, null, null, false, false);
        assertEquals(1, disabledUsers.size());
        assertEquals(user2.getUsername(), disabledUsers.get(0).getUsername());

        List<UserRepresentation> allUsers = realm.users().search(userCommonName, null, null, null, 0, 100, null, true);
        assertEquals(2, allUsers.size());
    }

    @Test
    public void searchWithFilters() {
        createUser();

        UserRepresentation user = new UserRepresentation();
        user.setUsername("user2");
        user.setFirstName("First");
        user.setLastName("Last");
        user.setEmail("user2@localhost");
        user.setRequiredActions(Collections.emptyList());
        user.setEnabled(false);
        createUser(user);

        List<UserRepresentation> searchFirstNameAndDisabled = realm.users().search(null, "First", null, null, null, null, false, true);
        assertEquals(1, searchFirstNameAndDisabled.size());
        assertEquals(user.getUsername(), searchFirstNameAndDisabled.get(0).getUsername());

        List<UserRepresentation> searchLastNameAndEnabled = realm.users().search(null, null, "Last", null, null, null, true, false);
        assertEquals(0, searchLastNameAndEnabled.size());

        List<UserRepresentation> searchEmailAndDisabled = realm.users().search(null, null, null, "user2@localhost", 0, 50, false, true);
        assertEquals(1, searchEmailAndDisabled.size());
        assertEquals(user.getUsername(), searchEmailAndDisabled.get(0).getUsername());

        List<UserRepresentation> searchInvalidSizeAndDisabled = realm.users().search(null, null, null, null, 10, 20, null, false);
        assertEquals(0, searchInvalidSizeAndDisabled.size());
    }

    @Test
    public void searchWithFilterAndEnabledAttribute() {
        createUser();

        UserRepresentation user = new UserRepresentation();
        user.setUsername("user3");
        user.setFirstName("user3First");
        user.setLastName("user3Last");
        user.setEmail("user3@localhost");
        user.setRequiredActions(Collections.emptyList());
        user.setEnabled(false);
        createUser(user);

        List<UserRepresentation> searchFilterUserNameAndDisabled = realm.users().search("user3", false, 0, 5);
        assertEquals(1, searchFilterUserNameAndDisabled.size());
        assertEquals(user.getUsername(), searchFilterUserNameAndDisabled.get(0).getUsername());

        List<UserRepresentation> searchFilterMailAndDisabled = realm.users().search("user3@localhost", false, 0, 5);
        assertEquals(1, searchFilterMailAndDisabled.size());
        assertEquals(user.getUsername(), searchFilterMailAndDisabled.get(0).getUsername());

        List<UserRepresentation> searchFilterLastNameAndEnabled = realm.users().search("user3Last", true, 0, 5);
        assertEquals(0, searchFilterLastNameAndEnabled.size());
    }

    @Test
    public void searchByIdp() {
        // Add user without IDP
        createUser();

        // add sample Identity Providers
        final String identityProviderAlias1 = "identity-provider-alias1";
        addSampleIdentityProvider(identityProviderAlias1, 0);
        final String identityProviderAlias2 = "identity-provider-alias2";
        addSampleIdentityProvider(identityProviderAlias2, 1);

        final String commonIdpUserId = "commonIdpUserId";

        // create first IDP1 User with link
        final String idp1User1Username = "idp1user1";
        final String idp1User1KeycloakId = createUser(idp1User1Username, "idp1user1@localhost");
        final String idp1User1UserId = "idp1user1Id";
        FederatedIdentityRepresentation link1_1 = new FederatedIdentityRepresentation();
        link1_1.setUserId(idp1User1UserId);
        link1_1.setUserName(idp1User1Username);
        addFederatedIdentity(idp1User1KeycloakId, identityProviderAlias1, link1_1);

        // create second IDP1 User with link
        final String idp1User2Username = "idp1user2";
        final String idp1User2KeycloakId = createUser(idp1User2Username, "idp1user2@localhost");
        FederatedIdentityRepresentation link1_2 = new FederatedIdentityRepresentation();
        link1_2.setUserId(commonIdpUserId);
        link1_2.setUserName(idp1User2Username);
        addFederatedIdentity(idp1User2KeycloakId, identityProviderAlias1, link1_2);

        // create IDP2 user with link
        final String idp2UserUsername = "idp2user";
        final String idp2UserKeycloakId = createUser(idp2UserUsername, "idp2user@localhost");
        FederatedIdentityRepresentation link2 = new FederatedIdentityRepresentation();
        link2.setUserId(commonIdpUserId);
        link2.setUserName(idp2UserUsername);
        addFederatedIdentity(idp2UserKeycloakId, identityProviderAlias2, link2);

        // run search tests
        List<UserRepresentation> searchForAllUsers =
                realm.users().search(null, null, null, null, null, null, null, null, null, null, null);
        assertEquals(4, searchForAllUsers.size());

        List<UserRepresentation> searchByIdpAlias =
                realm.users().search(null, null, null, null, null, identityProviderAlias1, null, null, null, null,
                        null);
        assertEquals(2, searchByIdpAlias.size());
        assertEquals(idp1User1Username, searchByIdpAlias.get(0).getUsername());
        assertEquals(idp1User2Username, searchByIdpAlias.get(1).getUsername());

        List<UserRepresentation> searchByIdpUserId =
                realm.users().search(null, null, null, null, null, null, commonIdpUserId, null, null, null, null);
        assertEquals(2, searchByIdpUserId.size());
        assertEquals(idp1User2Username, searchByIdpUserId.get(0).getUsername());
        assertEquals(idp2UserUsername, searchByIdpUserId.get(1).getUsername());

        List<UserRepresentation> searchByIdpAliasAndUserId =
                realm.users().search(null, null, null, null, null, identityProviderAlias1, idp1User1UserId, null, null,
                        null,
                        null);
        assertEquals(1, searchByIdpAliasAndUserId.size());
        assertEquals(idp1User1Username, searchByIdpAliasAndUserId.get(0).getUsername());
    }

    @Test
    public void searchByIdpAndEnabled() {
        // add sample Identity Provider
        final String identityProviderAlias = "identity-provider-alias";
        addSampleIdentityProvider(identityProviderAlias, 0);

        // add disabled user with IDP link
        UserRepresentation disabledUser = new UserRepresentation();
        final String disabledUsername = "disabled_username";
        disabledUser.setUsername(disabledUsername);
        disabledUser.setEmail("disabled@localhost");
        disabledUser.setEnabled(false);
        final String disabledUserKeycloakId = createUser(disabledUser);
        FederatedIdentityRepresentation disabledUserLink = new FederatedIdentityRepresentation();
        final String disabledUserId = "disabledUserId";
        disabledUserLink.setUserId(disabledUserId);
        disabledUserLink.setUserName(disabledUsername);
        addFederatedIdentity(disabledUserKeycloakId, identityProviderAlias, disabledUserLink);

        // add enabled user with IDP link
        UserRepresentation enabledUser = new UserRepresentation();
        final String enabledUsername = "enabled_username";
        enabledUser.setUsername(enabledUsername);
        enabledUser.setEmail("enabled@localhost");
        enabledUser.setEnabled(true);
        final String enabledUserKeycloakId = createUser(enabledUser);
        FederatedIdentityRepresentation enabledUserLink = new FederatedIdentityRepresentation();
        final String enabledUserId = "enabledUserId";
        enabledUserLink.setUserId(enabledUserId);
        enabledUserLink.setUserName(enabledUsername);
        addFederatedIdentity(enabledUserKeycloakId, identityProviderAlias, enabledUserLink);

        // run search tests
        List<UserRepresentation> searchByIdpAliasAndEnabled =
                realm.users().search(null, null, null, null, null, identityProviderAlias, null, null, null, true, null);
        assertEquals(1, searchByIdpAliasAndEnabled.size());
        assertEquals(enabledUsername, searchByIdpAliasAndEnabled.get(0).getUsername());

        List<UserRepresentation> searchByIdpAliasAndDisabled =
                realm.users().search(null, null, null, null, null, identityProviderAlias, null, null, null, false,
                        null);
        assertEquals(1, searchByIdpAliasAndDisabled.size());
        assertEquals(disabledUsername, searchByIdpAliasAndDisabled.get(0).getUsername());

        List<UserRepresentation> searchByIdpAliasWithoutEnabledFlag =
                realm.users().search(null, null, null, null, null, identityProviderAlias, null, null, null, null, null);
        assertEquals(2, searchByIdpAliasWithoutEnabledFlag.size());
        assertEquals(disabledUsername, searchByIdpAliasWithoutEnabledFlag.get(0).getUsername());
        assertEquals(enabledUsername, searchByIdpAliasWithoutEnabledFlag.get(1).getUsername());
    }

    @Test
    public void searchById() {
        String expectedUserId = createUsers().get(0);
        List<UserRepresentation> users = realm.users().search("id:" + expectedUserId, null, null);

        assertEquals(1, users.size());
        assertEquals(expectedUserId, users.get(0).getId());

        users = realm.users().search("id:   " + expectedUserId + "     ", null, null);

        assertEquals(1, users.size());
        assertEquals(expectedUserId, users.get(0).getId());
    }

    @Test
    public void infixSearch() {
        List<String> userIds = createUsers();

        // Username search
        List<UserRepresentation> users = realm.users().search("*1*", null, null);
        assertThat(users, hasSize(1));
        assertThat(userIds.get(0), equalTo(users.get(0).getId()));

        users = realm.users().search("*y*", null, null);
        assertThat(users.size(), is(0));

        users = realm.users().search("*name*", null, null);
        assertThat(users, hasSize(9));

        users = realm.users().search("**", null, null);
        assertThat(users, hasSize(9));

        // First/Last name search
        users = realm.users().search("*first1*", null, null);
        assertThat(users, hasSize(1));
        assertThat(userIds.get(0), equalTo(users.get(0).getId()));

        users = realm.users().search("*last*", null, null);
        assertThat(users, hasSize(9));

        // Email search
        users = realm.users().search("*@localhost*", null, null);
        assertThat(users, hasSize(9));

        users = realm.users().search("*1@local*", null, null);
        assertThat(users, hasSize(1));
        assertThat(userIds.get(0), equalTo(users.get(0).getId()));
    }

    @Test
    public void prefixSearch() {
        List<String> userIds = createUsers();

        // Username search
        List<UserRepresentation> users = realm.users().search("user", null, null);
        assertThat(users, hasSize(9));

        users = realm.users().search("user*", null, null);
        assertThat(users, hasSize(9));

        users = realm.users().search("name", null, null);
        assertThat(users, hasSize(0));

        users = realm.users().search("name*", null, null);
        assertThat(users, hasSize(0));

        users = realm.users().search("username1", null, null);
        assertThat(users, hasSize(1));
        assertThat(userIds.get(0), equalTo(users.get(0).getId()));

        users = realm.users().search("username1*", null, null);
        assertThat(users, hasSize(1));
        assertThat(userIds.get(0), equalTo(users.get(0).getId()));

        users = realm.users().search(null, null, null);
        assertThat(users, hasSize(9));

        users = realm.users().search("", null, null);
        assertThat(users, hasSize(9));

        users = realm.users().search("*", null, null);
        assertThat(users, hasSize(9));

        // First/Last name search
        users = realm.users().search("first1", null, null);
        assertThat(users, hasSize(1));
        assertThat(userIds.get(0), equalTo(users.get(0).getId()));

        users = realm.users().search("first1*", null, null);
        assertThat(users, hasSize(1));
        assertThat(userIds.get(0), equalTo(users.get(0).getId()));

        users = realm.users().search("last", null, null);
        assertThat(users, hasSize(9));

        users = realm.users().search("last*", null, null);
        assertThat(users, hasSize(9));

        // Email search
        users = realm.users().search("user1@local", null, null);
        assertThat(users, hasSize(1));
        assertThat(userIds.get(0), equalTo(users.get(0).getId()));

        users = realm.users().search("user1@local*", null, null);
        assertThat(users, hasSize(1));
        assertThat(userIds.get(0), equalTo(users.get(0).getId()));
    }

    @Test
    public void circumfixSearch() {
        createUsers();

        List<UserRepresentation> users = realm.users().search("u*name", null, null);
        assertThat(users, hasSize(9));
    }

    @Test
    public void wildcardSearch() {
        UserProfileResource upResource = realm.users().userProfile();
        UPConfig upConfig = upResource.getConfiguration();
        Map<String, Object> prohibitedCharsOrigCfg = upConfig.getAttribute("username").getValidations().get("username-prohibited-characters");
        upConfig.getAttribute("username").getValidations().remove("username-prohibited-characters");
        upResource.update(upConfig);

        try {
            createUser("0user\\\\0", "email0@emal");
            createUser("1user\\\\", "email1@emal");
            createUser("2user\\\\%", "email2@emal");
            createUser("3user\\\\*", "email3@emal");
            createUser("4user\\\\_", "email4@emal");

            assertThat(realm.users().search("*", null, null), hasSize(5));
            assertThat(realm.users().search("*user\\", null, null), hasSize(5));
            assertThat(realm.users().search("\"2user\\\\%\"", null, null), hasSize(1));
        } finally {
            upConfig.getAttribute("username").addValidation("username-prohibited-characters", prohibitedCharsOrigCfg);
            upResource.update(upConfig);
        }
    }

    @Test
    public void exactSearch() {
        List<String> userIds = createUsers();

        // Username search
        List<UserRepresentation> users = realm.users().search("\"username1\"", null, null);
        assertThat(users, hasSize(1));
        assertThat(userIds.get(0), equalTo(users.get(0).getId()));

        users = realm.users().search("\"user\"", null, null);
        assertThat(users, hasSize(0));

        users = realm.users().search("\"\"", null, null);
        assertThat(users, hasSize(0));

        // First/Last name search
        users = realm.users().search("\"first1\"", null, null);
        assertThat(users, hasSize(1));
        assertThat(userIds.get(0), equalTo(users.get(0).getId()));

        // Email search
        users = realm.users().search("\"user1@localhost\"", null, null);
        assertThat(users, hasSize(1));
        assertThat(userIds.get(0), equalTo(users.get(0).getId()));
    }

    @Test
    public void searchWithExactMatch() {
        UserRepresentation user = new UserRepresentation();
        user.setUsername("test_username");
        user.setFirstName("test_first_name");
        user.setLastName("test_last_name");
        user.setEmail("test_email@test.com");
        user.setEnabled(true);
        user.setEmailVerified(true);
        createUser(user);

        UserRepresentation user2 = new UserRepresentation();
        user2.setUsername("test_username2");
        user2.setFirstName("test_first_name2");
        user2.setLastName("test_last_name");
        user2.setEmail("test_email@test.com2");
        user2.setEnabled(true);
        user2.setEmailVerified(true);
        createUser(user2);

        UserRepresentation user3 = new UserRepresentation();
        user3.setUsername("test_username3");
        user3.setFirstName("test_first_name");
        user3.setLastName("test_last_name3");
        user3.setEmail("test_email@test.com3");
        user3.setEnabled(true);
        user3.setEmailVerified(true);
        createUser(user3);

        List<UserRepresentation> users = realm.users().search(
                null, null, null, "test_email@test.co",
                0, 10, null, null, true
        );
        assertEquals(0, users.size());
        users = realm.users().search(
                null, null, null, "test_email@test.com",
                0, 10, null, null, true
        );
        assertEquals(1, users.size());
        users = realm.users().search(
                null, null, "test_last", "test_email@test.com",
                0, 10, null, null, true
        );
        assertEquals(0, users.size());
        users = realm.users().search(
                null, null, "test_last_name", "test_email@test.com",
                0, 10, null, null, true
        );
        assertEquals(1, users.size());
        users = realm.users().search(
                null, "test_first", "test_last_name", "test_email@test.com",
                0, 10, null, null, true
        );
        assertEquals(0, users.size());
        users = realm.users().search(
                null, "test_first_name", "test_last_name", "test_email@test.com",
                0, 10, null, null, true
        );
        assertEquals(1, users.size());
        users = realm.users().search(
                "test_usernam", "test_first_name", "test_last_name", "test_email@test.com",
                0, 10, null, null, true
        );
        assertEquals(0, users.size());
        users = realm.users().search(
                "test_username", "test_first_name", "test_last_name", "test_email@test.com",
                0, 10, null, null, true
        );
        assertEquals(1, users.size());

        users = realm.users().search(
                null, null, "test_last_name", null,
                0, 10, null, null, true
        );
        assertEquals(2, users.size());
        users = realm.users().search(
                null, "test_first_name", null, null,
                0, 10, null, null, true
        );
        assertEquals(2, users.size());
    }

    @Test
    public void countUsersNotServiceAccount() {
        createUsers();

        Integer count = realm.users().count();
        assertEquals(9, count.intValue());

        ClientRepresentation client = new ClientRepresentation();

        client.setClientId("test-client");
        client.setPublicClient(false);
        client.setSecret("secret");
        client.setServiceAccountsEnabled(true);
        client.setEnabled(true);
        client.setRedirectUris(Arrays.asList("http://url"));

        adminClient.realm(REALM_NAME).clients().create(client);

        // KEYCLOAK-5660, should not consider service accounts
        assertEquals(9, realm.users().count().intValue());
    }

    @Test
    public void delete() {
        String userId = createUser();
        deleteUser(userId);
    }

    @Test
    public void deleteNonExistent() {
        try (Response response = realm.users().delete("does-not-exist")) {
            assertEquals(404, response.getStatus());
        }
    }

    @Test
    public void searchPaginated() {
        createUsers();

        List<UserRepresentation> users = realm.users().search("username", 0, 1);
        assertEquals(1, users.size());
        assertEquals("username1", users.get(0).getUsername());

        users = realm.users().search("username", 5, 2);
        assertEquals(2, users.size());
        assertEquals("username6", users.get(0).getUsername());
        assertEquals("username7", users.get(1).getUsername());

        users = realm.users().search("username", 7, 20);
        assertEquals(2, users.size());
        assertEquals("username8", users.get(0).getUsername());
        assertEquals("username9", users.get(1).getUsername());

        users = realm.users().search("username", 0, 20);
        assertEquals(9, users.size());
    }

    @KeycloakVersion(min = "26.0.0")
    @Test
    public void getFederatedIdentities() {
        // Add sample identity provider
        addSampleIdentityProvider();

        // Add sample user
        String id = createUser();
        UserResource user = realm.users().get(id);
        assertEquals(0, user.getFederatedIdentity().size());

        // Add social link to the user
        FederatedIdentityRepresentation link = new FederatedIdentityRepresentation();
        link.setUserId("social-user-id");
        link.setUserName("social-username");
        addFederatedIdentity(id, "social-provider-id", link);

        // Verify social link is here
        user = realm.users().get(id);
        List<FederatedIdentityRepresentation> federatedIdentities = user.getFederatedIdentity();
        assertEquals(1, federatedIdentities.size());
        link = federatedIdentities.get(0);
        assertEquals("social-provider-id", link.getIdentityProvider());
        assertEquals("social-user-id", link.getUserId());
        assertEquals("social-username", link.getUserName());

        // Remove social link now
        user.removeFederatedIdentity("social-provider-id");
        assertEquals(0, user.getFederatedIdentity().size());

        removeSampleIdentityProvider();
    }

    @Test
    public void addRequiredAction() {
        String id = createUser();

        UserResource user = realm.users().get(id);
        assertTrue(user.toRepresentation().getRequiredActions().isEmpty());

        UserRepresentation userRep = user.toRepresentation();
        userRep.getRequiredActions().add("UPDATE_PASSWORD");
        updateUser(user, userRep);

        assertEquals(1, user.toRepresentation().getRequiredActions().size());
        assertEquals("UPDATE_PASSWORD", user.toRepresentation().getRequiredActions().get(0));
    }

    @Test
    public void removeRequiredAction() {
        String id = createUser();

        UserResource user = realm.users().get(id);
        assertTrue(user.toRepresentation().getRequiredActions().isEmpty());

        UserRepresentation userRep = user.toRepresentation();
        userRep.getRequiredActions().add("UPDATE_PASSWORD");
        updateUser(user, userRep);

        user = realm.users().get(id);
        userRep = user.toRepresentation();
        userRep.getRequiredActions().clear();
        updateUser(user, userRep);

        assertTrue(user.toRepresentation().getRequiredActions().isEmpty());
    }

    @Test
    public void attributes() {
        UserRepresentation user1 = new UserRepresentation();
        user1.setUsername("user1");
        user1.singleAttribute("attr1", "value1user1");
        user1.singleAttribute("attr2", "value2user1");

        String user1Id = createUser(user1);

        UserRepresentation user2 = new UserRepresentation();
        user2.setUsername("user2");
        user2.singleAttribute("attr1", "value1user2");
        List<String> vals = new ArrayList<>();
        vals.add("value2user2");
        vals.add("value2user2_2");
        user2.getAttributes().put("attr2", vals);

        String user2Id = createUser(user2);

        user1 = realm.users().get(user1Id).toRepresentation();
        assertEquals(2, user1.getAttributes().size());
        assertAttributeValue("value1user1", user1.getAttributes().get("attr1"));
        assertAttributeValue("value2user1", user1.getAttributes().get("attr2"));

        user2 = realm.users().get(user2Id).toRepresentation();
        assertEquals(2, user2.getAttributes().size());
        assertAttributeValue("value1user2", user2.getAttributes().get("attr1"));
        vals = user2.getAttributes().get("attr2");
        assertEquals(2, vals.size());
        assertTrue(vals.contains("value2user2") && vals.contains("value2user2_2"));

        user1.singleAttribute("attr1", "value3user1");
        user1.singleAttribute("attr3", "value4user1");

        updateUser(realm.users().get(user1Id), user1);

        user1 = realm.users().get(user1Id).toRepresentation();
        assertEquals(3, user1.getAttributes().size());
        assertAttributeValue("value3user1", user1.getAttributes().get("attr1"));
        assertAttributeValue("value2user1", user1.getAttributes().get("attr2"));
        assertAttributeValue("value4user1", user1.getAttributes().get("attr3"));

        user1.getAttributes().remove("attr1");
        updateUser(realm.users().get(user1Id), user1);

        user1 = realm.users().get(user1Id).toRepresentation();
        assertEquals(2, user1.getAttributes().size());
        assertAttributeValue("value2user1", user1.getAttributes().get("attr2"));
        assertAttributeValue("value4user1", user1.getAttributes().get("attr3"));

        // null attributes should not remove attributes
        user1.setAttributes(null);
        updateUser(realm.users().get(user1Id), user1);
        user1 = realm.users().get(user1Id).toRepresentation();
        assertNotNull(user1.getAttributes());
        assertEquals(2, user1.getAttributes().size());

        // empty attributes should remove attributes
        user1.setAttributes(Collections.emptyMap());
        updateUser(realm.users().get(user1Id), user1);

        user1 = realm.users().get(user1Id).toRepresentation();
        assertNull(user1.getAttributes());

        Map<String, List<String>> attributes = new HashMap<>();

        attributes.put("foo", Arrays.asList("foo"));
        attributes.put("bar", Arrays.asList("bar"));

        user1.setAttributes(attributes);

        realm.users().get(user1Id).update(user1);
        user1 = realm.users().get(user1Id).toRepresentation();
        assertEquals(2, user1.getAttributes().size());

        user1.getAttributes().remove("foo");

        realm.users().get(user1Id).update(user1);
        user1 = realm.users().get(user1Id).toRepresentation();
        assertEquals(1, user1.getAttributes().size());
    }

    private void assertAttributeValue(String expectedValue, List<String> attrValues) {
        assertEquals(1, attrValues.size());
        assertEquals(expectedValue, attrValues.get(0));
    }

    @Test
    public void updateUserWithReadOnlyAttributes() {
        // Admin is able to update "usercertificate" attribute
        UserRepresentation user1 = new UserRepresentation();
        user1.setUsername("user1");
        user1.singleAttribute("usercertificate", "foo1");
        String user1Id = createUser(user1);
        user1 = realm.users().get(user1Id).toRepresentation();

        // Update of the user should be rejected due adding the "denied" attribute LDAP_ID
        try {
            user1.singleAttribute("usercertificate", "foo");
            user1.singleAttribute("saml.persistent.name.id.for.foo", "bar");
            user1.singleAttribute("LDAP_ID", "baz");
            updateUser(realm.users().get(user1Id), user1);
            Assert.fail("Not supposed to successfully update user");
        } catch (BadRequestException expected) {
            // Expected
            ErrorRepresentation error = expected.getResponse().readEntity(ErrorRepresentation.class);
            Assert.assertEquals("updateReadOnlyAttributesRejectedMessage", error.getErrorMessage());
        }

        // The same test as before, but with the case-sensitivity used
        try {
            user1.getAttributes().remove("LDAP_ID");
            user1.singleAttribute("LDap_Id", "baz");
            updateUser(realm.users().get(user1Id), user1);
            Assert.fail("Not supposed to successfully update user");
        } catch (BadRequestException bre) {
            // Expected
        }

        // usercertificate and saml attribute are allowed by admin
        user1.getAttributes().remove("LDap_Id");
        updateUser(realm.users().get(user1Id), user1);
        user1 = realm.users().get(user1Id).toRepresentation();
        assertEquals("foo", user1.getAttributes().get("usercertificate").get(0));
        assertEquals("bar", user1.getAttributes().get("saml.persistent.name.id.for.foo").get(0));
        assertFalse(user1.getAttributes().containsKey("LDAP_ID"));
    }

    @Test
    public void testImportUserWithNullAttribute() {
        RealmRepresentation rep = loadJson(getClass().getResourceAsStream("/import/testrealm-user-null-attr.json"), RealmRepresentation.class);

        try (Creator<RealmResource> c = Creator.create(adminClient, rep)) {
            List<UserRepresentation> users = c.resource().users().list();
            // there should be only one user
            assertThat(users, hasSize(1));
            // test there are only 2 attributes imported from json file, attribute "key3" : [ null ] shoudn't be imported
            assertThat(users.get(0).getAttributes().size(), equalTo(2));
        }
    }

    @Test
    public void sendResetPasswordEmail() {
        UserRepresentation userRep = new UserRepresentation();
        userRep.setUsername("user1");

        String id = createUser(userRep);

        UserResource user = realm.users().get(id);
        List<String> actions = new LinkedList<>();
        try {
            user.executeActionsEmail(actions);
            fail("Expected failure");
        } catch (ClientErrorException e) {
            assertEquals(400, e.getResponse().getStatus());

            ErrorRepresentation error = e.getResponse().readEntity(ErrorRepresentation.class);
            Assert.assertEquals("User email missing", error.getErrorMessage());
        }
        try {
            userRep = user.toRepresentation();
            userRep.setEmail("user1@localhost");
            userRep.setEnabled(false);
            updateUser(user, userRep);

            user.executeActionsEmail(actions);
            fail("Expected failure");
        } catch (ClientErrorException e) {
            assertEquals(400, e.getResponse().getStatus());

            ErrorRepresentation error = e.getResponse().readEntity(ErrorRepresentation.class);
            Assert.assertEquals("User is disabled", error.getErrorMessage());
        }
        try {
            userRep.setEnabled(true);
            updateUser(user, userRep);

            user.executeActionsEmail(Arrays.asList(
                    "UPDATE_PASSWORD",
                    "invalid\"<img src=\"alert(0)\">")
            );
            fail("Expected failure");
        } catch (ClientErrorException e) {
            assertEquals(400, e.getResponse().getStatus());

            ErrorRepresentation error = e.getResponse().readEntity(ErrorRepresentation.class);
            Assert.assertEquals("Provided invalid required actions", error.getErrorMessage());
        }

        try {
            user.executeActionsEmail(
                    "invalidClientId",
                    "invalidUri",
                    Collections.singletonList("UPDATE_PASSWORD")
            );
            fail("Expected failure");
        } catch (ClientErrorException e) {
            assertEquals(400, e.getResponse().getStatus());

            ErrorRepresentation error = e.getResponse().readEntity(ErrorRepresentation.class);
            Assert.assertEquals("Client doesn't exist", error.getErrorMessage());
        }
    }

    @Test
    public void updateUserWithoutUsername() {
        switchEditUsernameAllowedOn(true);
        getCleanup().addCleanup(() -> switchEditUsernameAllowedOn(false));

        String id = createUser();

        UserResource user = realm.users().get(id);

        UserRepresentation rep = new UserRepresentation();
        rep.setFirstName("Firstname");

        user.update(rep);

        rep = new UserRepresentation();
        rep.setLastName("Lastname");

        user.update(rep);

        rep = realm.users().get(id).toRepresentation();

        assertEquals("user1", rep.getUsername());
        assertEquals("user1@localhost", rep.getEmail());
        assertEquals("Firstname", rep.getFirstName());
        assertEquals("Lastname", rep.getLastName());
    }

    @Test
    public void updateUserWithEmailAsUsernameEditUsernameDisabled() {
        switchRegistrationEmailAsUsername(true);
        getCleanup().addCleanup(() -> switchRegistrationEmailAsUsername(false));
        RealmRepresentation rep = realm.toRepresentation();
        assertFalse(rep.isEditUsernameAllowed());
        String id = createUser();

        UserResource user = realm.users().get(id);
        UserRepresentation userRep = user.toRepresentation();
        assertEquals("user1@localhost", userRep.getUsername());

        userRep.setEmail("user11@localhost");
        updateUser(user, userRep);

        userRep = realm.users().get(id).toRepresentation();
        assertEquals("user11@localhost", userRep.getUsername());
        assertEquals("user11@localhost", userRep.getEmail());
    }

    @Test
    public void updateUserWithEmailAsUsernameEditUsernameAllowed() {
        switchRegistrationEmailAsUsername(true);
        getCleanup().addCleanup(() -> switchRegistrationEmailAsUsername(false));
        switchEditUsernameAllowedOn(true);
        getCleanup().addCleanup(() -> switchEditUsernameAllowedOn(false));

        String id = createUser();
        UserResource user = realm.users().get(id);
        UserRepresentation userRep = user.toRepresentation();
        assertEquals("user1@localhost", userRep.getUsername());

        userRep.setEmail("user11@localhost");
        updateUser(user, userRep);

        userRep = realm.users().get(id).toRepresentation();
        assertEquals("user11@localhost", userRep.getUsername());
        assertEquals("user11@localhost", userRep.getEmail());
    }

    @Test
    public void updateUserWithExistingEmail() {
        final String userId = createUser();
        assertNotNull(userId);
        assertNotNull(createUser("user2", "user2@localhost"));

        UserResource user = realm.users().get(userId);
        UserRepresentation userRep = user.toRepresentation();
        assertNotNull(userRep);
        userRep.setEmail("user2@localhost");

        try {
            updateUser(user, userRep);
            fail("Expected failure - Email conflict");
        } catch (ClientErrorException e) {
            assertNotNull(e.getResponse());
            assertThat(e.getResponse().getStatus(), is(409));

            ErrorRepresentation error = e.getResponse().readEntity(ErrorRepresentation.class);
            Assert.assertEquals("User exists with same email", error.getErrorMessage());
        }
    }

    @Test
    public void testKeepRootAttributeWhenOtherAttributesAreSet() {
        String random = UUID.randomUUID().toString();
        String userName = String.format("username-%s", random);
        String email = String.format("my@mail-%s.com", random);
        UserRepresentation user = new UserRepresentation();
        user.setUsername(userName);
        user.setEmail(email);
        String userId = createUser(user);

        UserRepresentation created = realm.users().get(userId).toRepresentation();
        assertThat(created.getEmail(), equalTo(email));
        assertThat(created.getUsername(), equalTo(userName));
        assertThat(created.getAttributes(), nullValue());

        UserRepresentation update = new UserRepresentation();
        update.setId(userId);
        // user profile requires sending all attributes otherwise they are removed
        update.setEmail(email);

        Map<String, List<String>> map = new HashMap<>();
        map.put("phoneNumber", Arrays.asList("123"));
        update.setAttributes(map);
        updateUser(realm.users().get(userId), update);

        UserRepresentation updated = realm.users().get(userId).toRepresentation();
        assertThat(updated.getUsername(), equalTo(userName));
        assertThat(updated.getAttributes().get("phoneNumber"), equalTo(Arrays.asList("123")));

        assertThat(updated.getEmail(), equalTo(email));
    }

    @Test
    public void updateUserWithNewUsernameNotPossible() {
        RealmRepresentation realmRep = realm.toRepresentation();
        assertFalse(realmRep.isEditUsernameAllowed());
        String id = createUser();

        UserResource user = realm.users().get(id);
        UserRepresentation userRep = user.toRepresentation();
        userRep.setUsername("user11");

        try {
            updateUser(user, userRep);
            fail("Should fail because realm does not allow edit username");
        } catch (BadRequestException expected) {
            ErrorRepresentation error = expected.getResponse().readEntity(ErrorRepresentation.class);
            assertEquals("error-user-attribute-read-only", error.getErrorMessage());
        }

        userRep = realm.users().get(id).toRepresentation();
        assertEquals("user1", userRep.getUsername());
    }

    @Test
    public void updateUserWithNewUsernameAccessingViaOldUsername() {
        switchEditUsernameAllowedOn(true);
        createUser();

        try {
            UserResource user = realm.users().get("user1");
            UserRepresentation userRep = user.toRepresentation();
            userRep.setUsername("user1");
            updateUser(user, userRep);

            realm.users().get("user11").toRepresentation();
            fail("Expected failure");
        } catch (ClientErrorException e) {
            assertEquals(404, e.getResponse().getStatus());
        } finally {
            switchEditUsernameAllowedOn(false);
        }
    }

    @Test
    public void updateUserWithExistingUsername() {
        switchEditUsernameAllowedOn(true);
        enableBruteForce(true);
        createUser();

        UserRepresentation userRep = new UserRepresentation();
        userRep.setUsername("user2");

        String createdId = createUser(userRep);

        try {
            UserResource user = realm.users().get(createdId);
            userRep = user.toRepresentation();
            userRep.setUsername("user1");
            user.update(userRep);
            fail("Expected failure");
        } catch (ClientErrorException e) {
            assertEquals(409, e.getResponse().getStatus());
        } finally {
            enableBruteForce(false);
            switchEditUsernameAllowedOn(false);
        }
    }

    @Test
    public void resetUserInvalidPassword() {
        String userId = createUser("user1", "user1@localhost");

        try {
            CredentialRepresentation cred = new CredentialRepresentation();
            cred.setType(CredentialRepresentation.PASSWORD);
            cred.setValue(" ");
            cred.setTemporary(false);
            realm.users().get(userId).resetPassword(cred);
            fail("Expected failure");
        } catch (ClientErrorException e) {
            assertEquals(400, e.getResponse().getStatus());
            e.getResponse().close();
        }
    }

    @Test
    public void testDefaultRequiredActionAdded() {
        // Add UPDATE_PASSWORD as default required action
        RequiredActionProviderRepresentation updatePasswordReqAction = realm.flows().getRequiredAction("UPDATE_PASSWORD");
        updatePasswordReqAction.setDefaultAction(true);
        realm.flows().updateRequiredAction("UPDATE_PASSWORD", updatePasswordReqAction);

        // Create user
        String userId = createUser("user1", "user1@localhost");

        UserRepresentation userRep = realm.users().get(userId).toRepresentation();
        Assert.assertEquals(1, userRep.getRequiredActions().size());
        Assert.assertEquals("UPDATE_PASSWORD", userRep.getRequiredActions().get(0));

        // Remove UPDATE_PASSWORD default action
        updatePasswordReqAction = realm.flows().getRequiredAction("UPDATE_PASSWORD");
        updatePasswordReqAction.setDefaultAction(false);
        realm.flows().updateRequiredAction("UPDATE_PASSWORD", updatePasswordReqAction);
    }

    @Test
    public void roleMappings() {
        RealmResource realm = adminClient.realms().realm("test");
        String realmId = realm.toRepresentation().getId();

        // Enable events
        RealmRepresentation realmRep = realm.toRepresentation();
        realm.update(realmRep);

        RoleRepresentation realmCompositeRole = RoleBuilder.create().name("realm-composite").singleAttribute("attribute1", "value1").build();

        realm.roles().create(RoleBuilder.create().name("realm-role").build());
        realm.roles().create(realmCompositeRole);

        realm.roles().create(RoleBuilder.create().name("realm-child").build());
        realm.roles().get("realm-composite").addComposites(Collections.singletonList(realm.roles().get("realm-child").toRepresentation()));
        getCleanup("test").addRoleId(realm.roles().get(realmCompositeRole.getName()).toRepresentation().getId());
        getCleanup("test").addRoleId(realm.roles().get("realm-child").toRepresentation().getId());
        getCleanup("test").addRoleId(realm.roles().get("realm-role").toRepresentation().getId());

        final String clientUuid;
        try (Response response = realm.clients().create(ClientBuilder.create().clientId("myclient").build())) {
            clientUuid = ApiUtil.getCreatedId(response);
            getCleanup("test").addClientUuid(clientUuid);
        }

        RoleRepresentation clientCompositeRole = RoleBuilder.create().name("client-composite").singleAttribute("attribute1", "value1").build();


        realm.clients().get(clientUuid).roles().create(RoleBuilder.create().name("client-role").build());
        realm.clients().get(clientUuid).roles().create(RoleBuilder.create().name("client-role2").build());
        realm.clients().get(clientUuid).roles().create(clientCompositeRole);
        realm.clients().get(clientUuid).roles().create(RoleBuilder.create().name("client-child").build());
        realm.clients().get(clientUuid).roles().get("client-composite").addComposites(Collections.singletonList(realm.clients().get(clientUuid).roles().get("client-child").toRepresentation()));

        final String userId;
        try (Response response = realm.users().create(UserBuilder.create().username("myuser").build())) {
            userId = ApiUtil.getCreatedId(response);
            getCleanup("test").addUserId(userId);
        }

        RoleMappingResource roles = realm.users().get(userId).roles();
        assertNames(roles.realmLevel().listAll(), Constants.DEFAULT_ROLES_ROLE_PREFIX + "-test");
        assertNames(roles.realmLevel().listEffective(), "user", "offline_access", Constants.AUTHZ_UMA_AUTHORIZATION, Constants.DEFAULT_ROLES_ROLE_PREFIX + "-test");

        // Add realm roles
        List<RoleRepresentation> l = new LinkedList<>();
        l.add(realm.roles().get("realm-role").toRepresentation());
        l.add(realm.roles().get("realm-composite").toRepresentation());
        roles.realmLevel().add(l);

        // Add client roles
        List<RoleRepresentation> list = Collections.singletonList(realm.clients().get(clientUuid).roles().get("client-role").toRepresentation());
        roles.clientLevel(clientUuid).add(list);

        list = Collections.singletonList(realm.clients().get(clientUuid).roles().get("client-composite").toRepresentation());
        roles.clientLevel(clientUuid).add(list);

        // List realm roles
        assertNames(roles.realmLevel().listAll(), "realm-role", "realm-composite", Constants.DEFAULT_ROLES_ROLE_PREFIX + "-test");
        assertNames(roles.realmLevel().listAvailable(), "realm-child", "admin", "customer-user-premium", "realm-composite-role", "sample-realm-role", "attribute-role", "user", "offline_access", Constants.AUTHZ_UMA_AUTHORIZATION);
        assertNames(roles.realmLevel().listEffective(), "realm-role", "realm-composite", "realm-child", "user", "offline_access", Constants.AUTHZ_UMA_AUTHORIZATION, Constants.DEFAULT_ROLES_ROLE_PREFIX + "-test");

        // List realm effective role with full representation
        List<RoleRepresentation> realmRolesFullRepresentations = roles.realmLevel().listEffective(false);
        RoleRepresentation realmCompositeRoleFromList = getRoleByName("realm-composite", realmRolesFullRepresentations);
        assertNotNull(realmCompositeRoleFromList);
        assertTrue(realmCompositeRoleFromList.getAttributes().containsKey("attribute1"));

        // List client roles
        assertNames(roles.clientLevel(clientUuid).listAll(), "client-role", "client-composite");
        assertNames(roles.clientLevel(clientUuid).listAvailable(), "client-role2", "client-child");
        assertNames(roles.clientLevel(clientUuid).listEffective(), "client-role", "client-composite", "client-child");

        // List client effective role with full representation
        List<RoleRepresentation> rolesFullRepresentations = roles.clientLevel(clientUuid).listEffective(false);
        RoleRepresentation clientCompositeRoleFromList = getRoleByName("client-composite", rolesFullRepresentations);
        assertNotNull(clientCompositeRoleFromList);
        assertTrue(clientCompositeRoleFromList.getAttributes().containsKey("attribute1"));

        // Get mapping representation
        MappingsRepresentation all = roles.getAll();
        assertNames(all.getRealmMappings(), "realm-role", "realm-composite", Constants.DEFAULT_ROLES_ROLE_PREFIX + "-test");
        assertEquals(1, all.getClientMappings().size());
        assertNames(all.getClientMappings().get("myclient").getMappings(), "client-role", "client-composite");

        // Remove realm role
        RoleRepresentation realmRoleRep = realm.roles().get("realm-role").toRepresentation();
        roles.realmLevel().remove(Collections.singletonList(realmRoleRep));

        assertNames(roles.realmLevel().listAll(), "realm-composite", Constants.DEFAULT_ROLES_ROLE_PREFIX + "-test");

        // Remove client role
        RoleRepresentation clientRoleRep = realm.clients().get(clientUuid).roles().get("client-role").toRepresentation();
        roles.clientLevel(clientUuid).remove(Collections.singletonList(clientRoleRep));

        assertNames(roles.clientLevel(clientUuid).listAll(), "client-composite");
    }

    private RoleRepresentation getRoleByName(String name, List<RoleRepresentation> roles) {
        for(RoleRepresentation role : roles) {
            if(role.getName().equalsIgnoreCase(name)) {
                return role;
            }
        }

        return null;
    }

    /**
     * Test for KEYCLOAK-10603.
     */
    @Test
    public void rolesCanBeAssignedEvenWhenTheyAreAlreadyIndirectlyAssigned() {
        RealmResource realm = adminClient.realms().realm("test");

        RoleRepresentation realmCompositeRole = RoleBuilder.create().name("realm-composite").build();
        realm.roles().create(realmCompositeRole);
        realm.roles().create(RoleBuilder.create().name("realm-child").build());
        realm.roles().get("realm-composite")
                .addComposites(Collections.singletonList(realm.roles().get("realm-child").toRepresentation()));
        realm.roles().create(RoleBuilder.create().name("realm-role-in-group").build());
        getCleanup("test").addRoleId(realm.roles().get(realmCompositeRole.getName()).toRepresentation().getId());
        getCleanup("test").addRoleId(realm.roles().get("realm-child").toRepresentation().getId());

        Response response = realm.clients().create(ClientBuilder.create().clientId("myclient").build());
        String clientUuid = ApiUtil.getCreatedId(response);
        getCleanup("test").addClientUuid(clientUuid);
        response.close();

        RoleRepresentation clientCompositeRole = RoleBuilder.create().name("client-composite").build();
        realm.clients().get(clientUuid).roles().create(clientCompositeRole);
        realm.clients().get(clientUuid).roles().create(RoleBuilder.create().name("client-child").build());
        realm.clients().get(clientUuid).roles().get("client-composite").addComposites(Collections
                .singletonList(realm.clients().get(clientUuid).roles().get("client-child").toRepresentation()));
        realm.clients().get(clientUuid).roles().create(RoleBuilder.create().name("client-role-in-group").build());

        GroupRepresentation group = GroupBuilder.create().name("mygroup").build();
        response = realm.groups().add(group);
        String groupId = ApiUtil.getCreatedId(response);
        response.close();

        response = realm.users().create(UserBuilder.create().username("myuser").build());
        String userId = ApiUtil.getCreatedId(response);
        getCleanup("test").addUserId(userId);
        response.close();

        // Make indirect assignments
        // .. add roles to the group and add it to the user
        realm.groups().group(groupId).roles().realmLevel()
                .add(Collections.singletonList(realm.roles().get("realm-role-in-group").toRepresentation()));
        realm.groups().group(groupId).roles().clientLevel(clientUuid).add(Collections
                .singletonList(realm.clients().get(clientUuid).roles().get("client-role-in-group").toRepresentation()));
        realm.users().get(userId).joinGroup(groupId);
        // .. assign composite roles
        RoleMappingResource userRoles = realm.users().get(userId).roles();
        userRoles.realmLevel().add(Collections.singletonList(realm.roles().get("realm-composite").toRepresentation()));
        userRoles.clientLevel(clientUuid).add(Collections
                .singletonList(realm.clients().get(clientUuid).roles().get("client-composite").toRepresentation()));

        // check state before making the direct assignments
        assertNames(userRoles.realmLevel().listAll(), "realm-composite", Constants.DEFAULT_ROLES_ROLE_PREFIX + "-test");
        assertNames(userRoles.realmLevel().listAvailable(), "realm-child", "realm-role-in-group",
                "admin", "customer-user-premium", "realm-composite-role",
                "sample-realm-role",
                "attribute-role", "user", "offline_access", Constants.AUTHZ_UMA_AUTHORIZATION);
        assertNames(userRoles.realmLevel().listEffective(), "realm-composite", "realm-child", "realm-role-in-group",
                "user", "offline_access", Constants.AUTHZ_UMA_AUTHORIZATION,
                Constants.DEFAULT_ROLES_ROLE_PREFIX + "-test");

        assertNames(userRoles.clientLevel(clientUuid).listAll(), "client-composite");
        assertNames(userRoles.clientLevel(clientUuid).listAvailable(), "client-child",
                "client-role-in-group");
        assertNames(userRoles.clientLevel(clientUuid).listEffective(), "client-composite", "client-child",
                "client-role-in-group");

        // Make direct assignments for roles which are already indirectly assigned
        userRoles.realmLevel().add(Collections.singletonList(realm.roles().get("realm-child").toRepresentation()));
        userRoles.realmLevel()
                .add(Collections.singletonList(realm.roles().get("realm-role-in-group").toRepresentation()));
        userRoles.clientLevel(clientUuid).add(Collections
                .singletonList(realm.clients().get(clientUuid).roles().get("client-child").toRepresentation()));
        userRoles.clientLevel(clientUuid).add(Collections
                .singletonList(realm.clients().get(clientUuid).roles().get("client-role-in-group").toRepresentation()));

        // List realm roles
        assertNames(userRoles.realmLevel().listAll(), "realm-composite",
                "realm-child", "realm-role-in-group", Constants.DEFAULT_ROLES_ROLE_PREFIX + "-test");
        assertNames(userRoles.realmLevel().listAvailable(), "admin", "customer-user-premium", "realm-composite-role",
                "sample-realm-role", "attribute-role", "user", "offline_access", Constants.AUTHZ_UMA_AUTHORIZATION);
        assertNames(userRoles.realmLevel().listEffective(), "realm-composite", "realm-child", "realm-role-in-group",
                "user", "offline_access", Constants.AUTHZ_UMA_AUTHORIZATION,
                Constants.DEFAULT_ROLES_ROLE_PREFIX + "-test");

        // List client roles
        assertNames(userRoles.clientLevel(clientUuid).listAll(), "client-composite", "client-child",
                "client-role-in-group");
        assertNames(userRoles.clientLevel(clientUuid).listAvailable());
        assertNames(userRoles.clientLevel(clientUuid).listEffective(), "client-composite", "client-child",
                "client-role-in-group");

        // Get mapping representation
        MappingsRepresentation all = userRoles.getAll();
        assertNames(all.getRealmMappings(), "realm-composite",
                "realm-child", "realm-role-in-group", Constants.DEFAULT_ROLES_ROLE_PREFIX + "-test");
        assertEquals(1, all.getClientMappings().size());
        assertNames(all.getClientMappings().get("myclient").getMappings(), "client-composite", "client-child",
                "client-role-in-group");
    }

    @Test
    public void defaultMaxResults() {
        UserProfileResource upResource = adminClient.realm("test").users().userProfile();
        UPConfig upConfig = upResource.getConfiguration();
        upConfig.addOrReplaceAttribute(createAttributeMetadata("aName"));
        upResource.update(upConfig);

        try {
            UsersResource users = adminClient.realms().realm("test").users();

            for (int i = 0; i < 110; i++) {
                users.create(UserBuilder.create().username("test-" + i).addAttribute("aName", "aValue").build()).close();
            }

            List<UserRepresentation> result = users.search("test", null, null);
            assertEquals(100, result.size());
            for (UserRepresentation user : result) {
                assertThat(user.getAttributes(), notNullValue());
                assertThat(user.getAttributes().keySet(), hasSize(1));
                assertThat(user.getAttributes(), hasEntry(is("aName"), contains("aValue")));
            }

            assertEquals(105, users.search("test", 0, 105).size());
            assertEquals(111, users.search("test", 0, 1000).size());
        } finally {
            upConfig.removeAttribute("aName");
            upResource.update(upConfig);
        }
    }

    @Test
    public void defaultMaxResultsBrief() {
        UserProfileResource upResource = adminClient.realm("test").users().userProfile();
        UPConfig upConfig = upResource.getConfiguration();
        upConfig.addOrReplaceAttribute(createAttributeMetadata("aName"));
        upResource.update(upConfig);

        try {
            UsersResource users = adminClient.realms().realm("test").users();

            for (int i = 0; i < 110; i++) {
                users.create(UserBuilder.create().username("test-" + i).addAttribute("aName", "aValue").build()).close();
            }

            List<UserRepresentation> result = users.search("test", null, null, true);
            assertEquals(100, result.size());
            for (UserRepresentation user : result) {
                assertThat(user.getAttributes(), nullValue());
            }
        } finally {
            upConfig.removeAttribute("aName");
            upResource.update(upConfig);
        }
    }

    @Test
    public void testAccessUserFromOtherRealm() {
        RealmRepresentation firstRealm = new RealmRepresentation();

        firstRealm.setRealm("first-realm");

        adminClient.realms().create(firstRealm);
        getCleanup().addCleanup(new AutoCloseable() {
            @Override
            public void close() throws Exception {
                adminClient.realms().realm(firstRealm.getRealm()).remove();
            }
        });

        realm = adminClient.realm(firstRealm.getRealm());
        realmId = realm.toRepresentation().getId();

        UserRepresentation firstUser = new UserRepresentation();

        firstUser.setUsername("first");
        firstUser.setEmail("first@first-realm.org");

        firstUser.setId(createUser(firstUser, false));

        RealmRepresentation secondRealm = new RealmRepresentation();

        secondRealm.setRealm("second-realm");

        adminClient.realms().create(secondRealm);

        adminClient.realm(firstRealm.getRealm()).users().get(firstUser.getId()).update(firstUser);

        try {
            adminClient.realm(secondRealm.getRealm()).users().get(firstUser.getId()).toRepresentation();
            fail("Should not have access to firstUser from another realm");
        } catch (NotFoundException nfe) {
            // ignore
        } finally {
            adminClient.realm(secondRealm.getRealm()).remove();
        }
    }

    @Test
    public void testGetAndMoveCredentials() {

        UserResource user = ApiUtil.findUserByUsernameId(testRealm(), "user-with-two-configured-otp");
        List<CredentialRepresentation> creds = user.credentials();
        List<String> expectedCredIds = Arrays.asList(creds.get(0).getId(), creds.get(1).getId(), creds.get(2).getId());

        // Check actual user credentials
        assertSameIds(expectedCredIds, user.credentials());

        // Move first credential after second one
        user.moveCredentialAfter(expectedCredIds.get(0), expectedCredIds.get(1));
        List<String> newOrderCredIds = Arrays.asList(expectedCredIds.get(1), expectedCredIds.get(0), expectedCredIds.get(2));
        assertSameIds(newOrderCredIds, user.credentials());

        // Move last credential in first position
        user.moveCredentialToFirst(expectedCredIds.get(2));
        newOrderCredIds = Arrays.asList(expectedCredIds.get(2), expectedCredIds.get(1), expectedCredIds.get(0));
        assertSameIds(newOrderCredIds, user.credentials());

        // Restore initial state
        user.moveCredentialToFirst(expectedCredIds.get(1));
        user.moveCredentialToFirst(expectedCredIds.get(0));
        assertSameIds(expectedCredIds, user.credentials());
    }

    private void assertSameIds(List<String> expectedIds, List<CredentialRepresentation> actual) {
        Assert.assertEquals(expectedIds.size(), actual.size());
        for (int i = 0; i < expectedIds.size(); i++) {
            Assert.assertEquals(expectedIds.get(i), actual.get(i).getId());
        }
    }

    @Test
    public void testUpdateCredentials() {

        // Get user user-with-one-configured-otp and assert he has no label linked to its OTP credential
        UserResource user = ApiUtil.findUserByUsernameId(adminClient.realm("test"), "user-with-one-configured-otp");
        CredentialRepresentation otpCred = user.credentials().get(0);
        Assert.assertNull(otpCred.getUserLabel());

        // Set and check a new label
        String newLabel = "the label";
        user.setCredentialUserLabel(otpCred.getId(), newLabel);
        Assert.assertEquals(newLabel, user.credentials().get(0).getUserLabel());
    }

    @Test
    public void testDeleteCredentials() {
        UserResource user = ApiUtil.findUserByUsernameId(testRealm(), "john-doh@localhost");
        List<CredentialRepresentation> creds = user.credentials();
        Assert.assertEquals(1, creds.size());
        CredentialRepresentation credPasswd = creds.get(0);
        Assert.assertEquals("password", credPasswd.getType());

        // Remove password
        user.removeCredential(credPasswd.getId());
        Assert.assertEquals(0, user.credentials().size());

        // Restore password
        credPasswd.setValue("password");
        user.resetPassword(credPasswd);
        Assert.assertEquals(1, user.credentials().size());
    }

    @Test
    public void testCRUDCredentialsOfDifferentUser() {
        // Get credential ID of the OTP credential of the user1
        UserResource user1 = ApiUtil.findUserByUsernameId(testRealm(), "user-with-one-configured-otp");
        CredentialRepresentation otpCredential = user1.credentials().stream()
                .filter(credentialRep -> "otp".equals(credentialRep.getType()))
                .findFirst()
                .get();

        // Test that when admin operates on user "user2", he can't update, move or remove credentials of different user "user1"
        UserResource user2 = ApiUtil.findUserByUsernameId(testRealm(), "test-user@localhost");
        try {
            user2.setCredentialUserLabel(otpCredential.getId(), "new-label");
            Assert.fail("Not expected to successfully update user label");
        } catch (NotFoundException nfe) {
            // Expected
        }

        try {
            user2.moveCredentialToFirst(otpCredential.getId());
            Assert.fail("Not expected to successfully move credential");
        } catch (NotFoundException nfe) {
            // Expected
        }

        try {
            user2.removeCredential(otpCredential.getId());
            Assert.fail("Not expected to successfully remove credential");
        } catch (NotFoundException nfe) {
            // Expected
        }

        // Assert credential was not removed or updated
        CredentialRepresentation otpCredentialLoaded = user1.credentials().stream()
                .filter(credentialRep -> "otp".equals(credentialRep.getType()))
                .findFirst()
                .get();
        Assert.assertTrue(ObjectUtil.isEqualOrBothNull(otpCredential.getUserLabel(), otpCredentialLoaded.getUserLabel()));
        Assert.assertTrue(ObjectUtil.isEqualOrBothNull(otpCredential.getPriority(), otpCredentialLoaded.getPriority()));
    }

    @Test
    public void testGetGroupsForUserFullRepresentation() {
        RealmResource realm = adminClient.realms().realm("test");

        String userName = "averagejoe";
        String groupName = "groupWithAttribute";
        Map<String, List<String>> attributes = new HashMap<String, List<String>>();
        attributes.put("attribute1", Arrays.asList("attribute1","attribute2"));

        UserRepresentation userRepresentation = UserBuilder
                .edit(createUserRepresentation(userName, "joe@average.com", "average", "joe", true))
                .addPassword("password")
                .build();

        try (Creator<UserResource> u = Creator.create(realm, userRepresentation);
             Creator<GroupResource> g = Creator.create(realm, GroupBuilder.create().name(groupName).attributes(attributes).build())) {

            String groupId = g.id();
            UserResource user = u.resource();
            user.joinGroup(groupId);

            List<GroupRepresentation> userGroups = user.groups(0, 100, false);

            assertFalse(userGroups.isEmpty());
            assertTrue(userGroups.get(0).getAttributes().containsKey("attribute1"));
        }
    }

    @Test
    public void testGetSearchedGroupsForUserFullRepresentation() {
        RealmResource realm = adminClient.realms().realm("test");

        String userName = "averagejoe";
        String groupName1 = "group1WithAttribute";
        String groupName2 = "group2WithAttribute";
        Map<String, List<String>> attributes1 = new HashMap<String, List<String>>();
        attributes1.put("attribute1", Arrays.asList("attribute1"));
        Map<String, List<String>> attributes2 = new HashMap<String, List<String>>();
        attributes2.put("attribute2", Arrays.asList("attribute2"));

        UserRepresentation userRepresentation = UserBuilder
                .edit(createUserRepresentation(userName, "joe@average.com", "average", "joe", true))
                .addPassword("password")
                .build();

        try (Creator<UserResource> u = Creator.create(realm, userRepresentation);
             Creator<GroupResource> g1 = Creator.create(realm, GroupBuilder.create().name(groupName1).attributes(attributes1).build());
             Creator<GroupResource> g2 = Creator.create(realm, GroupBuilder.create().name(groupName2).attributes(attributes2).build())) {

            String group1Id = g1.id();
            String group2Id = g2.id();
            UserResource user = u.resource();
            user.joinGroup(group1Id);
            user.joinGroup(group2Id);

            List<GroupRepresentation> userGroups = user.groups("group2", false);
            assertFalse(userGroups.isEmpty());
            assertTrue(userGroups.stream().collect(Collectors.toMap(GroupRepresentation::getName, Function.identity())).get(groupName2).getAttributes().containsKey("attribute2"));

            userGroups = user.groups("group3", false);
            assertTrue(userGroups.isEmpty());
        }
    }

    @Test
    public void groupMembershipPaginated() {
        String userId = createUser(UserBuilder.create().username("user-a").build());

        for (int i = 1; i <= 10; i++) {
            GroupRepresentation group = new GroupRepresentation();
            group.setName("group-" + i);
            String groupId = createGroup(realm, group).getId();
            realm.users().get(userId).joinGroup(groupId);
        }

        List<GroupRepresentation> groups = realm.users().get(userId).groups(5, 6);
        assertEquals(groups.size(), 5);
        assertNames(groups, "group-5","group-6","group-7","group-8","group-9");
    }

    @Test
    public void groupMembershipSearch() {
        String userId = createUser(UserBuilder.create().username("user-b").build());

        for (int i = 1; i <= 10; i++) {
            GroupRepresentation group = new GroupRepresentation();
            group.setName("group-" + i);
            String groupId = createGroup(realm, group).getId();
            realm.users().get(userId).joinGroup(groupId);
        }

        List<GroupRepresentation> groups = realm.users().get(userId).groups("-3", 0, 10);
        assertThat(realm.users().get(userId).groupsCount("-3").get("count"), is(1L));
        assertEquals(1, groups.size());
        assertNames(groups, "group-3");

        List<GroupRepresentation> groups2 = realm.users().get(userId).groups("1", 0, 10);
        assertThat(realm.users().get(userId).groupsCount("1").get("count"), is(2L));
        assertEquals(2, groups2.size());
        assertNames(groups2, "group-1", "group-10");

        List<GroupRepresentation> groups3 = realm.users().get(userId).groups("1", 2, 10);
        assertEquals(0, groups3.size());

        List<GroupRepresentation> groups4 = realm.users().get(userId).groups("gr", 2, 10);
        assertThat(realm.users().get(userId).groupsCount("gr").get("count"), is(10L));
        assertEquals(8, groups4.size());

        List<GroupRepresentation> groups5 = realm.users().get(userId).groups("Gr", 2, 10);
        assertEquals(8, groups5.size());
    }

    @KeycloakVersion(min = "26.0.0")
    @Test
    public void createFederatedIdentities() {
        String identityProviderAlias = "social-provider-id";
        String username = "federated-identities";
        String federatedUserId = "federated-user-id";

        addSampleIdentityProvider();

        UserRepresentation build = UserBuilder.create()
                .username(username)
                .federatedLink(identityProviderAlias, federatedUserId)
                .build();

        //when
        String userId = createUser(build, false);
        List<FederatedIdentityRepresentation> obtainedFederatedIdentities = realm.users().get(userId).getFederatedIdentity();

        //then
        assertEquals(1, obtainedFederatedIdentities.size());
        assertEquals(federatedUserId, obtainedFederatedIdentities.get(0).getUserId());
        assertEquals(username, obtainedFederatedIdentities.get(0).getUserName());
        assertEquals(identityProviderAlias, obtainedFederatedIdentities.get(0).getIdentityProvider());
    }

    @Test
    public void createUserWithGroups() {
        String username = "user-with-groups";
        String groupToBeAdded = "test-group";

        createGroup(realm, GroupBuilder.create().name(groupToBeAdded).build());

        UserRepresentation build = UserBuilder.create()
                .username(username)
                .addGroups(groupToBeAdded)
                .build();

        //when
        String userId = createUser(build);
        List<GroupRepresentation> obtainedGroups = realm.users().get(userId).groups();

        //then
        assertEquals(1, obtainedGroups.size());
        assertEquals(groupToBeAdded, obtainedGroups.get(0).getName());
    }

    private GroupRepresentation createGroup(RealmResource realm, GroupRepresentation group) {
        final String groupId;
        try (Response response = realm.groups().add(group)) {
            groupId = ApiUtil.getCreatedId(response);
            getCleanup().addGroupId(groupId);
        }


        // Set ID to the original rep
        group.setId(groupId);
        return group;
    }

    @Test
    public void failCreateUserUsingRegularUser() throws Exception {
        String regularUserId = ApiUtil.getCreatedId(
                testRealm().users().create(UserBuilder.create().username("regular-user").password("password").build()));
        UserResource regularUser = testRealm().users().get(regularUserId);
        UserRepresentation regularUserRep = regularUser.toRepresentation();

        try (Keycloak adminClient = AdminClientUtil.createAdminClient(true,
                "test", regularUserRep.getUsername(), "password", Constants.ADMIN_CLI_CLIENT_ID, null)) {
            UserRepresentation invalidUser = UserBuilder.create().username("do-not-create-me").build();

            Response response = adminClient.realm("test").users().create(invalidUser);
            assertEquals(Response.Status.FORBIDDEN.getStatusCode(), response.getStatus());

            invalidUser.setGroups(Collections.emptyList());
            response = adminClient.realm("test").users().create(invalidUser);

            assertEquals(Response.Status.FORBIDDEN.getStatusCode(), response.getStatus());
        }
    }

    @Test
    public void testCreateUserDoNotGrantRole() {
        testRealm().roles().create(RoleBuilder.create().name("realm-role").build());

        try {
            UserRepresentation userRep = UserBuilder.create().username("alice").password("password").addRoles("realm-role")
                    .build();
            String userId = ApiUtil.getCreatedId(testRealm().users().create(userRep));
            UserResource user = testRealm().users().get(userId);
            List<RoleRepresentation> realmMappings = user.roles().getAll().getRealmMappings();

            assertFalse(realmMappings.stream().map(RoleRepresentation::getName).anyMatch("realm-role"::equals));
        } finally {
            testRealm().roles().get("realm-role").remove();
        }
    }

    /**
     * Test for #9482
     */
    @Test
    public void joinParentGroupAfterSubGroup() {
        String username = "user-with-sub-and-parent-group";
        String parentGroupName = "parent-group";
        String subGroupName = "sub-group";

        UserRepresentation userRepresentation = UserBuilder.create().username(username).build();

        GroupRepresentation subGroupRep = GroupBuilder.create().name(subGroupName).build();
        GroupRepresentation parentGroupRep = GroupBuilder.create().name(parentGroupName).subGroups(Arrays.asList(subGroupRep)).build();

        try (Creator<UserResource> u = Creator.create(realm, userRepresentation);
             Creator<GroupResource> subgroup = Creator.create(realm, subGroupRep);
             Creator<GroupResource> parentGroup = Creator.create(realm, parentGroupRep)) {

            UserResource user = u.resource();

            //when
            user.joinGroup(subgroup.id());
            List<GroupRepresentation> obtainedGroups = realm.users().get(u.id()).groups();

            //then
            assertEquals(1, obtainedGroups.size());
            assertEquals(subGroupName, obtainedGroups.get(0).getName());

            //when
            user.joinGroup(parentGroup.id());
            obtainedGroups = realm.users().get(u.id()).groups();

            //then
            assertEquals(2, obtainedGroups.size());
            assertEquals(parentGroupName, obtainedGroups.get(0).getName());
            assertEquals(subGroupName, obtainedGroups.get(1).getName());
        }
    }

    @Test
    public void joinSubGroupAfterParentGroup() {
        String username = "user-with-sub-and-parent-group";
        String parentGroupName = "parent-group";
        String subGroupName = "sub-group";

        UserRepresentation userRepresentation = UserBuilder.create().username(username).build();
        GroupRepresentation subGroupRep = GroupBuilder.create().name(subGroupName).build();
        GroupRepresentation parentGroupRep = GroupBuilder.create().name(parentGroupName).subGroups(Arrays.asList(subGroupRep)).build();

        try (Creator<UserResource> u = Creator.create(realm, userRepresentation);
             Creator<GroupResource> subgroup = Creator.create(realm, subGroupRep);
             Creator<GroupResource> parentGroup = Creator.create(realm, parentGroupRep)) {

            UserResource user = u.resource();

            //when
            user.joinGroup(parentGroup.id());
            List<GroupRepresentation> obtainedGroups = realm.users().get(u.id()).groups();

            //then
            assertEquals(1, obtainedGroups.size());
            assertEquals(parentGroupName, obtainedGroups.get(0).getName());

            //when
            user.joinGroup(subgroup.id());
            obtainedGroups = realm.users().get(u.id()).groups();

            //then
            assertEquals(2, obtainedGroups.size());
            assertEquals(parentGroupName, obtainedGroups.get(0).getName());
            assertEquals(subGroupName, obtainedGroups.get(1).getName());
        }
    }

    @Test
    public void testUserProfileMetadata() {
        String userId = createUser("user-metadata", "user-metadata@keycloak.org");
        UserRepresentation user = realm.users().get(userId).toRepresentation(true);
        UserProfileMetadata metadata = user.getUserProfileMetadata();
        assertNotNull(metadata);

        for (String name : managedAttributes) {
            assertNotNull(metadata.getAttributeMetadata(name));
        }
    }

    @Test
    public void testUsernameReadOnlyIfEmailAsUsernameEnabled() {
        switchRegistrationEmailAsUsername(true);
        getCleanup().addCleanup(() -> switchRegistrationEmailAsUsername(false));
        String userId = createUser("user-metadata", "user-metadata@keycloak.org");
        UserRepresentation user = realm.users().get(userId).toRepresentation(true);
        UserProfileMetadata metadata = user.getUserProfileMetadata();
        assertNotNull(metadata);
        UserProfileAttributeMetadata username = metadata.getAttributeMetadata("username");
        assertNotNull(username);
        assertTrue(username.isReadOnly());
        UserProfileAttributeMetadata email = metadata.getAttributeMetadata("email");
        assertNotNull(email);
        assertFalse(email.isReadOnly());
    }

    @Test
    public void testEmailNotReadOnlyIfEmailAsUsernameEnabledAndEditUsernameDisabled() {
        switchRegistrationEmailAsUsername(true);
        getCleanup().addCleanup(() -> switchRegistrationEmailAsUsername(false));
        RealmRepresentation rep = realm.toRepresentation();
        assertFalse(rep.isEditUsernameAllowed());
        String userId = createUser("user-metadata", "user-metadata@keycloak.org");
        UserRepresentation user = realm.users().get(userId).toRepresentation(true);
        UserProfileMetadata metadata = user.getUserProfileMetadata();
        assertNotNull(metadata);
        UserProfileAttributeMetadata username = metadata.getAttributeMetadata("username");
        assertNotNull(username);
        assertTrue(username.isReadOnly());
        UserProfileAttributeMetadata email = metadata.getAttributeMetadata("email");
        assertNotNull(email);
        assertFalse(email.isReadOnly());
    }

    @Test
    public void testDefaultCharacterValidationOnUsername() {
        List<String> invalidNames = Arrays.asList("1user\\\\", "2user\\\\%", "3user\\\\*", "4user\\\\_");

        for (String invalidName : invalidNames) {
            try {
                createUser(invalidName, "test@invalid.org");
                fail("Should fail because the username contains invalid characters");
            } catch (WebApplicationException bre) {
                assertEquals(400, bre.getResponse().getStatus());
                ErrorRepresentation error = bre.getResponse().readEntity(ErrorRepresentation.class);
                assertEquals("error-username-invalid-character", error.getErrorMessage());
            }
        }
    }

    private void removeSampleIdentityProvider() {
        IdentityProviderResource resource = realm.identityProviders().get("social-provider-id");
        Assert.assertNotNull(resource);
        resource.remove();
    }

    private void addSampleIdentityProvider() {
        addSampleIdentityProvider("social-provider-id", 0);
    }

    private void addSampleIdentityProvider(final String alias, final int expectedInitialIdpCount) {
        List<?> providers = realm.identityProviders().findAll();

        IdentityProviderRepresentation rep = new IdentityProviderRepresentation();
        rep.setAlias(alias);
        rep.setProviderId("oidc");

        realm.identityProviders().create(rep);
    }

    private void addFederatedIdentity(String keycloakUserId, String identityProviderAlias1,
                                      FederatedIdentityRepresentation link) {
        Response response1 = realm.users().get(keycloakUserId).addFederatedIdentity(identityProviderAlias1, link);
        assertEquals(204, response1.getStatus());
    }

    private List<String> createUsers() {
        List<String> ids = new ArrayList<>();

        for (int i = 1; i < 10; i++) {
            UserRepresentation user = new UserRepresentation();
            user.setUsername("username" + i);
            user.setEmail("user" + i + "@localhost");
            user.setFirstName("First" + i);
            user.setLastName("Last" + i);

            addAttribute(user, "test", Collections.singletonList("test" + i));
            addAttribute(user, "test" + i, Collections.singletonList("test" + i));
            addAttribute(user, "attr", Collections.singletonList("common"));

            ids.add(createUser(user));
        }

        return ids;
    }

    private void addAttribute(UserRepresentation user, String name, List<String> values) {
        Map<String, List<String>> attributes = Optional.ofNullable(user.getAttributes()).orElse(new HashMap<>());

        attributes.put(name, values);
        managedAttributes.add(name);

        user.setAttributes(attributes);
    }

    private void deleteUser(String id) {
        try (Response response = realm.users().delete(id)) {
            assertEquals(204, response.getStatus());
        }
    }

    private void switchEditUsernameAllowedOn(boolean enable) {
        RealmRepresentation rep = realm.toRepresentation();
        rep.setEditUsernameAllowed(enable);
        realm.update(rep);
    }

    protected void switchRegistrationEmailAsUsername(boolean enable) {
        RealmRepresentation rep = realm.toRepresentation();
        rep.setRegistrationEmailAsUsername(enable);
        realm.update(rep);
    }

    private void enableBruteForce(boolean enable) {
        RealmRepresentation rep = realm.toRepresentation();
        rep.setBruteForceProtected(enable);
        realm.update(rep);
    }


    private UPAttribute createAttributeMetadata(String name) {
        UPAttribute attribute = new UPAttribute();
        attribute.setName(name);
        attribute.setMultivalued(true);
        UPAttributePermissions permissions = new UPAttributePermissions();
        Set<String> set = new HashSet<>();
        set.add("user");
        set.add("admin");
        permissions.setEdit(set);
        attribute.setPermissions(permissions);
        this.managedAttributes.add(name);
        return attribute;
    }

    public static UPConfig setUserProfileConfiguration(RealmResource testRealm, String configuration) {
        try {
            UPConfig config = configuration == null ? null : JsonSerialization.readValue(configuration, UPConfig.class);

            if (config != null) {
                UPAttribute username = config.getAttribute("username");

                if (username == null) {
                    config.addOrReplaceAttribute(new UPAttribute("username"));
                }

                UPAttribute email = config.getAttribute("email");

                if (email == null) {
                    Set<String> setUserAdmin = new HashSet<>();
                    setUserAdmin.add("user");
                    setUserAdmin.add("admin");
                    Set<String> setUser = new HashSet<>();
                    setUser.add("user");
                    config.addOrReplaceAttribute(new UPAttribute("email", new UPAttributePermissions(setUserAdmin, setUserAdmin), new UPAttributeRequired(setUser, new HashSet<>())));
                }
            }

            testRealm.users().userProfile().update(config);

            return config;
        } catch (IOException ioe) {
            throw new RuntimeException("Failed to read configuration", ioe);
        }
    }
}
