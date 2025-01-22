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
package org.keycloak.client.testsuite;

import jakarta.ws.rs.core.Response;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.admin.client.resource.RealmsResource;
import org.keycloak.client.testsuite.common.OAuthClient;
import org.keycloak.client.testsuite.common.RealmImporter;
import org.keycloak.client.testsuite.common.RealmRepsSupplier;
import org.keycloak.client.testsuite.framework.Inject;
import org.keycloak.client.testsuite.framework.KeycloakClientTestExtension;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.representations.idm.RealmRepresentation;
import org.keycloak.representations.idm.RoleRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.keycloak.testsuite.util.ApiUtil;
import org.keycloak.testsuite.util.RoleBuilder;
import org.keycloak.testsuite.util.ServerURLs;
import org.keycloak.testsuite.util.TestCleanup;
import org.keycloak.util.JsonSerialization;

import java.io.IOException;
import java.io.InputStream;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;

import static org.keycloak.testsuite.util.Users.setPasswordFor;

@ExtendWith(KeycloakClientTestExtension.class)
public abstract class AbstractAdminClientTest implements RealmRepsSupplier {

    protected static final String REALM_NAME = "admin-client-test";

    protected RealmResource realm;
    protected String realmId;

    protected Map<String, TestCleanup> testCleanup = new HashMap<>();

    @Inject
    protected Keycloak adminClient;

    @Inject
    protected RealmImporter realmImporter;

    @Inject
    protected OAuthClient oauth;

    @Override
    public List<RealmRepresentation> getRealmsForImport() {
        RealmRepresentation adminRealmRep = new RealmRepresentation();
        adminRealmRep.setId(REALM_NAME);
        adminRealmRep.setRealm(REALM_NAME);
        adminRealmRep.setEnabled(true);
        Map<String, String> config = new HashMap<>();
        config.put("from", "auto@keycloak.org");
        config.put("host", "localhost");
        config.put("port", "3025");
        adminRealmRep.setSmtpServer(config);

        List<String> eventListeners = new ArrayList<>();
        eventListeners.add("event-queue");
        adminRealmRep.setEventsListeners(eventListeners);

        RealmRepresentation testRealm = loadJson(getClass().getResourceAsStream("/testrealm.json"), RealmRepresentation.class);

        return Arrays.asList(adminRealmRep, testRealm);
    }

    @BeforeEach
    public void importRealms() {
        realmImporter.importRealmsIfNotImported(this);
        realm = adminClient.realm(REALM_NAME);
        realmId = realm.toRepresentation().getId();
    }

    @AfterEach
    public void cleanup() {
        this.testCleanup.keySet().forEach(key -> getCleanup(key).executeCleanup());
    }

    @Override
    public boolean removeVerifyProfileAtImport() {
        // remove verify profile by default because most tests are not prepared
        return true;
    }

    public RealmsResource realmsResource() {
        return adminClient.realms();
    }

    public static <T> T loadJson(InputStream is, Class<T> type) {
        try {
            return JsonSerialization.readValue(is, type);
        } catch (IOException e) {
            throw new RuntimeException("Failed to parse json", e);
        }
    }

    RoleRepresentation createRealmRole(String roleName) {
        RoleRepresentation role = RoleBuilder.create().name(roleName).build();
        return createRealmRole(role);
    }

    RoleRepresentation createRealmRole(RoleRepresentation role) {
        realm.roles().create(role);
        return realm.roles().get(role.getName()).toRepresentation();
    }

    public static UserRepresentation createUserRepresentation(String id, String username, String email, String firstName, String lastName, List<String> groups, boolean enabled) {
        UserRepresentation user = new UserRepresentation();
        user.setId(id);
        user.setUsername(username);
        user.setEmail(email);
        user.setFirstName(firstName);
        user.setLastName(lastName);
        user.setGroups(groups);
        user.setEnabled(enabled);
        return user;
    }

    public static UserRepresentation createUserRepresentation(String username, String email, String firstName, String lastName, List<String> groups, boolean enabled) {
        return createUserRepresentation(null, username, email, firstName, lastName, groups, enabled);
    }

    public static UserRepresentation createUserRepresentation(String username, String email, String firstName, String lastName, boolean enabled) {
        return createUserRepresentation(username, email, firstName, lastName, null, enabled);
    }

    public static UserRepresentation createUserRepresentation(String username, String email, String firstName, String lastName, boolean enabled, String password) {
        UserRepresentation user = createUserRepresentation(username, email, firstName, lastName, enabled);
        setPasswordFor(user, password);
        return user;
    }

    public static UserRepresentation createUserRepresentation(String username, String password) {
        UserRepresentation user = createUserRepresentation(username, null, null, null, true, password);
        return user;
    }

    public String createUser(String realm, String username, String password, String... requiredActions) {
        UserRepresentation homer = createUserRepresentation(username, password);
        homer.setRequiredActions(Arrays.asList(requiredActions));

        return ApiUtil.createUserWithAdminClient(adminClient.realm(realm), homer);
    }

    public String createUser(String realm, String username, String password, String firstName, String lastName, String email, Consumer<UserRepresentation> customizer) {
        UserRepresentation user = createUserRepresentation(username, email, firstName, lastName, true, password);
        customizer.accept(user);
        return ApiUtil.createUserWithAdminClient(adminClient.realm(realm), user);
    }

    public String createUser(String realm, String username, String password, String firstName, String lastName, String email) {
        UserRepresentation homer = createUserRepresentation(username, email, firstName, lastName, true, password);
        return ApiUtil.createUserWithAdminClient(adminClient.realm(realm), homer);
    }

    protected void createAppClientInRealm(String realm) {
        ClientRepresentation client = new ClientRepresentation();
        client.setClientId("test-app");
        client.setName("test-app");
        client.setSecret("password");
        client.setEnabled(true);
        client.setDirectAccessGrantsEnabled(true);

        client.setRedirectUris(Collections.singletonList(ServerURLs.AUTH_SERVER_URL + "/*"));

        Response response = adminClient.realm(realm).clients().create(client);
        response.close();
    }

    protected TestCleanup getCleanup(String realmName) {
        if (!this.testCleanup.containsKey(realmName)) {
            this.testCleanup.put(realmName, new TestCleanup(realmName, adminClient));
        }
        return this.testCleanup.get(realmName);
    }

    protected TestCleanup getCleanup() {
        return getCleanup(REALM_NAME);
    }

    protected RealmResource testRealm() {
        return adminClient.realm("test");
    }

    public RealmResource testRealmResource() {
        return adminClient.realm("test");
    }

    protected String randomAlphanumericString(int count) {
        return new SecureRandom().ints('0', 'z' + 1)
                .filter(i -> (i <= '9' || i >= 'A') && (i <= 'Z' || i >= 'a'))
                .limit(count)
                .collect(StringBuilder::new, StringBuilder::appendCodePoint, StringBuilder::append)
                .toString();
    }
}
