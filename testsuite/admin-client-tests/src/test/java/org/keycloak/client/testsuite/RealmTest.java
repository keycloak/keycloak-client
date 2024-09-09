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

import com.google.common.collect.ImmutableSet;
import com.google.common.collect.Sets;
import jakarta.ws.rs.BadRequestException;
import jakarta.ws.rs.NotFoundException;
import org.apache.commons.io.IOUtils;
import org.junit.jupiter.api.Test;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.client.testsuite.common.Creator;
import org.keycloak.client.testsuite.framework.KeycloakVersion;
import org.keycloak.client.testsuite.events.EventType;
import org.keycloak.client.testsuite.models.CibaConfig;
import org.keycloak.client.testsuite.models.Constants;
import org.keycloak.client.testsuite.models.OAuth2DeviceConfig;
import org.keycloak.client.testsuite.models.ParConfig;
import org.keycloak.client.testsuite.models.RealmAttributes;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.representations.idm.ComponentRepresentation;
import org.keycloak.representations.idm.RealmEventsConfigRepresentation;
import org.keycloak.representations.idm.RealmRepresentation;
import org.keycloak.representations.idm.RoleRepresentation;
import org.keycloak.testsuite.util.AdminClientUtil;
import org.keycloak.testsuite.util.RealmBuilder;
import org.keycloak.testsuite.util.UserBuilder;
import org.keycloak.util.JsonSerialization;
import org.testcontainers.shaded.org.hamcrest.CoreMatchers;

import java.io.IOException;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static io.smallrye.common.constraint.Assert.assertFalse;
import static io.smallrye.common.constraint.Assert.assertTrue;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.fail;
import static org.testcontainers.shaded.org.hamcrest.Matchers.hasItems;
import static org.testcontainers.shaded.org.hamcrest.MatcherAssert.assertThat;
import static org.testcontainers.shaded.org.hamcrest.Matchers.containsInAnyOrder;
import static org.testcontainers.shaded.org.hamcrest.Matchers.containsString;
import static org.testcontainers.shaded.org.hamcrest.Matchers.empty;
import static org.testcontainers.shaded.org.hamcrest.Matchers.everyItem;
import static org.testcontainers.shaded.org.hamcrest.Matchers.hasSize;
import static org.testcontainers.shaded.org.hamcrest.Matchers.notNullValue;
import static org.testcontainers.shaded.org.hamcrest.Matchers.not;

/**
 * @author <a href="mailto:sthorger@redhat.com">Stian Thorgersen</a>
 */
public class RealmTest extends AbstractAdminClientTest {

    @Override
    public List<RealmRepresentation> getRealmsForImport() {
        return super.getRealmsForImport();
    }

    @Test
    public void getRealms() {
        List<RealmRepresentation> realms = adminClient.realms().findAll();
        Assert.assertNames(realms, "master", REALM_NAME, "test");
    }

    @Test
    public void renameRealm() {
        String OLD = "old";
        String NEW = "new";

        RealmRepresentation rep = new RealmRepresentation();
        rep.setId(OLD);
        rep.setRealm(OLD);

        adminClient.realms().create(rep);

        Map<String, String> newBaseUrls = new HashMap<>();
        Map<String, List<String>> newRedirectUris = new HashMap<>();

        // memorize all existing clients with their soon-to-be URIs
        adminClient.realm(OLD).clients().findAll().forEach(client -> {
            if (client.getBaseUrl() != null && client.getBaseUrl().contains("/" + OLD + "/")) {
                newBaseUrls.put(client.getClientId(), client.getBaseUrl().replace("/" + OLD + "/", "/" + NEW + "/"));
            }
            if (client.getRedirectUris() != null) {
                newRedirectUris.put(
                        client.getClientId(),
                        client.getRedirectUris()
                                .stream()
                                .map(redirectUri -> redirectUri.replace("/" + OLD + "/", "/" + NEW + "/"))
                                .collect(Collectors.toList())
                );
            }
        });
        // at least those three default clients should be in the list of things to be tested
        assertThat(newBaseUrls.keySet(), hasItems(Constants.ADMIN_CONSOLE_CLIENT_ID, Constants.ACCOUNT_MANAGEMENT_CLIENT_ID, Constants.ACCOUNT_CONSOLE_CLIENT_ID));
        assertThat(newRedirectUris.keySet(), hasItems(Constants.ADMIN_CONSOLE_CLIENT_ID, Constants.ACCOUNT_MANAGEMENT_CLIENT_ID, Constants.ACCOUNT_CONSOLE_CLIENT_ID));

        rep.setRealm(NEW);
        adminClient.realm(OLD).update(rep);

        // Check client in master realm renamed
        assertEquals(0, adminClient.realm("master").clients().findByClientId("old-realm").size());
        assertEquals(1, adminClient.realm("master").clients().findByClientId("new-realm").size());

        ClientRepresentation adminConsoleClient = adminClient.realm(NEW).clients().findByClientId(Constants.ADMIN_CONSOLE_CLIENT_ID).get(0);
        assertEquals(Constants.AUTH_ADMIN_URL_PROP, adminConsoleClient.getRootUrl());

        ClientRepresentation accountClient = adminClient.realm(NEW).clients().findByClientId(Constants.ACCOUNT_MANAGEMENT_CLIENT_ID).get(0);
        assertEquals(Constants.AUTH_BASE_URL_PROP, accountClient.getRootUrl());

        ClientRepresentation accountConsoleClient = adminClient.realm(NEW).clients().findByClientId(Constants.ACCOUNT_CONSOLE_CLIENT_ID).get(0);
        assertEquals(Constants.AUTH_BASE_URL_PROP, accountConsoleClient.getRootUrl());

        newBaseUrls.forEach((clientId, baseUrl) -> {
            assertEquals(baseUrl, adminClient.realm(NEW).clients().findByClientId(clientId).get(0).getBaseUrl());
        });
        newRedirectUris.forEach((clientId, redirectUris) -> {
            assertEquals(redirectUris, adminClient.realm(NEW).clients().findByClientId(clientId).get(0).getRedirectUris());
        });

        adminClient.realms().realm(NEW).remove();
    }

    @Test
    public void createRealmEmpty() {

        RealmRepresentation rep = new RealmRepresentation();
        rep.setRealm("new-realm");

        adminClient.realms().create(rep);

        Assert.assertNames(adminClient.realms().findAll(), "master", REALM_NAME, "test", "new-realm");

        List<String> clients = adminClient.realms().realm("new-realm").clients().findAll().stream().map(ClientRepresentation::getClientId).collect(Collectors.toList());
        assertThat(clients, containsInAnyOrder("account", "account-console", "admin-cli", "broker", "realm-management", "security-admin-console"));

        adminClient.realms().realm("new-realm").remove();

        Assert.assertNames(adminClient.realms().findAll(), "master", REALM_NAME, "test");
    }

    @Test
    @KeycloakVersion(min = "25.0.0")
    public void createRealmWithValidConsoleUris() throws Exception {
        var realmNameWithSpaces = "new realm";


        RealmRepresentation rep = new RealmRepresentation();
        rep.setRealm(realmNameWithSpaces);
        rep.setEnabled(Boolean.TRUE);
        rep.setUsers(Collections.singletonList(UserBuilder.create()
                .username("new-realm-admin")
                .firstName("new-realm-admin")
                .lastName("new-realm-admin")
                .email("new-realm-admin@keycloak.org")
                .password("password")
                .role(Constants.REALM_MANAGEMENT_CLIENT_ID, "realm-admin")
                .build()));

        adminClient.realms().create(rep);

        Assert.assertNames(adminClient.realms().findAll(), "master", REALM_NAME, "test" , realmNameWithSpaces);

        final var urlPlaceHolders = ImmutableSet.of("${authBaseUrl}", "${authAdminUrl}");

        RealmResource newRealm = adminClient.realms().realm(realmNameWithSpaces);
        List<String> clientUris = newRealm.clients()
                .findAll()
                .stream()
                .flatMap(client -> Stream.concat(Stream.concat(Stream.concat(
                        client.getRedirectUris().stream(),
                        Stream.of(client.getBaseUrl())),
                        Stream.of(client.getRootUrl())),
                        Stream.of(client.getAdminUrl())))
                .filter(Objects::nonNull)
                .filter(uri -> !urlPlaceHolders.contains(uri))
                .collect(Collectors.toList());

        assertThat(clientUris, not(empty()));
        assertThat(clientUris, everyItem(containsString("/new%20realm/")));


        try (Keycloak client = AdminClientUtil.createAdminClient(true, realmNameWithSpaces,
                "new-realm-admin", "password", Constants.ADMIN_CLI_CLIENT_ID, null)) {
            assertNotNull(client.serverInfo().getInfo());
        }

        adminClient.realms().realm(realmNameWithSpaces).remove();

        Assert.assertNames(adminClient.realms().findAll(), "master", REALM_NAME, "test");
    }

    @Test
    public void createRealmRejectReservedCharOrEmptyName() {
        RealmRepresentation rep = new RealmRepresentation();
        rep.setRealm("new-re;alm");
        assertThrows(BadRequestException.class, () -> adminClient.realms().create(rep));
        rep.setRealm("");
        assertThrows(BadRequestException.class, () -> adminClient.realms().create(rep));
        rep.setRealm("new-realm");
        rep.setId("invalid;id");
        assertThrows(BadRequestException.class, () -> adminClient.realms().create(rep));
    }

    /**
     * Checks attributes exposed as fields are not also included as attributes
     */
    @Test
    public void excludesFieldsFromAttributes() {
        RealmRepresentation rep = new RealmRepresentation();
        rep.setRealm("attributes");

        adminClient.realms().create(rep);

        RealmRepresentation rep2 = adminClient.realm("attributes").toRepresentation();
        if (rep2.getAttributes() != null) {
            Arrays.asList(CibaConfig.CIBA_BACKCHANNEL_TOKEN_DELIVERY_MODE,
                    CibaConfig.CIBA_EXPIRES_IN,
                    CibaConfig.CIBA_INTERVAL,
                    CibaConfig.CIBA_AUTH_REQUESTED_USER_HINT).stream().forEach(i -> rep2.getAttributes().remove(i));
        }

        Set<String> attributesKeys = rep2.getAttributes().keySet();

        int expectedAttributesCount = 3;
        final Set<String> expectedAttributes = Sets.newHashSet(
                OAuth2DeviceConfig.OAUTH2_DEVICE_CODE_LIFESPAN,
                OAuth2DeviceConfig.OAUTH2_DEVICE_POLLING_INTERVAL,
                ParConfig.PAR_REQUEST_URI_LIFESPAN
        );

        // This attribute is represented in Legacy store as attribute and for Map store as a field
        expectedAttributes.add("realmReusableOtpCode");
        expectedAttributesCount++;

        assertThat(attributesKeys.size(), CoreMatchers.is(expectedAttributesCount));
        assertThat(attributesKeys, CoreMatchers.is(expectedAttributes));

        adminClient.realms().realm("attributes").remove();
    }

    /**
     * Checks attributes exposed as fields are not deleted on update realm
     */
    @Test
    public void testFieldNotErased() {
        Long dummyLong = Long.valueOf(999);
        Integer dummyInt = Integer.valueOf(999);

        RealmRepresentation rep = new RealmRepresentation();
        rep.setRealm("attributes");
        rep.setDisplayName("DISPLAY_NAME");
        rep.setDisplayNameHtml("DISPLAY_NAME_HTML");
        rep.setDefaultSignatureAlgorithm("RS256");
        rep.setBruteForceProtected(true);
        rep.setPermanentLockout(true);
        rep.setMaxFailureWaitSeconds(dummyInt);
        rep.setWaitIncrementSeconds(dummyInt);
        rep.setQuickLoginCheckMilliSeconds(dummyLong);
        rep.setMinimumQuickLoginWaitSeconds(dummyInt);
        rep.setMaxDeltaTimeSeconds(dummyInt);
        rep.setFailureFactor(dummyInt);
        rep.setActionTokenGeneratedByAdminLifespan(dummyInt);
        rep.setActionTokenGeneratedByUserLifespan(dummyInt);
        rep.setOfflineSessionMaxLifespanEnabled(true);
        rep.setOfflineSessionMaxLifespan(dummyInt);

        rep.setWebAuthnPolicyRpEntityName("RP_ENTITY_NAME");
        rep.setWebAuthnPolicySignatureAlgorithms(Collections.singletonList("RS256"));
        rep.setWebAuthnPolicyRpId("localhost");
        rep.setWebAuthnPolicyAttestationConveyancePreference("Direct");
        rep.setWebAuthnPolicyAuthenticatorAttachment("Platform");
        rep.setWebAuthnPolicyRequireResidentKey("Yes");
        rep.setWebAuthnPolicyUserVerificationRequirement("Required");
        rep.setWebAuthnPolicyCreateTimeout(dummyInt);
        rep.setWebAuthnPolicyAvoidSameAuthenticatorRegister(true);
        rep.setWebAuthnPolicyAcceptableAaguids(Collections.singletonList("00000000-0000-0000-0000-000000000000"));

        rep.setWebAuthnPolicyPasswordlessRpEntityName("RP_ENTITY_NAME");
        rep.setWebAuthnPolicyPasswordlessSignatureAlgorithms(Collections.singletonList("RS256"));
        rep.setWebAuthnPolicyPasswordlessRpId("localhost");
        rep.setWebAuthnPolicyPasswordlessAttestationConveyancePreference("Direct");
        rep.setWebAuthnPolicyPasswordlessAuthenticatorAttachment("Platform");
        rep.setWebAuthnPolicyPasswordlessRequireResidentKey("Yes");
        rep.setWebAuthnPolicyPasswordlessUserVerificationRequirement("Required");
        rep.setWebAuthnPolicyPasswordlessCreateTimeout(dummyInt);
        rep.setWebAuthnPolicyPasswordlessAvoidSameAuthenticatorRegister(true);
        rep.setWebAuthnPolicyPasswordlessAcceptableAaguids(Collections.singletonList("00000000-0000-0000-0000-000000000000"));

        adminClient.realms().create(rep);

        RealmRepresentation rep2 = new RealmRepresentation();
        rep2.setAttributes(Collections.singletonMap("frontendUrl", "http://localhost/frontEnd"));
        adminClient.realm("attributes").update(rep2);

        rep = adminClient.realm("attributes").toRepresentation();
        assertEquals("DISPLAY_NAME", rep.getDisplayName());
        assertEquals("DISPLAY_NAME_HTML", rep.getDisplayNameHtml());
        assertEquals("RS256", rep.getDefaultSignatureAlgorithm());
        assertTrue(rep.isBruteForceProtected());
        assertTrue(rep.isPermanentLockout());
        assertEquals(dummyInt, rep.getMaxFailureWaitSeconds());
        assertEquals(dummyInt, rep.getWaitIncrementSeconds());
        assertEquals(dummyLong, rep.getQuickLoginCheckMilliSeconds());
        assertEquals(dummyInt, rep.getMinimumQuickLoginWaitSeconds());
        assertEquals(dummyInt, rep.getMaxDeltaTimeSeconds());
        assertEquals(dummyInt, rep.getFailureFactor());
        assertEquals(dummyInt, rep.getActionTokenGeneratedByAdminLifespan());
        assertEquals(dummyInt, rep.getActionTokenGeneratedByUserLifespan());
        assertTrue(rep.getOfflineSessionMaxLifespanEnabled());
        assertEquals(dummyInt, rep.getOfflineSessionMaxLifespan());

        assertEquals("RP_ENTITY_NAME", rep.getWebAuthnPolicyRpEntityName());
        assertEquals(Collections.singletonList("RS256"), rep.getWebAuthnPolicySignatureAlgorithms());
        assertEquals("localhost", rep.getWebAuthnPolicyRpId());
        assertEquals("Direct", rep.getWebAuthnPolicyAttestationConveyancePreference());
        assertEquals("Platform", rep.getWebAuthnPolicyAuthenticatorAttachment());
        assertEquals("Yes", rep.getWebAuthnPolicyRequireResidentKey());
        assertEquals("Required", rep.getWebAuthnPolicyUserVerificationRequirement());
        assertEquals(dummyInt, rep.getWebAuthnPolicyCreateTimeout());
        assertTrue(rep.isWebAuthnPolicyAvoidSameAuthenticatorRegister());
        assertEquals(Collections.singletonList("00000000-0000-0000-0000-000000000000"), rep.getWebAuthnPolicyAcceptableAaguids());

        assertEquals("RP_ENTITY_NAME", rep.getWebAuthnPolicyPasswordlessRpEntityName());
        assertEquals(Collections.singletonList("RS256"), rep.getWebAuthnPolicyPasswordlessSignatureAlgorithms());
        assertEquals("localhost", rep.getWebAuthnPolicyPasswordlessRpId());
        assertEquals("Direct", rep.getWebAuthnPolicyPasswordlessAttestationConveyancePreference());
        assertEquals("Platform", rep.getWebAuthnPolicyPasswordlessAuthenticatorAttachment());
        assertEquals("Yes", rep.getWebAuthnPolicyPasswordlessRequireResidentKey());
        assertEquals("Required", rep.getWebAuthnPolicyPasswordlessUserVerificationRequirement());
        assertEquals(dummyInt, rep.getWebAuthnPolicyPasswordlessCreateTimeout());
        assertTrue(rep.isWebAuthnPolicyPasswordlessAvoidSameAuthenticatorRegister());
        assertEquals(Collections.singletonList("00000000-0000-0000-0000-000000000000"), rep.getWebAuthnPolicyPasswordlessAcceptableAaguids());

        adminClient.realms().realm("attributes").remove();
    }

    @Test
    public void smtpPasswordSecret() {
        RealmRepresentation rep = RealmBuilder.create().testMail().build();
        rep.setRealm("realm-with-smtp");
        rep.getSmtpServer().put("user", "user");
        rep.getSmtpServer().put("password", "secret");

        adminClient.realms().create(rep);

        RealmRepresentation returned = adminClient.realm("realm-with-smtp").toRepresentation();
        assertEquals(ComponentRepresentation.SECRET_VALUE, returned.getSmtpServer().get("password"));

        adminClient.realm("realm-with-smtp").update(rep);


        RealmRepresentation realm = adminClient.realms().findAll().stream().filter(r -> r.getRealm().equals("realm-with-smtp")).findFirst().get();
        assertEquals(ComponentRepresentation.SECRET_VALUE, realm.getSmtpServer().get("password"));

        adminClient.realms().realm("realm-with-smtp").remove();
    }

    @Test
    public void createRealmCheckDefaultPasswordPolicy() {
        RealmRepresentation rep = new RealmRepresentation();
        rep.setRealm("new-realm");

        adminClient.realms().create(rep);

        assertEquals(null, adminClient.realm("new-realm").toRepresentation().getPasswordPolicy());

        adminClient.realms().realm("new-realm").remove();

        rep.setPasswordPolicy("length(8)");

        adminClient.realms().create(rep);

        assertEquals("length(8)", adminClient.realm("new-realm").toRepresentation().getPasswordPolicy());

        adminClient.realms().realm("new-realm").remove();
    }

    @Test
    public void createRealmFromJson() {
        RealmRepresentation rep = loadJson(getClass().getResourceAsStream("/admin-test/testrealm.json"), RealmRepresentation.class);
        adminClient.realms().create(rep);

        RealmRepresentation created = adminClient.realms().realm("admin-test-1").toRepresentation();
        assertRealm(rep, created);

        adminClient.realms().realm("admin-test-1").remove();
    }

    //KEYCLOAK-6146
    @Test
    public void createRealmWithPasswordPolicyFromJsonWithInvalidPasswords() {

        //try to create realm with password policies and users with plain-text passwords what doesn't met the policies
        RealmRepresentation rep = loadJson(getClass().getResourceAsStream("/import/testrealm-keycloak-6146-error.json"), RealmRepresentation.class);
        try {
            adminClient.realms().create(rep);
            fail();
        }
        catch (BadRequestException ex) {
        }

        try {
            //ensure the realm was not created
            adminClient.realms().realm("secure-app").toRepresentation();
            fail();
        }
        catch (NotFoundException ex) {
        }
        //test will fail on AssertionError when both BadRequestException and NotFoundException is not thrown
    }

    //KEYCLOAK-6146
    @Test
    public void createRealmWithPasswordPolicyFromJsonWithValidPasswords() {
        RealmRepresentation rep = loadJson(getClass().getResourceAsStream("/import/testrealm-keycloak-6146.json"), RealmRepresentation.class);
        try (Creator<RealmResource> c = Creator.create(adminClient, rep)) {
            RealmRepresentation created = c.resource().toRepresentation();
            assertRealm(rep, created);
        }
    }

    @Test
    public void removeRealm() {
        RealmRepresentation realmRepresentation = realm.toRepresentation();
        realm.remove();

        Assert.assertNames(adminClient.realms().findAll(), "master", "test");

        // Re-create realm
        adminClient.realms().create(realmRepresentation);
    }

    @Test
    @KeycloakVersion(min = "25.0.0")
    public void removeMasterRealm() {
        // any attempt to remove the master realm should fail.
        try {
            adminClient.realm("master").remove();
            fail("It should not be possible to remove the master realm");
        } catch(BadRequestException ignored) {
        }
    }

    @Test
    public void loginAfterRemoveRealm() {
        RealmRepresentation realmRepresentation = realm.toRepresentation();
        realm.remove();

        try (Keycloak client =  AdminClientUtil.createAdminClient(true, "master", "admin", "admin", Constants.ADMIN_CLI_CLIENT_ID, null)) {
            client.serverInfo().getInfo();
        }

        // Re-create realm
        adminClient.realms().create(realmRepresentation);
    }

    /**
     * KEYCLOAK-1990 1991
     * @throws Exception
     */
    @Test
    public void renameRealmTest() throws Exception {
        RealmRepresentation realm1 = new RealmRepresentation();
        realm1.setRealm("test-immutable");
        adminClient.realms().create(realm1);
        realm1 = adminClient.realms().realm("test-immutable").toRepresentation();
        realm1.setRealm("test-immutable-old");
        adminClient.realms().realm("test-immutable").update(realm1);
        assertThat(adminClient.realms().realm("test-immutable-old").toRepresentation(), notNullValue());

        RealmRepresentation realm2 = new RealmRepresentation();
        realm2.setRealm("test-immutable");
        adminClient.realms().create(realm2);
        assertThat(adminClient.realms().realm("test-immutable").toRepresentation(), notNullValue());

        adminClient.realms().realm("test-immutable").remove();
        adminClient.realms().realm("test-immutable-old").remove();
    }

    private RealmEventsConfigRepresentation copyRealmEventsConfigRepresentation(RealmEventsConfigRepresentation rep) {
        RealmEventsConfigRepresentation recr = new RealmEventsConfigRepresentation();
        recr.setEnabledEventTypes(rep.getEnabledEventTypes());
        recr.setEventsListeners(rep.getEventsListeners());
        recr.setEventsExpiration(rep.getEventsExpiration());
        recr.setEventsEnabled(rep.isEventsEnabled());
        recr.setAdminEventsEnabled(rep.isAdminEventsEnabled());
        recr.setAdminEventsDetailsEnabled(rep.isAdminEventsDetailsEnabled());
        return recr;
    }

    private void checkRealmEventsConfigRepresentation(RealmEventsConfigRepresentation expected,
            RealmEventsConfigRepresentation actual) {
        assertEquals(expected.getEnabledEventTypes().size(), actual.getEnabledEventTypes().size());
        assertTrue(actual.getEnabledEventTypes().containsAll(expected.getEnabledEventTypes()));
        assertEquals(expected.getEventsListeners().size(), actual.getEventsListeners().size());
        assertTrue(actual.getEventsListeners().containsAll(expected.getEventsListeners()));
        assertEquals(expected.getEventsExpiration(), actual.getEventsExpiration());
        assertEquals(expected.isEventsEnabled(), actual.isEventsEnabled());
        assertEquals(expected.isAdminEventsEnabled(), actual.isAdminEventsEnabled());
        assertEquals(expected.isAdminEventsDetailsEnabled(), actual.isAdminEventsDetailsEnabled());
    }

    @Test
    public void updateRealmEventsConfig() {
        RealmEventsConfigRepresentation rep = realm.getRealmEventsConfig();
        RealmEventsConfigRepresentation repOrig = copyRealmEventsConfigRepresentation(rep);

        // the "event-queue" listener should be enabled by default
        assertTrue(rep.getEventsListeners().contains("event-queue"));

        // first modification => remove "event-queue", should be sent to the queue
        rep.setEnabledEventTypes(Arrays.asList(EventType.LOGIN.name(), EventType.LOGIN_ERROR.name()));
        rep.setEventsListeners(Arrays.asList("jboss-logging"));
        rep.setEventsExpiration(36000L);
        rep.setEventsEnabled(true);
        rep.setAdminEventsEnabled(true);
        rep.setAdminEventsDetailsEnabled(true);
        adminClient.realms().realm(REALM_NAME).updateRealmEventsConfig(rep);
        RealmEventsConfigRepresentation actual = realm.getRealmEventsConfig();
        checkRealmEventsConfigRepresentation(rep, actual);

        // second modification => should not be sent cos event-queue was removed in the first mod
        rep.setEnabledEventTypes(Arrays.asList(EventType.LOGIN.name(),
                EventType.LOGIN_ERROR.name(), EventType.CLIENT_LOGIN.name()));
        adminClient.realms().realm(REALM_NAME).updateRealmEventsConfig(rep);
        actual = realm.getRealmEventsConfig();
        checkRealmEventsConfigRepresentation(rep, actual);

        // third modification => restore queue => should be sent and recovered
        adminClient.realms().realm(REALM_NAME).updateRealmEventsConfig(repOrig);
        actual = realm.getRealmEventsConfig();
        checkRealmEventsConfigRepresentation(repOrig, actual);
    }

    @Test
    public void updateRealmWithReservedCharInNameOrEmptyName() {
        RealmRepresentation rep = realm.toRepresentation();
        rep.setRealm("fo#o");
        assertThrows(BadRequestException.class, () -> realm.update(rep));
        rep.setRealm("");
        assertThrows(BadRequestException.class, () -> realm.update(rep));
    }

    @Test
    public void updateRealm() {
        // first change
        RealmRepresentation rep = realm.toRepresentation();
        rep.setSsoSessionIdleTimeout(123);
        rep.setSsoSessionMaxLifespan(12);
        rep.setSsoSessionIdleTimeoutRememberMe(33);
        rep.setSsoSessionMaxLifespanRememberMe(34);
        rep.setAccessCodeLifespanLogin(1234);
        rep.setActionTokenGeneratedByAdminLifespan(2345);
        rep.setActionTokenGeneratedByUserLifespan(3456);
        rep.setRegistrationAllowed(true);
        rep.setRegistrationEmailAsUsername(true);
        rep.setEditUsernameAllowed(true);
        rep.setUserManagedAccessAllowed(true);

        realm.update(rep);

        rep = realm.toRepresentation();

        assertEquals(123, rep.getSsoSessionIdleTimeout().intValue());
        assertEquals(12, rep.getSsoSessionMaxLifespan().intValue());
        assertEquals(33, rep.getSsoSessionIdleTimeoutRememberMe().intValue());
        assertEquals(34, rep.getSsoSessionMaxLifespanRememberMe().intValue());
        assertEquals(1234, rep.getAccessCodeLifespanLogin().intValue());
        assertEquals(2345, rep.getActionTokenGeneratedByAdminLifespan().intValue());
        assertEquals(3456, rep.getActionTokenGeneratedByUserLifespan().intValue());
        assertEquals(Boolean.TRUE, rep.isRegistrationAllowed());
        assertEquals(Boolean.TRUE, rep.isRegistrationEmailAsUsername());
        assertEquals(Boolean.TRUE, rep.isEditUsernameAllowed());
//        if (ProfileAssume.isFeatureEnabled(Profile.Feature.AUTHORIZATION)) {
//            assertEquals(Boolean.TRUE, rep.isUserManagedAccessAllowed());
//        } else {
//            assertEquals(Boolean.FALSE, rep.isUserManagedAccessAllowed());
//        }

        // second change
        rep.setRegistrationAllowed(false);
        rep.setRegistrationEmailAsUsername(false);
        rep.setEditUsernameAllowed(false);
        rep.setUserManagedAccessAllowed(false);

        realm.update(rep);

        rep = realm.toRepresentation();
        assertEquals(Boolean.FALSE, rep.isRegistrationAllowed());
        assertEquals(Boolean.FALSE, rep.isRegistrationEmailAsUsername());
        assertEquals(Boolean.FALSE, rep.isEditUsernameAllowed());
        assertEquals(Boolean.FALSE, rep.isUserManagedAccessAllowed());
    }

    @Test
    @KeycloakVersion(min = "26.0.0")
    public void updateRealmWithIncorrectTimeoutValues() {
        // first change
        RealmRepresentation rep = realm.toRepresentation();
        rep.setAccessCodeLifespanLogin(0);
        rep.setAccessCodeLifespanUserAction(0);
        try {
            realm.update(rep);
            Assert.fail("Not expected to successfully update the realm");
        } catch (Exception expected) {
            // Expected exception
            assertEquals("HTTP 400 Bad Request", expected.getMessage());
        }
    }

    @Test
    public void updateRealmWithNewRepresentation() {
        // first change
        RealmRepresentation rep = new RealmRepresentation();
        rep.setEditUsernameAllowed(true);
        rep.setSupportedLocales(new HashSet<>(Arrays.asList("en", "de")));

        realm.update(rep);

        rep = realm.toRepresentation();

        assertEquals(Boolean.TRUE, rep.isEditUsernameAllowed());
        assertEquals(2, rep.getSupportedLocales().size());

        // second change
        rep = new RealmRepresentation();
        rep.setEditUsernameAllowed(false);

        realm.update(rep);

        rep = realm.toRepresentation();
        assertEquals(Boolean.FALSE, rep.isEditUsernameAllowed());
        assertEquals(2, rep.getSupportedLocales().size());
    }

    @Test
    public void updateRealmAttributes() {
        // first change
        RealmRepresentation rep = new RealmRepresentation();
        List<String> webAuthnPolicyAcceptableAaguids = new ArrayList<>();
        webAuthnPolicyAcceptableAaguids.add("aaguid1");
        webAuthnPolicyAcceptableAaguids.add("aaguid2");

        rep.setAttributes(new HashMap<>());
        rep.getAttributes().put("foo1", "bar1");
        rep.getAttributes().put("foo2", "bar2");

        rep.setWebAuthnPolicyRpEntityName("keycloak");
        rep.setWebAuthnPolicyAcceptableAaguids(webAuthnPolicyAcceptableAaguids);
        rep.setBruteForceProtected(true);
        rep.setDisplayName("dn1");

        realm.update(rep);

        rep = realm.toRepresentation();
        assertEquals("bar1", rep.getAttributes().get("foo1"));
        assertEquals("bar2", rep.getAttributes().get("foo2"));
        assertTrue(rep.isBruteForceProtected());
        assertEquals("dn1", rep.getDisplayName());
        assertEquals(webAuthnPolicyAcceptableAaguids, rep.getWebAuthnPolicyAcceptableAaguids());

        // second change
        webAuthnPolicyAcceptableAaguids.clear();
        rep.setBruteForceProtected(false);
        rep.setDisplayName("dn2");
        rep.getAttributes().put("foo1", "bar11");
        rep.getAttributes().remove("foo2");
        rep.setWebAuthnPolicyAcceptableAaguids(webAuthnPolicyAcceptableAaguids);

        realm.update(rep);

        rep = realm.toRepresentation();

        assertFalse(rep.isBruteForceProtected());
        assertEquals("dn2", rep.getDisplayName());

        assertEquals("bar11", rep.getAttributes().get("foo1"));
        assertFalse(rep.getAttributes().containsKey("foo2"));
        assertTrue(rep.getWebAuthnPolicyAcceptableAaguids().isEmpty());
    }

    @Test
    public void getRealmRepresentation() {
        RealmRepresentation rep = realm.toRepresentation();
        assertEquals(REALM_NAME, rep.getRealm());
        assertTrue(rep.isEnabled());
    }

    @Test
    // KEYCLOAK-1110
    public void deleteDefaultRole() {
        RoleRepresentation role = new RoleRepresentation("test", "test", false);
        realm.roles().create(role);

        role = realm.roles().get("test").toRepresentation();
        assertNotNull(role);

        realm.roles().get(Constants.DEFAULT_ROLES_ROLE_PREFIX + "-" + REALM_NAME).addComposites(Collections.singletonList(role));


        realm.roles().deleteRole("test");

        try {
            realm.roles().get("testsadfsadf").toRepresentation();
            fail("Expected NotFoundException");
        } catch (NotFoundException e) {
            // Expected
        }
    }

    @Test
    public void convertKeycloakClientDescription() throws IOException {
        ClientRepresentation description = new ClientRepresentation();
        description.setClientId("client-id");
        description.setRedirectUris(Collections.singletonList("http://localhost"));

        ClientRepresentation converted = realm.convertClientDescription(JsonSerialization.writeValueAsString(description));
        assertEquals("client-id", converted.getClientId());
        assertEquals("http://localhost", converted.getRedirectUris().get(0));
    }

    @Test
    public void convertOIDCClientDescription() throws IOException {
        String description = IOUtils.toString(getClass().getResourceAsStream("/client-descriptions/client-oidc.json"), Charset.defaultCharset());

        ClientRepresentation converted = realm.convertClientDescription(description);
        assertEquals(1, converted.getRedirectUris().size());
        assertEquals("http://localhost", converted.getRedirectUris().get(0));
    }

    @Test
    public void convertSAMLClientDescription() throws IOException {
        String description = IOUtils.toString(getClass().getResourceAsStream("/client-descriptions/saml-entity-descriptor.xml"), Charset.defaultCharset());

        ClientRepresentation converted = realm.convertClientDescription(description);
        assertEquals("loadbalancer-9.siroe.com", converted.getClientId());
        assertEquals(2, converted.getRedirectUris().size());
        assertEquals("https://LoadBalancer-9.siroe.com:3443/federation/Consumer/metaAlias/sp", converted.getRedirectUris().get(0));
        assertEquals("https://LoadBalancer-9.siroe.com:3443/federation/Consumer/metaAlias/sp", converted.getRedirectUris().get(1));
    }

    public static void assertRealm(RealmRepresentation realm, RealmRepresentation storedRealm) {
        if (realm.getRealm() != null) {
            assertEquals(realm.getRealm(), storedRealm.getRealm());
        }
        if (realm.isEnabled() != null) assertEquals(realm.isEnabled(), storedRealm.isEnabled());
        if (realm.isBruteForceProtected() != null) assertEquals(realm.isBruteForceProtected(), storedRealm.isBruteForceProtected());
        if (realm.getMaxFailureWaitSeconds() != null) assertEquals(realm.getMaxFailureWaitSeconds(), storedRealm.getMaxFailureWaitSeconds());
        if (realm.getMinimumQuickLoginWaitSeconds() != null) assertEquals(realm.getMinimumQuickLoginWaitSeconds(), storedRealm.getMinimumQuickLoginWaitSeconds());
        if (realm.getWaitIncrementSeconds() != null) assertEquals(realm.getWaitIncrementSeconds(), storedRealm.getWaitIncrementSeconds());
        if (realm.getQuickLoginCheckMilliSeconds() != null) assertEquals(realm.getQuickLoginCheckMilliSeconds(), storedRealm.getQuickLoginCheckMilliSeconds());
        if (realm.getMaxDeltaTimeSeconds() != null) assertEquals(realm.getMaxDeltaTimeSeconds(), storedRealm.getMaxDeltaTimeSeconds());
        if (realm.getFailureFactor() != null) assertEquals(realm.getFailureFactor(), storedRealm.getFailureFactor());
        if (realm.isRegistrationAllowed() != null) assertEquals(realm.isRegistrationAllowed(), storedRealm.isRegistrationAllowed());
        if (realm.isRegistrationEmailAsUsername() != null) assertEquals(realm.isRegistrationEmailAsUsername(), storedRealm.isRegistrationEmailAsUsername());
        if (realm.isRememberMe() != null) assertEquals(realm.isRememberMe(), storedRealm.isRememberMe());
        if (realm.isVerifyEmail() != null) assertEquals(realm.isVerifyEmail(), storedRealm.isVerifyEmail());
        if (realm.isLoginWithEmailAllowed() != null) assertEquals(realm.isLoginWithEmailAllowed(), storedRealm.isLoginWithEmailAllowed());
        if (realm.isDuplicateEmailsAllowed() != null) assertEquals(realm.isDuplicateEmailsAllowed(), storedRealm.isDuplicateEmailsAllowed());
        if (realm.isResetPasswordAllowed() != null) assertEquals(realm.isResetPasswordAllowed(), storedRealm.isResetPasswordAllowed());
        if (realm.isEditUsernameAllowed() != null) assertEquals(realm.isEditUsernameAllowed(), storedRealm.isEditUsernameAllowed());
        if (realm.getSslRequired() != null) assertEquals(realm.getSslRequired(), storedRealm.getSslRequired());
        if (realm.getAccessCodeLifespan() != null) assertEquals(realm.getAccessCodeLifespan(), storedRealm.getAccessCodeLifespan());
        if (realm.getAccessCodeLifespanUserAction() != null)
            assertEquals(realm.getAccessCodeLifespanUserAction(), storedRealm.getAccessCodeLifespanUserAction());
        if (realm.getActionTokenGeneratedByAdminLifespan() != null)
            assertEquals(realm.getActionTokenGeneratedByAdminLifespan(), storedRealm.getActionTokenGeneratedByAdminLifespan());
        if (realm.getActionTokenGeneratedByUserLifespan() != null)
            assertEquals(realm.getActionTokenGeneratedByUserLifespan(), storedRealm.getActionTokenGeneratedByUserLifespan());
        else
            assertEquals(realm.getAccessCodeLifespanUserAction(), storedRealm.getActionTokenGeneratedByUserLifespan());
        if (realm.getNotBefore() != null) assertEquals(realm.getNotBefore(), storedRealm.getNotBefore());
        if (realm.getAccessTokenLifespan() != null) assertEquals(realm.getAccessTokenLifespan(), storedRealm.getAccessTokenLifespan());
        if (realm.getAccessTokenLifespanForImplicitFlow() != null) assertEquals(realm.getAccessTokenLifespanForImplicitFlow(), storedRealm.getAccessTokenLifespanForImplicitFlow());
        if (realm.getSsoSessionIdleTimeout() != null) assertEquals(realm.getSsoSessionIdleTimeout(), storedRealm.getSsoSessionIdleTimeout());
        if (realm.getSsoSessionMaxLifespan() != null) assertEquals(realm.getSsoSessionMaxLifespan(), storedRealm.getSsoSessionMaxLifespan());
        if (realm.getSsoSessionIdleTimeoutRememberMe() != null) assertEquals(realm.getSsoSessionIdleTimeoutRememberMe(), storedRealm.getSsoSessionIdleTimeoutRememberMe());
        if (realm.getSsoSessionMaxLifespanRememberMe() != null) assertEquals(realm.getSsoSessionMaxLifespanRememberMe(), storedRealm.getSsoSessionMaxLifespanRememberMe());
        if (realm.getClientSessionIdleTimeout() != null)
            assertEquals(realm.getClientSessionIdleTimeout(), storedRealm.getClientSessionIdleTimeout());
        if (realm.getClientSessionMaxLifespan() != null)
            assertEquals(realm.getClientSessionMaxLifespan(), storedRealm.getClientSessionMaxLifespan());
        if (realm.getClientOfflineSessionIdleTimeout() != null)
            assertEquals(realm.getClientOfflineSessionIdleTimeout(), storedRealm.getClientOfflineSessionIdleTimeout());
        if (realm.getClientOfflineSessionMaxLifespan() != null)
            assertEquals(realm.getClientOfflineSessionMaxLifespan(), storedRealm.getClientOfflineSessionMaxLifespan());
        if (realm.getRequiredCredentials() != null) {
            assertNotNull(storedRealm.getRequiredCredentials());
            for (String cred : realm.getRequiredCredentials()) {
                assertTrue(storedRealm.getRequiredCredentials().contains(cred));
            }
        }
        if (realm.getLoginTheme() != null) assertEquals(realm.getLoginTheme(), storedRealm.getLoginTheme());
        if (realm.getAccountTheme() != null) assertEquals(realm.getAccountTheme(), storedRealm.getAccountTheme());
        if (realm.getAdminTheme() != null) assertEquals(realm.getAdminTheme(), storedRealm.getAdminTheme());
        if (realm.getEmailTheme() != null) assertEquals(realm.getEmailTheme(), storedRealm.getEmailTheme());

        if (realm.getPasswordPolicy() != null) assertEquals(realm.getPasswordPolicy(), storedRealm.getPasswordPolicy());

        if (realm.getSmtpServer() != null) {
            assertEquals(realm.getSmtpServer(), storedRealm.getSmtpServer());
        }

        if (realm.getBrowserSecurityHeaders() != null) {
            assertEquals(realm.getBrowserSecurityHeaders(), storedRealm.getBrowserSecurityHeaders());
        }

        if (realm.getAttributes() != null) {
            HashMap<String, String> attributes = new HashMap<>();
            attributes.putAll(storedRealm.getAttributes());
            attributes.entrySet().retainAll(realm.getAttributes().entrySet());
            assertEquals(realm.getAttributes(), attributes);
        }

        if (realm.isUserManagedAccessAllowed() != null) assertEquals(realm.isUserManagedAccessAllowed(), storedRealm.isUserManagedAccessAllowed());
    }

    // NOTE: clearKeysCache tested in KcOIDCBrokerWithSignatureTest
    @Test
    // KEYCLOAK-17342
    public void testDefaultSignatureAlgorithm() {
        RealmRepresentation rep = new RealmRepresentation();
        rep.setRealm("new-realm");

        adminClient.realms().create(rep);

        assertEquals(Constants.DEFAULT_SIGNATURE_ALGORITHM, adminClient.realm("master").toRepresentation().getDefaultSignatureAlgorithm());
        assertEquals(Constants.DEFAULT_SIGNATURE_ALGORITHM, adminClient.realm("new-realm").toRepresentation().getDefaultSignatureAlgorithm());
        adminClient.realms().realm("new-realm").remove();
    }

    @KeycloakVersion(min = "25.0.0")
    @Test
    public void testSupportedOTPApplications() {
        RealmRepresentation rep = new RealmRepresentation();
        rep.setRealm("new-realm");

        adminClient.realms().create(rep);

        RealmResource realm = adminClient.realms().realm("new-realm");

        rep = realm.toRepresentation();

        List<String> supportedApplications = rep.getOtpSupportedApplications();
        assertThat(supportedApplications, hasSize(3));
        assertThat(supportedApplications, containsInAnyOrder("totpAppGoogleName", "totpAppFreeOTPName", "totpAppMicrosoftAuthenticatorName"));

        rep.setOtpPolicyDigits(8);
        realm.update(rep);

        rep = realm.toRepresentation();

        supportedApplications = rep.getOtpSupportedApplications();
        assertThat(supportedApplications, hasSize(2));
        assertThat(supportedApplications, containsInAnyOrder("totpAppFreeOTPName", "totpAppGoogleName"));

        rep.setOtpPolicyType("hotp");
        realm.update(rep);

        rep = realm.toRepresentation();

        supportedApplications = rep.getOtpSupportedApplications();
        assertThat(supportedApplications, hasSize(2));
        assertThat(supportedApplications, containsInAnyOrder("totpAppFreeOTPName", "totpAppGoogleName"));
        adminClient.realms().realm("new-realm").remove();
    }

    @Test
    public void testNoUserProfileProviderComponentUponRealmChange() {
        String realmName = "new-realm";
        RealmRepresentation rep = new RealmRepresentation();
        rep.setRealm(realmName);

        adminClient.realms().create(rep);

        assertThat(adminClient.realm(realmName).components().query(null, "UserProfileProvider"), empty());

        rep.setDisplayName("displayName");
        adminClient.realm(realmName).update(rep);

        // this used to return non-empty collection
        assertThat(adminClient.realm(realmName).components().query(null, "UserProfileProvider"), empty());

        adminClient.realms().realm(realmName).remove();
    }

    @Test
    public void testSetEmptyAttributeValues() {
        String realmName = "testSetEmptyAttributeValues";
        RealmRepresentation rep = new RealmRepresentation();
        rep.setRealm(realmName);
        rep.setAttributes(new HashMap<>());
        rep.getAttributes().put("myboolean", "");
        rep.getAttributes().put(RealmAttributes.ACTION_TOKEN_GENERATED_BY_USER_LIFESPAN + ".something", "");

        adminClient.realms().create(rep);

        RealmRepresentation realmRepresentation = adminClient.realms().realm(realmName).toRepresentation();
        Assert.assertNotNull(realmRepresentation.getAttributes().get("myboolean"));
        adminClient.realm(realmName).remove();
    }
}
