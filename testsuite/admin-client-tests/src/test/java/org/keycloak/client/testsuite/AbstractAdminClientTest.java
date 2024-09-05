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

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.admin.client.resource.RealmsResource;
import org.keycloak.client.testsuite.common.OAuthClient;
import org.keycloak.client.testsuite.common.RealmImporter;
import org.keycloak.client.testsuite.common.RealmRepsSupplier;
import org.keycloak.client.testsuite.framework.Inject;
import org.keycloak.representations.idm.RealmRepresentation;
import org.keycloak.representations.idm.RoleRepresentation;
import org.keycloak.testsuite.util.RoleBuilder;
import org.keycloak.util.JsonSerialization;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public abstract class AbstractAdminClientTest implements RealmRepsSupplier {

    protected static final String REALM_NAME = "admin-client-test";

    protected RealmResource realm;
    protected String realmId;

    @org.keycloak.client.testsuite.framework.Inject
    protected Keycloak adminClient;

    @org.keycloak.client.testsuite.framework.Inject
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
}