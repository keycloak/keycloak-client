/*
  Copyright 2016 Red Hat, Inc. and/or its affiliates
  and other contributors as indicated by the @author tags.

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

 */
package org.keycloak.client.testsuite.authz.admin;

import jakarta.ws.rs.core.Response;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.keycloak.admin.client.resource.AuthorizationResource;
import org.keycloak.admin.client.resource.ClientResource;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.admin.client.resource.ResourceScopeResource;
import org.keycloak.admin.client.resource.ResourceScopesResource;
import org.keycloak.client.testsuite.authz.AbstractAuthzTest;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.representations.idm.RealmRepresentation;
import org.keycloak.representations.idm.authorization.ResourceServerRepresentation;
import org.keycloak.representations.idm.authorization.ScopeRepresentation;
import org.keycloak.testsuite.util.ApiUtil;
import org.keycloak.testsuite.util.ClientBuilder;
import org.keycloak.testsuite.util.RealmBuilder;
import org.keycloak.testsuite.util.RoleBuilder;
import org.keycloak.testsuite.util.RolesBuilder;
import org.keycloak.testsuite.util.UserBuilder;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public abstract class AbstractAuthorizationTest extends AbstractAuthzTest {

    protected static final String RESOURCE_SERVER_CLIENT_ID = "resource-server-test";

    @Override
    public List<RealmRepresentation> getRealmsForImport() {
        List<RealmRepresentation> testRealms = new ArrayList<>();
        testRealms.add(createTestRealm().build());
        return testRealms;
    }

    @AfterEach
    public void onAfterReenableAuthorization() {
        enableAuthorizationServices(false);
        enableAuthorizationServices(true);
    }

    protected RealmResource testRealmResource() {
        return adminClient.realm("authz-test");
    }

    protected String getRealmId() {
        return "authz-test";
    }

    protected ClientResource getClientResource() {
        return ApiUtil.findClientResourceByName(testRealmResource(), RESOURCE_SERVER_CLIENT_ID);
    }

    protected ClientRepresentation getResourceServer() {
        return findClientRepresentation(RESOURCE_SERVER_CLIENT_ID);
    }

    protected ClientRepresentation findClientRepresentation(String name) {
        ClientResource clientRsc = findClientResource(name);
        if (clientRsc == null) return null;
        return findClientResource(name).toRepresentation();
    }

    protected ClientResource findClientResource(String name) {
        return ApiUtil.findClientResourceByName(testRealmResource(), name);
    }

    protected ClientResource findClientResourceById(String id) {
        return ApiUtil.findClientResourceByClientId(testRealmResource(), id);
    }

    protected void enableAuthorizationServices(boolean enable) {
        ClientRepresentation resourceServer = getResourceServer();

        resourceServer.setAuthorizationServicesEnabled(enable);
        resourceServer.setServiceAccountsEnabled(true);
        resourceServer.setPublicClient(false);
        resourceServer.setSecret("secret");

        getClientResource().update(resourceServer);

        if (enable) {
            AuthorizationResource authorization = getClientResource().authorization();
            ResourceServerRepresentation settings = authorization.exportSettings();
            settings.setAllowRemoteResourceManagement(true);
            authorization.update(settings);
        }
    }

    protected ResourceScopeResource createDefaultScope() {
        return createScope("Test Scope", "Scope Icon");
    }

    protected ResourceScopeResource createScope(String name, String iconUri) {
        ScopeRepresentation newScope = new ScopeRepresentation();

        newScope.setName(name);
        newScope.setIconUri(iconUri);

        ResourceScopesResource resources = getClientResource().authorization().scopes();

        try (Response response = resources.create(newScope)) {
            Assertions.assertEquals(Response.Status.CREATED.getStatusCode(), response.getStatus());

            ScopeRepresentation stored = response.readEntity(ScopeRepresentation.class);

            return resources.scope(stored.getId());
        }
    }

    protected RealmBuilder createTestRealm() {
        return RealmBuilder.create().name("authz-test")
                .user(UserBuilder.create().username("marta").password("password"))
                .user(UserBuilder.create().username("kolo").password("password"))
                .roles(RolesBuilder.create().realmRole(RoleBuilder.create().name("realm-role").build()))
                .client(ClientBuilder.create().clientId(RESOURCE_SERVER_CLIENT_ID)
                        .name(RESOURCE_SERVER_CLIENT_ID)
                        .secret("secret")
                        .authorizationServicesEnabled(true)
                        .redirectUris("http://localhost/" + RESOURCE_SERVER_CLIENT_ID)
                        .defaultRoles("uma_protection")
                        .directAccessGrants());
    }
}
