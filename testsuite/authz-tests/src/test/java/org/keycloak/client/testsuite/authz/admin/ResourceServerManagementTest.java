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

package org.keycloak.client.testsuite.authz.admin;

import jakarta.ws.rs.NotFoundException;
import jakarta.ws.rs.core.Response;
import java.util.List;
import java.util.Objects;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.keycloak.admin.client.resource.AuthorizationResource;
import org.keycloak.admin.client.resource.ClientsResource;
import org.keycloak.client.testsuite.framework.KeycloakVersion;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.representations.idm.authorization.DecisionStrategy;
import org.keycloak.representations.idm.authorization.PolicyEnforcementMode;
import org.keycloak.representations.idm.authorization.PolicyRepresentation;
import org.keycloak.representations.idm.authorization.ResourceRepresentation;
import org.keycloak.representations.idm.authorization.ResourceServerRepresentation;
import org.keycloak.representations.idm.authorization.ScopeRepresentation;
import org.keycloak.testsuite.util.ClientBuilder;
import org.keycloak.testsuite.util.KeycloakModelUtils;
import org.keycloak.util.JsonSerialization;

/**
 *
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class ResourceServerManagementTest extends AbstractAuthorizationTest {

    @Test
    public void testCreateAndDeleteResourceServer() throws Exception {
        ClientsResource clientsResource = testRealmResource().clients();

        try (Response response = clientsResource.create(JsonSerialization.readValue(getClass().getResourceAsStream("/authorization-test/client-with-authz-settings.json"), ClientRepresentation.class))) {
            Assertions.assertEquals(201, response.getStatus());
        }

        List<ClientRepresentation> clients = clientsResource.findByClientId("authz-client");

        Assertions.assertFalse(clients.isEmpty());

        String clientId = clients.get(0).getId();
        AuthorizationResource settings = clientsResource.get(clientId).authorization();

        Assertions.assertEquals(PolicyEnforcementMode.PERMISSIVE, settings.exportSettings().getPolicyEnforcementMode());
        Assertions.assertEquals(DecisionStrategy.UNANIMOUS, settings.exportSettings().getDecisionStrategy());

        Assertions.assertFalse(settings.resources().findByName("Resource 1").isEmpty());
        Assertions.assertFalse(settings.resources().findByName("Resource 15").isEmpty());
        Assertions.assertFalse(settings.resources().findByName("Resource 20").isEmpty());

        Assertions.assertNotNull(settings.permissions().resource().findByName("Resource 15 Permission"));
        Assertions.assertNotNull(settings.policies().role().findByName("Resource 1 Policy"));

        clientsResource.get(clientId).remove();

        clients = clientsResource.findByClientId("authz-client");

        Assertions.assertTrue(clients.isEmpty());
    }

    @Test
    public void testInvalidRequestWhenCallingAuthzEndpoints() throws Exception {
        ClientsResource clientsResource = testRealmResource().clients();
        ClientRepresentation clientRepresentation = JsonSerialization.readValue(
                getClass().getResourceAsStream("/authorization-test/client-with-authz-settings.json"),
                ClientRepresentation.class);

        clientRepresentation.setAuthorizationServicesEnabled(false);
        clientRepresentation.setAuthorizationSettings(null);

        try (Response response = clientsResource.create(clientRepresentation)) {
            Assertions.assertEquals(201, response.getStatus());
        }

        List<ClientRepresentation> clients = clientsResource.findByClientId("authz-client");

        Assertions.assertFalse(clients.isEmpty());

        String clientId = clients.get(0).getId();

        NotFoundException nfe = Assertions.assertThrows(NotFoundException.class,
                () -> clientsResource.get(clientId).authorization().getSettings());
        Assertions.assertEquals(404, nfe.getResponse().getStatus());
    }

    @Test
    @KeycloakVersion(min = "25.0")
    public void testImportSettingsToDifferentClient() throws Exception {
        ClientsResource clientsResource = testRealmResource().clients();
        ClientRepresentation clientRep = JsonSerialization.readValue(getClass().getResourceAsStream("/authorization-test/client-with-authz-settings.json"), ClientRepresentation.class);
        clientRep.setClientId(KeycloakModelUtils.generateId());
        try (Response response = clientsResource.create(clientRep)) {
            Assertions.assertEquals(201, response.getStatus());
        }
        List<ClientRepresentation> clients = clientsResource.findByClientId(clientRep.getClientId());
        Assertions.assertFalse(clients.isEmpty());
        String clientId = clients.get(0).getId();
        AuthorizationResource authorization = clientsResource.get(clientId).authorization();
        ResourceServerRepresentation settings = authorization.exportSettings();
        Assertions.assertEquals(PolicyEnforcementMode.PERMISSIVE, settings.getPolicyEnforcementMode());
        Assertions.assertEquals(DecisionStrategy.UNANIMOUS, settings.getDecisionStrategy());
        Assertions.assertFalse(authorization.resources().findByName("Resource 1").isEmpty());
        Assertions.assertFalse(authorization.resources().findByName("Resource 15").isEmpty());
        Assertions.assertFalse(authorization.resources().findByName("Resource 20").isEmpty());
        Assertions.assertNotNull(authorization.permissions().resource().findByName("Resource 15 Permission"));
        Assertions.assertNotNull(authorization.policies().role().findByName("Resource 1 Policy"));
        settings.getPolicies().removeIf(p -> "js".equals(p.getType()));

        ClientRepresentation anotherClientRep = ClientBuilder.create().clientId(KeycloakModelUtils.generateId()).secret("secret").authorizationServicesEnabled(true).serviceAccount().enabled(true).build();
        clientsResource.create(anotherClientRep).close();
        clients = clientsResource.findByClientId(anotherClientRep.getClientId());
        Assertions.assertFalse(clients.isEmpty());
        ClientRepresentation anotherClient = clients.get(0);
        authorization = clientsResource.get(anotherClient.getId()).authorization();
        authorization.importSettings(settings);
        ResourceServerRepresentation anotherSettings = authorization.exportSettings();
        Assertions.assertEquals(PolicyEnforcementMode.PERMISSIVE, anotherSettings.getPolicyEnforcementMode());
        Assertions.assertEquals(DecisionStrategy.UNANIMOUS, anotherSettings.getDecisionStrategy());
        Assertions.assertFalse(authorization.resources().findByName("Resource 1").isEmpty());
        Assertions.assertFalse(authorization.resources().findByName("Resource 15").isEmpty());
        Assertions.assertFalse(authorization.resources().findByName("Resource 20").isEmpty());
        Assertions.assertNotNull(authorization.permissions().resource().findByName("Resource 15 Permission"));
        Assertions.assertNotNull(authorization.policies().role().findByName("Resource 1 Policy"));
    }

    @Test
    @KeycloakVersion(min = "25.0")
    public void testExportSettings() throws Exception {
        ClientsResource clientsResource = testRealmResource().clients();
        ClientRepresentation clientRep = JsonSerialization.readValue(getClass().getResourceAsStream("/authorization-test/client-with-authz-settings.json"), ClientRepresentation.class);
        clientRep.setClientId(KeycloakModelUtils.generateId());
        try (Response response = clientsResource.create(clientRep)) {
            Assertions.assertEquals(201, response.getStatus());
        }
        List<ClientRepresentation> clients = clientsResource.findByClientId(clientRep.getClientId());
        Assertions.assertFalse(clients.isEmpty());
        String clientId = clients.get(0).getId();
        AuthorizationResource authorization = clientsResource.get(clientId).authorization();
        ResourceServerRepresentation settings = authorization.exportSettings();
        Assertions.assertFalse(settings.getResources().stream().map(ResourceRepresentation::getId).anyMatch(Objects::nonNull));
        Assertions.assertFalse(settings.getScopes().stream().map(ScopeRepresentation::getId).anyMatch(Objects::nonNull));
        Assertions.assertFalse(settings.getPolicies().stream().map(PolicyRepresentation::getId).anyMatch(Objects::nonNull));
    }
}