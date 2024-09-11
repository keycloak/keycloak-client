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
package org.keycloak.client.testsuite.authz;

import jakarta.ws.rs.core.Response;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.admin.client.resource.AuthorizationResource;
import org.keycloak.admin.client.resource.ClientResource;
import org.keycloak.admin.client.resource.ClientsResource;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.authorization.client.AuthzClient;
import org.keycloak.client.testsuite.framework.PairwiseHttpServerExtension;
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.JsonWebToken;
import org.keycloak.representations.idm.RealmRepresentation;
import org.keycloak.representations.idm.authorization.AuthorizationRequest;
import org.keycloak.representations.idm.authorization.AuthorizationResponse;
import org.keycloak.representations.idm.authorization.JSPolicyRepresentation;
import org.keycloak.representations.idm.authorization.Permission;
import org.keycloak.representations.idm.authorization.PermissionRequest;
import org.keycloak.representations.idm.authorization.ResourcePermissionRepresentation;
import org.keycloak.representations.idm.authorization.ResourceRepresentation;
import org.keycloak.testsuite.util.ClientBuilder;
import org.keycloak.testsuite.util.RealmBuilder;
import org.keycloak.testsuite.util.RoleBuilder;
import org.keycloak.testsuite.util.RolesBuilder;
import org.keycloak.testsuite.util.UserBuilder;
import org.keycloak.util.JsonSerialization;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
@ExtendWith(PairwiseHttpServerExtension.class)
public class AuthorizationAPITest extends AbstractAuthzTest {

    private static final String RESOURCE_SERVER_TEST = "resource-server-test";
    private static final String TEST_CLIENT = "test-client";
    private static final String AUTHZ_CLIENT_CONFIG = "/authorization-test/default-keycloak.json";
    private static final String PAIRWISE_RESOURCE_SERVER_TEST = "pairwise-resource-server-test";
    private static final String PAIRWISE_TEST_CLIENT = "test-client-pairwise";
    private static final String PAIRWISE_AUTHZ_CLIENT_CONFIG = "/authorization-test/default-keycloak-pairwise.json";

    @Override
    public List<RealmRepresentation> getRealmsForImport() {
        List<RealmRepresentation> testRealms = new ArrayList<>();
        testRealms.add(RealmBuilder.create().name("authz-test")
                .roles(RolesBuilder.create().realmRole(RoleBuilder.create().name("uma_authorization").build()))
                .user(UserBuilder.create().username("marta").password("password").addRoles("uma_authorization"))
                .user(UserBuilder.create().username("kolo").password("password"))
                .client(ClientBuilder.create().clientId(RESOURCE_SERVER_TEST)
                    .secret("secret")
                    .authorizationServicesEnabled(true)
                    .redirectUris("http://localhost/resource-server-test")
                    .defaultRoles("uma_protection")
                    .directAccessGrants())
                .client(ClientBuilder.create().clientId(PAIRWISE_RESOURCE_SERVER_TEST)
                    .secret("secret")
                    .authorizationServicesEnabled(true)
                    .redirectUris("http://localhost/resource-server-test")
                    .defaultRoles("uma_protection")
                    .directAccessGrants()
                    .protocolMapper(createPairwiseMapper(PairwiseHttpServerExtension.HTTP_URL)))
                .client(ClientBuilder.create().clientId(TEST_CLIENT)
                    .secret("secret")
                    .authorizationServicesEnabled(true)
                    .redirectUris("http://localhost/test-client")
                    .directAccessGrants())
                .client(ClientBuilder.create().clientId(PAIRWISE_TEST_CLIENT)
                        .secret("secret")
                        .authorizationServicesEnabled(true)
                        .redirectUris("http://localhost/test-client")
                        .directAccessGrants())
                .build());

        return testRealms;
    }

    @BeforeEach
    public void configureAuthorization() throws Exception {
        configureAuthorization(RESOURCE_SERVER_TEST);
        configureAuthorization(PAIRWISE_RESOURCE_SERVER_TEST);
    }

    private void configureAuthorization(String clientId) throws Exception {
        ClientResource client = getClient(getRealm(), clientId);
        AuthorizationResource authorization = client.authorization();
        ResourceRepresentation resource = new ResourceRepresentation("Resource A");

        Response response = authorization.resources().create(resource);
        response.close();

        JSPolicyRepresentation policy = new JSPolicyRepresentation();

        policy.setName("Default Policy");
        policy.setType("script-scripts/default-policy.js");

        response = authorization.policies().js().create(policy);
        response.close();

        ResourcePermissionRepresentation permission = new ResourcePermissionRepresentation();

        permission.setName(resource.getName() + " Permission");
        permission.addResource(resource.getName());
        permission.addPolicy(policy.getName());

        response = authorization.permissions().resource().create(permission);
        response.close();
    }

    @Test
    public void testAccessTokenWithUmaAuthorization() {
        testAccessTokenWithUmaAuthorization(AUTHZ_CLIENT_CONFIG);
    }

    @Test
    public void testAccessTokenWithUmaAuthorizationPairwise() {
        testAccessTokenWithUmaAuthorization(PAIRWISE_AUTHZ_CLIENT_CONFIG);
    }

    public void testAccessTokenWithUmaAuthorization(String authzConfigFile) {
        AuthzClient authzClient = getAuthzClient(authzConfigFile);
        PermissionRequest request = new PermissionRequest("Resource A");

        String ticket = authzClient.protection().permission().create(request).getTicket();
        AuthorizationResponse response = authzClient.authorization("marta", "password").authorize(new AuthorizationRequest(ticket));

        Assertions.assertNotNull(response.getToken());
    }

    @Test
    public void testResourceServerAsAudience() throws Exception {
        testResourceServerAsAudience(
                TEST_CLIENT,
                RESOURCE_SERVER_TEST,
                AUTHZ_CLIENT_CONFIG);
    }

    @Test
    public void testResourceServerAsAudienceWithPairwiseClient() throws Exception {
        testResourceServerAsAudience(
                PAIRWISE_TEST_CLIENT,
                RESOURCE_SERVER_TEST,
                AUTHZ_CLIENT_CONFIG);
    }

    @Test
    public void testPairwiseResourceServerAsAudience() throws Exception {
        testResourceServerAsAudience(
                TEST_CLIENT,
                PAIRWISE_RESOURCE_SERVER_TEST,
                PAIRWISE_AUTHZ_CLIENT_CONFIG);
    }

    @Test
    public void testPairwiseResourceServerAsAudienceWithPairwiseClient() throws Exception {
        testResourceServerAsAudience(
                PAIRWISE_TEST_CLIENT,
                PAIRWISE_RESOURCE_SERVER_TEST,
                PAIRWISE_AUTHZ_CLIENT_CONFIG);
    }

    @Test
    public void testResponseMode() {
        AuthzClient authzClient = getAuthzClient(AUTHZ_CLIENT_CONFIG);
        PermissionRequest permission = new PermissionRequest("Resource A");

        String ticket = authzClient.protection().permission().create(permission).getTicket();
        AuthorizationRequest request = new AuthorizationRequest(ticket);
        AuthorizationResponse response = authzClient.authorization("marta", "password").authorize(request);
        Assertions.assertNotNull(response.getToken());

        request.setMetadata(new AuthorizationRequest.Metadata());
        request.getMetadata().setResponseMode("decision");
        response = authzClient.authorization("marta", "password").authorize(request);
        Assertions.assertNull(response.getToken());
        Assertions.assertTrue((Boolean) response.getOtherClaims().getOrDefault("result", "false"));

        List<Permission> permissions = authzClient.authorization("marta", "password").getPermissions(request);
        Assertions.assertFalse(permissions.isEmpty());
        Assertions.assertTrue(permissions.get(0) instanceof Permission);
    }

    public void testResourceServerAsAudience(String clientId, String resourceServerClientId, String authzConfigFile) throws Exception {
        AuthzClient authzClient = getAuthzClient(authzConfigFile);
        PermissionRequest request = new PermissionRequest();

        request.setResourceId("Resource A");

        String accessToken = oauth.realm("authz-test").clientId(clientId).doGrantAccessTokenRequest("secret", "marta", "password").getAccessToken();
        String ticket = authzClient.protection().permission().create(request).getTicket();

        // Ticket is opaque to client or resourceServer. The audience should be just an authorization server itself
        JsonWebToken ticketDecoded = JsonSerialization.readValue(new JWSInput(ticket).getContent(), JsonWebToken.class);
        Assertions.assertFalse(ticketDecoded.hasAudience(clientId));
        Assertions.assertFalse(ticketDecoded.hasAudience(resourceServerClientId));

        AuthorizationResponse response = authzClient.authorization(accessToken).authorize(new AuthorizationRequest(ticket));

        Assertions.assertNotNull(response.getToken());
        AccessToken rpt = toAccessToken(response.getToken());
        Assertions.assertEquals(resourceServerClientId, rpt.getAudience()[0]);
    }

    private RealmResource getRealm() {
        return adminClient.realm("authz-test");
    }

    private ClientResource getClient(RealmResource realm, String clientId) {
        ClientsResource clients = realm.clients();
        return clients.findByClientId(clientId).stream().map(representation -> clients.get(representation.getId())).findFirst().orElseThrow(() -> new RuntimeException("Expected client [resource-server-test]"));
    }
}