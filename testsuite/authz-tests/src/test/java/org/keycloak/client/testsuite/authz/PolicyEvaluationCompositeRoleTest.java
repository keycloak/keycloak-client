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
package org.keycloak.client.testsuite.authz;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.keycloak.admin.client.resource.AuthorizationResource;
import org.keycloak.admin.client.resource.ClientResource;
import org.keycloak.admin.client.resource.ClientsResource;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.representations.idm.RealmRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.keycloak.representations.idm.authorization.DecisionEffect;
import org.keycloak.representations.idm.authorization.DecisionStrategy;
import org.keycloak.representations.idm.authorization.Logic;
import org.keycloak.representations.idm.authorization.PolicyEvaluationRequest;
import org.keycloak.representations.idm.authorization.PolicyEvaluationResponse;
import org.keycloak.representations.idm.authorization.ResourceRepresentation;
import org.keycloak.representations.idm.authorization.RolePolicyRepresentation;
import org.keycloak.representations.idm.authorization.ScopePermissionRepresentation;
import org.keycloak.representations.idm.authorization.ScopeRepresentation;
import org.keycloak.testsuite.util.ClientBuilder;
import org.keycloak.testsuite.util.RealmBuilder;
import org.keycloak.testsuite.util.RoleBuilder;
import org.keycloak.testsuite.util.RolesBuilder;
import org.keycloak.testsuite.util.UserBuilder;

/**
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 */
public class PolicyEvaluationCompositeRoleTest extends AbstractAuthzTest {

    @Override
    public List<RealmRepresentation> getRealmsForImport() {
        List<RealmRepresentation> testRealms = new ArrayList<>();
        testRealms
            .add(RealmBuilder.create().name("test")
                .user(UserBuilder.create().username("userok").password("password").addRoles("composite"))
                    .user(UserBuilder.create().username("userko").password("password"))
                .client(ClientBuilder.create().clientId("myclient").secret("secret")
                    .authorizationServicesEnabled(true).redirectUris("http://localhost/myclient").directAccessGrants())
                .roles(RolesBuilder.create()
                    .clientRole("myclient", RoleBuilder.create().name("client-role1").build())
                    .realmRole(RoleBuilder.create().name("composite").clientComposite("myclient", "client-role1").build()))
                .build());
        return testRealms;
    }

    private ClientResource getClient() {
        ClientsResource clients = adminClient.realm("test").clients();
        return clients.findByClientId("myclient").stream().map(representation -> clients.get(representation.getId())).findFirst().orElseThrow(() -> new RuntimeException("Expected client [resource-server-test]"));
    }

    private void createRolePolicy() {
        RolePolicyRepresentation policy = new RolePolicyRepresentation();

        policy.setName("client-role1");
        policy.addClientRole("myclient", "client-role1", true);
        policy.setDecisionStrategy(DecisionStrategy.UNANIMOUS);
        policy.setLogic(Logic.POSITIVE);

        getClient().authorization().policies().role().create(policy).close();
    }

    private void createResource() {
        AuthorizationResource authorization = getClient().authorization();
        ResourceRepresentation resource = new ResourceRepresentation("myresource");

        authorization.resources().create(resource).close();
    }

    private void createScope() {
        AuthorizationResource authorization = getClient().authorization();
        ScopeRepresentation scope = new ScopeRepresentation("myscope");

        authorization.scopes().create(scope).close();
    }

    private void createScopePermission() {
        ScopePermissionRepresentation permission = new ScopePermissionRepresentation();

        permission.setName("mypermission");
        permission.addResource("myresource");
        permission.addPolicy("client-role1");
        permission.setScopes(new HashSet<>(Arrays.asList("myscope")));

        getClient().authorization().permissions().scope().create(permission).close();
    }

    @Test
    public void testCreate() throws Exception {
        createResource();
        createScope();
        createRolePolicy();
        createScopePermission();

        RealmResource realm = adminClient.realm("test");
        String resourceServerId = realm.clients().findByClientId("myclient").get(0).getId();
        UserRepresentation userok = realm.users().search("userok").get(0);
        UserRepresentation userko = realm.users().search("userko").get(0);

        PolicyEvaluationRequest request = new PolicyEvaluationRequest();
        request.setUserId(userok.getId());
        request.setClientId(resourceServerId);
        request.addResource("myresource");
        PolicyEvaluationResponse result = realm.clients().get(resourceServerId).authorization().policies().evaluate(request);
        Assertions.assertEquals(DecisionEffect.PERMIT, result.getStatus());

        request = new PolicyEvaluationRequest();
        request.setUserId(userko.getId());
        request.setClientId(resourceServerId);
        request.addResource("myresource");
        result = realm.clients().get(resourceServerId).authorization().policies().evaluate(request);
        Assertions.assertEquals(DecisionEffect.DENY, result.getStatus());
    }
}