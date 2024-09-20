/*
 * Copyright 2018 Red Hat, Inc. and/or its affiliates
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

import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.keycloak.admin.client.resource.ClientResource;
import org.keycloak.admin.client.resource.ClientsResource;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.representations.idm.ProtocolMapperRepresentation;
import org.keycloak.representations.idm.RealmRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.keycloak.representations.idm.authorization.AbstractPolicyRepresentation;
import org.keycloak.representations.idm.authorization.DecisionEffect;
import org.keycloak.representations.idm.authorization.JSPolicyRepresentation;
import org.keycloak.representations.idm.authorization.Logic;
import org.keycloak.representations.idm.authorization.PolicyEvaluationRequest;
import org.keycloak.representations.idm.authorization.PolicyEvaluationResponse;
import org.keycloak.representations.idm.authorization.ResourcePermissionRepresentation;
import org.keycloak.representations.idm.authorization.ResourceRepresentation;
import org.keycloak.representations.idm.authorization.ScopePermissionRepresentation;
import org.keycloak.representations.idm.authorization.ScopeRepresentation;
import org.keycloak.representations.idm.authorization.TimePolicyRepresentation;
import org.keycloak.representations.userprofile.config.UPConfig;
import org.keycloak.testsuite.util.ClientBuilder;
import org.keycloak.testsuite.util.GroupBuilder;
import org.keycloak.testsuite.util.RealmBuilder;
import org.keycloak.testsuite.util.RoleBuilder;
import org.keycloak.testsuite.util.RolesBuilder;
import org.keycloak.testsuite.util.UserBuilder;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class PolicyEvaluationTest extends AbstractAuthzTest {

    @Override
    public List<RealmRepresentation> getRealmsForImport()  {
        List<RealmRepresentation> testRealms = new ArrayList<>();

        ProtocolMapperRepresentation groupProtocolMapper = new ProtocolMapperRepresentation();

        groupProtocolMapper.setName("groups");
        groupProtocolMapper.setProtocolMapper("oidc-group-membership-mapper");
        groupProtocolMapper.setProtocol("openid-connect");
        Map<String, String> config = new HashMap<>();
        config.put("claim.name", "groups");
        config.put("access.token.claim", "true");
        config.put("id.token.claim", "true");
        config.put("full.path", "true");
        groupProtocolMapper.setConfig(config);

        testRealms.add(RealmBuilder.create().name("authz-test")
                .roles(RolesBuilder.create()
                        .realmRole(RoleBuilder.create().name("uma_authorization").build())
                        .realmRole(RoleBuilder.create().name("role-a").build())
                        .realmRole(RoleBuilder.create().name("role-b").build())
                )
                .group(GroupBuilder.create().name("Group A")
                        .subGroups(Arrays.asList("Group B", "Group D").stream().map(name -> {
                            if ("Group B".equals(name)) {
                                return GroupBuilder.create().name(name).subGroups(Arrays.asList("Group C", "Group E").stream()
                                        .map((String name1) -> GroupBuilder.create().name(name1).build())
                                        .collect(Collectors.toList()))
                                        .build();
                            }
                            return GroupBuilder.create().name(name).realmRoles(Arrays.asList("role-a")).build();
                        }).collect(Collectors.toList())).build())
                .group(GroupBuilder.create().name("Group E").build())
                .user(UserBuilder.create().username("marta").password("password").addRoles("uma_authorization", "role-a").addGroups("Group A"))
                .user(UserBuilder.create().username("alice").password("password").addRoles("uma_authorization").addGroups("/Group A/Group B/Group E"))
                .user(UserBuilder.create().username("kolo").password("password").addRoles("uma_authorization").addGroups("/Group A/Group D"))
                .user(UserBuilder.create().username("trinity").password("password").addRoles("uma_authorization").role("role-mapping-client", "client-role-a"))
                .user(UserBuilder.create().username("jdoe").password("password").addGroups("/Group A/Group B", "/Group A/Group D"))
                .client(ClientBuilder.create().clientId("resource-server-test")
                        .secret("secret")
                        .authorizationServicesEnabled(true)
                        .redirectUris("http://localhost/resource-server-test")
                        .defaultRoles("uma_protection")
                        .directAccessGrants()
                        .protocolMapper(groupProtocolMapper))
                .client(ClientBuilder.create().clientId("role-mapping-client")
                        .defaultRoles("client-role-a", "client-role-b"))
                .build());
        return testRealms;
    }

    private ClientResource getClient(RealmResource realm) {
        ClientsResource clients = realm.clients();
        return clients.findByClientId("resource-server-test").stream()
                .map(representation -> clients.get(representation.getId()))
                .findFirst()
                .orElseThrow(() -> new RuntimeException("Expected client [resource-server-test]"));
    }

    private void remove(ClientResource client, ResourceRepresentation resource) {
        if (resource != null && resource.getId() != null) {
            client.authorization().resources().resource(resource.getId()).remove();
        }
    }

    private void remove(ClientResource client, AbstractPolicyRepresentation policy) {
        if (policy != null && policy.getId() != null) {
            client.authorization().policies().policy(policy.getId()).remove();
        }
    }

    private void remove(ClientResource client, ResourcePermissionRepresentation permission) {
        if (permission != null && permission.getId() != null) {
            client.authorization().permissions().resource().findById(permission.getId()).remove();
        }
    }

    private void remove(ClientResource client, ScopePermissionRepresentation permission) {
        if (permission != null && permission.getId() != null) {
            client.authorization().permissions().scope().findById(permission.getId()).remove();
        }
    }

    private void remove(ClientResource client, ScopeRepresentation scope) {
        if (scope != null && scope.getId() != null) {
            client.authorization().scopes().scope(scope.getId()).remove();
        }
    }

    private ResourceRepresentation createResource(ClientResource client, String name, String... scopes) {
        ResourceRepresentation resource = new ResourceRepresentation(name);
        if (scopes != null && scopes.length > 0) {
            resource.addScope(scopes);
        }
        client.authorization().resources().create(resource).close();
        resource.setId(client.authorization().resources().findByName(resource.getName()).iterator().next().getId());
        return resource;
    }

    private TimePolicyRepresentation createTimePolicy(ClientResource client, boolean valid) {
        TimePolicyRepresentation policy = new TimePolicyRepresentation();
        policy.setName("time-policy");
        long notOnOrAfter = System.currentTimeMillis() + (valid ? 24 * 3600 * 1000 : -24 * 3600 * 1000);
        Date notOnOrAfterDate = new Date(notOnOrAfter);
        policy.setNotOnOrAfter(new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(notOnOrAfterDate));
        client.authorization().policies().time().create(policy).close();
        policy.setId(client.authorization().policies().findByName(policy.getName()).getId());
        return policy;
    }

    private JSPolicyRepresentation createJSPolicy(ClientResource client, String name, Logic logic) {
        JSPolicyRepresentation policy = new JSPolicyRepresentation();
        policy.setName("javascript-policy");
        policy.setType(name);
        policy.setLogic(logic);
        client.authorization().policies().js().create(policy).close();
        policy.setId(client.authorization().policies().findByName(policy.getName()).getId());
        return policy;
    }

    private ResourcePermissionRepresentation createResourcePermission(ClientResource client,
            String name, String resourceId, String policyId) {
        ResourcePermissionRepresentation permission = new ResourcePermissionRepresentation();
        permission.setName(name);
        permission.addResource(resourceId);
        permission.addPolicy(policyId);
        client.authorization().permissions().resource().create(permission).close();
        permission.setId(client.authorization().permissions().resource().findByName(permission.getName()).getId());
        return permission;
    }

    private PolicyEvaluationResponse evaluate(ClientResource client, String userId, String resourceId) {
        PolicyEvaluationRequest request = new PolicyEvaluationRequest();
        request.setUserId(userId);
        request.setClientId(client.toRepresentation().getId());
        request.addResource(resourceId);
        PolicyEvaluationResponse result = client.authorization().policies().evaluate(request);
        return result;
    }

    private ScopeRepresentation createScope(ClientResource client, String name) {
        ScopeRepresentation scope = new ScopeRepresentation();
        scope.setName(name);
        client.authorization().scopes().create(scope).close();
        scope.setId(client.authorization().scopes().findByName(scope.getName()).getId());
        return scope;
    }

    private ScopePermissionRepresentation createScopePermission(ClientResource client, String name, String scopeId, String policyId) {
        ScopePermissionRepresentation permission = new ScopePermissionRepresentation();
        permission.setName(name);
        permission.addScope(scopeId);
        permission.addPolicy(policyId);
        client.authorization().permissions().scope().create(permission).close();
        permission.setId(client.authorization().permissions().resource().findByName(permission.getName()).getId());
        return permission;
    }

    private void testCheckDateAndTime(DecisionEffect effect) {
        RealmResource realm = adminClient.realm("authz-test");
        ClientResource client = getClient(realm);
        UserRepresentation marta = realm.users().search("marta").get(0);

        ResourceRepresentation resource = null;
        TimePolicyRepresentation policy = null;
        ResourcePermissionRepresentation permission = null;

        try {
            resource = createResource(client, "time-resource");
            policy = createTimePolicy(client, DecisionEffect.PERMIT == effect);
            permission = createResourcePermission(client, "time-resource-permission", resource.getId(), policy.getId());

            PolicyEvaluationResponse result = evaluate(client, marta.getId(), resource.getId());
            Assertions.assertEquals(effect, result.getStatus());
        } finally {
            remove(client, permission);
            remove(client, policy);
            remove(client, resource);
        }
    }

    @Test
    public void testCheckDateAndTime() {
        testCheckDateAndTime(DecisionEffect.PERMIT);
        testCheckDateAndTime(DecisionEffect.DENY);
    }

    private void testJavaScriptPolicy(DecisionEffect effect, String name) {
        RealmResource realm = adminClient.realm("authz-test");
        ClientResource client = getClient(realm);
        UserRepresentation marta = realm.users().search("marta").get(0);

        ResourceRepresentation resource = null;
        JSPolicyRepresentation policy = null;
        ResourcePermissionRepresentation permission = null;

        try {
            resource = createResource(client, "js-resource");
            policy = createJSPolicy(client, name, Logic.POSITIVE);
            permission = createResourcePermission(client, "javascript-permission", resource.getId(), policy.getId());

            PolicyEvaluationResponse result = evaluate(client, marta.getId(), resource.getId());
            Assertions.assertEquals(effect, result.getStatus());
        } finally {
            remove(client, permission);
            remove(client, policy);
            remove(client, resource);
        }
    }

    @Test
    public void testCheckUserInGroup() {
        testJavaScriptPolicy(DecisionEffect.DENY, "script-scripts/allow-group-name-in-role-policy.js");
        testJavaScriptPolicy(DecisionEffect.PERMIT, "script-scripts/allow-user-in-group-name-a-policy.js");
        testJavaScriptPolicy(DecisionEffect.PERMIT, "script-scripts/allow-user-in-group-path-a-policy.js");
        testJavaScriptPolicy(DecisionEffect.DENY, "script-scripts/allow-user-in-group-path-b-policy.js");
        testJavaScriptPolicy(DecisionEffect.PERMIT, "script-scripts/allow-alice-in-group-child-e-policy.js");
        testJavaScriptPolicy(DecisionEffect.PERMIT, "script-scripts/allow-alice-in-group-path-a-policy.js");
        testJavaScriptPolicy(DecisionEffect.DENY, "script-scripts/allow-alice-in-group-path-a-no-parent-policy.js");
        testJavaScriptPolicy(DecisionEffect.DENY, "script-scripts/allow-alice-in-group-path-e-policy.js");
        testJavaScriptPolicy(DecisionEffect.DENY, "script-scripts/allow-alice-in-group-name-e-policy.js");
    }

    @Test
    public void testCheckUserInRole() {
        testJavaScriptPolicy(DecisionEffect.PERMIT, "script-scripts/allow-marta-in-role-a-policy.js");
        testJavaScriptPolicy(DecisionEffect.DENY, "script-scripts/allow-marta-in-role-b-policy.js");
    }

    @Test
    public void testCheckUserInClientRole() {
        testJavaScriptPolicy(DecisionEffect.PERMIT, "script-scripts/allow-trinity-in-client-roles-policy.js");
        testJavaScriptPolicy(DecisionEffect.DENY, "script-scripts/allow-trinity-in-client-role-b-policy.js");
    }

    @Test
    public void testCheckGroupInRole() {
        testJavaScriptPolicy(DecisionEffect.PERMIT, "script-scripts/allow-group-in-role-policy.js");
        testJavaScriptPolicy(DecisionEffect.DENY, "script-scripts/allow-child-group-in-role-policy.js");
    }

    @Test
    public void testCheckUserRealmRoles() {
        testJavaScriptPolicy(DecisionEffect.PERMIT, "script-scripts/allow-user-realm-roles-policy.js");
    }

    @Test
    public void testCheckUserClientRoles() {
        testJavaScriptPolicy(DecisionEffect.PERMIT, "script-scripts/allow-user-client-roles-policy.js");
    }

    @Test
    public void testCheckUserGroups() {
        testJavaScriptPolicy(DecisionEffect.PERMIT, "script-scripts/allow-user-from-groups-policy.js");
    }

    @Test
    public void testCheckUserAttributes() {
        RealmResource realm = adminClient.realm("authz-test");

        testJavaScriptPolicy(DecisionEffect.DENY, "script-scripts/allow-user-with-attributes.js");

        UPConfig up = realm.users().userProfile().getConfiguration();
        up.setUnmanagedAttributePolicy(UPConfig.UnmanagedAttributePolicy.ENABLED);
        realm.users().userProfile().update(up);

        try {
            UserRepresentation jdoe = realm.users().search("jdoe").get(0);
            Map<String, List<String>> attrs = new HashMap<>();
            attrs.put("a1", Arrays.asList("1", "2"));
            attrs.put("a2", Arrays.asList("3"));
            jdoe.setAttributes(attrs);
            realm.users().get(jdoe.getId()).update(jdoe);

            testJavaScriptPolicy(DecisionEffect.PERMIT, "script-scripts/allow-user-with-attributes.js");
        } finally {
            up.setUnmanagedAttributePolicy(null);
            realm.users().userProfile().update(up);
        }
    }

    @Test
    public void testCheckResourceAttributes() {
        RealmResource realm = adminClient.realm("authz-test");
        ClientResource client = getClient(realm);
        UserRepresentation marta = realm.users().search("marta").get(0);

        ResourceRepresentation resource = null;
        JSPolicyRepresentation policy = null;
        ResourcePermissionRepresentation permission = null;

        try {
            // create a resource bur with the attributes list
            resource = new ResourceRepresentation("js-resource");
            Map<String, List<String>> attrs = new HashMap<>();
            attrs.put("a1", Arrays.asList("1", "2"));
            attrs.put("a2", Arrays.asList("3"));
            resource.setAttributes(attrs);
            client.authorization().resources().create(resource).close();
            resource.setId(client.authorization().resources().findByName(resource.getName()).iterator().next().getId());

            policy = createJSPolicy(client, "script-scripts/allow-resources-with-attributes.js", Logic.POSITIVE);
            permission = createResourcePermission(client, "javascript-permission", resource.getId(), policy.getId());

            PolicyEvaluationResponse result = evaluate(client, marta.getId(), resource.getId());
            Assertions.assertEquals(DecisionEffect.PERMIT, result.getStatus());
        } finally {
            remove(client, permission);
            remove(client, policy);
            remove(client, resource);
        }
    }

    @Test
    public void testCachedDecisionsWithNegativePolicies() {
        RealmResource realm = adminClient.realm("authz-test");
        ClientResource client = getClient(realm);
        UserRepresentation marta = realm.users().search("marta").get(0);

        ScopeRepresentation readScope = null;
        ScopeRepresentation writeScope = null;
        ResourceRepresentation resource = null;
        JSPolicyRepresentation policy = null;
        ScopePermissionRepresentation readPermission = null;
        ScopePermissionRepresentation writePermission = null;

        try {
            readScope = createScope(client, "read");
            writeScope = createScope(client, "write");
            resource = createResource(client, "resource", readScope.getName(), writeScope.getName());
            policy = createJSPolicy(client, "script-scripts/default-policy.js", Logic.NEGATIVE);
            readPermission = createScopePermission(client, "read-premission", readScope.getId(), policy.getId());
            writePermission = createScopePermission(client, "write-premission", writeScope.getId(), policy.getId());

            PolicyEvaluationResponse result = evaluate(client, marta.getId(), resource.getId());
            Assertions.assertEquals(DecisionEffect.DENY, result.getStatus());
        } finally {
            remove(client, readPermission);
            remove(client, writePermission);
            remove(client, policy);
            remove(client, resource);
            remove(client, readScope);
            remove(client, writeScope);
        }
    }
}
