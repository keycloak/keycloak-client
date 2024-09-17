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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import org.keycloak.representations.idm.ProtocolMapperRepresentation;
import org.keycloak.representations.idm.RealmRepresentation;
import org.keycloak.testsuite.util.ClientBuilder;
import org.keycloak.testsuite.util.GroupBuilder;
import org.keycloak.testsuite.util.RealmBuilder;
import org.keycloak.testsuite.util.RoleBuilder;
import org.keycloak.testsuite.util.RolesBuilder;
import org.keycloak.testsuite.util.UserBuilder;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class GroupPathWithoutGroupClaimPolicyTest extends GroupPathPolicyTest {

    @Override
    public List<RealmRepresentation> getRealmsForImport() {
        List<RealmRepresentation> testRealms = new ArrayList<>();
        ProtocolMapperRepresentation groupProtocolMapper = new ProtocolMapperRepresentation();

        groupProtocolMapper.setName("groups");
        groupProtocolMapper.setProtocolMapper("oidc-group-membership-mapper");
        groupProtocolMapper.setProtocol("openid-connect");
        Map<String, String> config = new HashMap<>();
        config.put("claim.name", "groups");
        config.put("access.token.claim", "true");
        config.put("id.token.claim", "true");
        groupProtocolMapper.setConfig(config);

        testRealms.add(RealmBuilder.create().name("authz-test")
                .roles(RolesBuilder.create()
                        .realmRole(RoleBuilder.create().name("uma_authorization").build())
                )
                .group(GroupBuilder.create().name("Group A")
                    .subGroups(Arrays.asList("Group B", "Group D").stream().map(name -> {
                        if ("Group B".equals(name)) {
                            return GroupBuilder.create().name(name).subGroups(Arrays.asList("Group C", "Group E").stream()
                                    .map((String name1) -> GroupBuilder.create().name(name1).build())
                                    .collect(Collectors.toList())).build();
                        }
                        return GroupBuilder.create().name(name).build();
                    }).collect(Collectors.toList())).build())
                .group(GroupBuilder.create().name("Group E").build())
                .user(UserBuilder.create().username("marta").password("password").addRoles("uma_authorization").addGroups("Group A"))
                .user(UserBuilder.create().username("alice").password("password").addRoles("uma_authorization"))
                .user(UserBuilder.create().username("kolo").password("password").addRoles("uma_authorization"))
                .client(ClientBuilder.create().clientId("resource-server-test")
                    .secret("secret")
                    .authorizationServicesEnabled(true)
                    .redirectUris("http://localhost/resource-server-test")
                    .defaultRoles("uma_protection")
                    .directAccessGrants())
                .build());
        return testRealms;
    }
}