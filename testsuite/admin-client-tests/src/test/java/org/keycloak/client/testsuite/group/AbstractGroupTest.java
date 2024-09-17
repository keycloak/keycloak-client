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

package org.keycloak.client.testsuite.group;

import jakarta.ws.rs.core.Response;
import org.junit.jupiter.api.BeforeEach;
import org.keycloak.TokenVerifier;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.client.testsuite.AbstractAdminClientTest;
import org.keycloak.common.util.PemUtils;
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.RefreshToken;
import org.keycloak.representations.idm.GroupRepresentation;
import org.keycloak.representations.idm.RealmRepresentation;
import org.keycloak.representations.idm.RoleRepresentation;
import org.keycloak.testsuite.util.ApiUtil;
import org.keycloak.client.testsuite.common.OAuthClient.AccessTokenResponse;
import org.keycloak.testsuite.util.KeyUtils;

import java.security.PublicKey;
import java.util.List;

import static org.keycloak.testsuite.util.ServerURLs.getAuthServerContextRoot;


/**
 * @author <a href="mailto:mstrukel@redhat.com">Marko Strukelj</a>
 */
public abstract class AbstractGroupTest extends AbstractAdminClientTest {

    protected String testRealmId;

    @BeforeEach
    public void beforeAbstractKeycloakTest() throws Exception {
        this.testRealmId = adminClient.realm("test").toRepresentation().getId();
    }

    AccessToken login(String login, String clientId, String clientSecret, String userId) throws Exception {
        AccessTokenResponse tokenResponse = oauth.doGrantAccessTokenRequest("test", login, "password", null, clientId, clientSecret);

        String accessToken = tokenResponse.getAccessToken();
        String refreshToken = tokenResponse.getRefreshToken();

        oauth.realm("test");
        AccessToken accessTokenRepresentation = oauth.verifyToken(accessToken, AccessToken.class);

        JWSInput jws = new JWSInput(refreshToken);
        RefreshToken refreshTokenRepresentation = jws.readJsonContent(RefreshToken.class);

        return accessTokenRepresentation;
    }

    RealmRepresentation loadTestRealm(List<RealmRepresentation> testRealms) {
        RealmRepresentation testRealm = loadJson(getClass().getResourceAsStream("/testrealm.json"), RealmRepresentation.class);
        testRealms.add(testRealm);
        return testRealm;
    }

    GroupRepresentation createGroup(RealmResource realm, GroupRepresentation group) {
        try (Response response = realm.groups().add(group)) {
            String groupId = ApiUtil.getCreatedId(response);
            getCleanup(realm.toRepresentation().getRealm()).addGroupId(groupId);

            // Set ID to the original rep
            group.setId(groupId);
            return group;
        }
    }

    void addSubGroup(RealmResource realm, GroupRepresentation parent, GroupRepresentation child) {
        Response response = realm.groups().add(child);
        child.setId(ApiUtil.getCreatedId(response));
        response = realm.groups().group(parent.getId()).subGroup(child);
        response.close();
    }

    RoleRepresentation createRealmRole(RealmResource realm, RoleRepresentation role) {
        realm.roles().create(role);

        RoleRepresentation created = realm.roles().get(role.getName()).toRepresentation();
        getCleanup(realm.toRepresentation().getRealm()).addRoleId(created.getId());
        return created;
    }
}
