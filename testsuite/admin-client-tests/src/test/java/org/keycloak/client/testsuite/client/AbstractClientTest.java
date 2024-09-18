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

package org.keycloak.client.testsuite.client;

import jakarta.ws.rs.core.Response;
import org.junit.jupiter.api.BeforeEach;
import org.keycloak.admin.client.resource.ClientResource;
import org.keycloak.client.testsuite.AbstractAdminClientTest;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.representations.idm.RealmRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.keycloak.testsuite.util.ApiUtil;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 *
 * @author Stan Silvert ssilvert@redhat.com (C) 2016 Red Hat Inc.
 */
public abstract class AbstractClientTest extends AbstractAdminClientTest {

    @BeforeEach
    public void setDefaultPageUriParameters() {
        oauth.realm("test");
    }

    protected RealmRepresentation realmRep() {
        return testRealmResource().toRepresentation();
    }

    protected String getRealmId() {
        return testRealmResource().toRepresentation().getId();
    }

    // returns UserRepresentation retrieved from server, with all fields, including id
    protected UserRepresentation getFullUserRep(String userName) {
        // the search returns all users who has userName contained in their username.
        List<UserRepresentation> results = testRealmResource().users().search(userName, null, null, null, null, null);
        UserRepresentation result = null;
        for (UserRepresentation user : results) {
            if (userName.equals(user.getUsername())) {
                result = user;
            }
        }
        assertNotNull(result, "Did not find user with username " + userName);
        return result;
    }

    protected String createOidcClient(String name) {
        return createClient(createOidcClientRep(name));
    }

    protected String createOidcBearerOnlyClient(String name) {
        ClientRepresentation clientRep = createOidcClientRep(name);
        clientRep.setBearerOnly(Boolean.TRUE);
        clientRep.setPublicClient(Boolean.FALSE);
        return createClient(clientRep);
    }

    protected String createOidcConfidentialClientWithAuthz(String name) {
        ClientRepresentation clientRep = createOidcClientRep(name);
        clientRep.setBearerOnly(Boolean.FALSE);
        clientRep.setPublicClient(Boolean.FALSE);
        clientRep.setAuthorizationServicesEnabled(Boolean.TRUE);
        clientRep.setServiceAccountsEnabled(Boolean.TRUE);
        String id = createClient(clientRep);
        return id;
    }

    protected ClientRepresentation createOidcClientRep(String name) {
        ClientRepresentation clientRep = new ClientRepresentation();
        clientRep.setClientId(name);
        clientRep.setName(name);
        clientRep.setProtocol("openid-connect");
        return clientRep;
    }

    protected String createSamlClient(String name) {
        ClientRepresentation clientRep = new ClientRepresentation();
        clientRep.setClientId(name);
        clientRep.setName(name);
        clientRep.setProtocol("saml");
        return createClient(clientRep);
    }

    protected String createClient(ClientRepresentation clientRep) {
        Response resp = testRealmResource().clients().create(clientRep);
        String id = ApiUtil.getCreatedId(resp);
        resp.close();
        return id;
    }

    protected void removeClient(String clientDbId) {
        testRealmResource().clients().get(clientDbId).remove();
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

}
