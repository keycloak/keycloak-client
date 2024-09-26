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

package org.keycloak.client.testsuite.authentication;

import jakarta.ws.rs.BadRequestException;
import jakarta.ws.rs.NotFoundException;
import jakarta.ws.rs.core.Response;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.client.testsuite.Assert;
import org.keycloak.representations.idm.AuthenticationExecutionInfoRepresentation;
import org.keycloak.representations.idm.AuthenticationFlowRepresentation;
import org.keycloak.representations.idm.AuthenticatorConfigInfoRepresentation;
import org.keycloak.representations.idm.AuthenticatorConfigRepresentation;

import org.keycloak.testsuite.util.ApiUtil;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.fail;
import static org.junit.jupiter.api.Assertions.assertNull;

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class AuthenticatorConfigTest extends AbstractAuthenticationTest {

    private String executionId;

    @BeforeEach
    public void beforeConfigTest() {
        AuthenticationFlowRepresentation flowRep = newFlow("firstBrokerLogin2", "firstBrokerLogin2", "basic-flow", true, false);
        createFlow(flowRep);

        HashMap<String, Object> params = new HashMap<>();
        params.put("provider", "idp-create-user-if-unique");
        authMgmtResource.addExecution("firstBrokerLogin2", params);

        List<AuthenticationExecutionInfoRepresentation> executionReps = authMgmtResource.getExecutions("firstBrokerLogin2");
        AuthenticationExecutionInfoRepresentation exec = findExecutionByProvider("idp-create-user-if-unique", executionReps);
        assertNotNull(exec);
        executionId = exec.getId();
    }

    @Test
    public void testCreateConfigWithReservedChar() {
        AuthenticatorConfigRepresentation cfg = newConfig("f!oo", "require.password.update.after.registration", "true");
        Response resp = authMgmtResource.newExecutionConfig(executionId, cfg);
        assertEquals(400, resp.getStatus());
    }

    @Test
    public void testCreateConfig() {
        AuthenticatorConfigRepresentation cfg = newConfig("foo", "require.password.update.after.registration", "true");

        // Attempt to create config for non-existent execution
        Response response = authMgmtResource.newExecutionConfig("exec-id-doesnt-exists", cfg);
        assertEquals(404, response.getStatus());
        response.close();

        // Create config success
        String cfgId = createConfig(executionId, cfg);

        // Assert found
        AuthenticatorConfigRepresentation cfgRep = authMgmtResource.getAuthenticatorConfig(cfgId);
        assertConfig(cfgRep, cfgId, "foo", "require.password.update.after.registration", "true");

        // Cleanup
        authMgmtResource.removeAuthenticatorConfig(cfgId);
    }

    @Test
    public void testUpdateConfigWithBadChar() {
        try {
            AuthenticatorConfigRepresentation cfg = newConfig("foo", "require.password.update.after.registration", "true");
            String cfgId = createConfig(executionId, cfg);
            AuthenticatorConfigRepresentation cfgRep = authMgmtResource.getAuthenticatorConfig(cfgId);

            cfgRep.setAlias("Bad@Char");
            authMgmtResource.updateAuthenticatorConfig(cfgRep.getId(), cfgRep);
            fail();
        }
        catch (BadRequestException e) {
        }
    }
    
    @Test
    public void testUpdateConfig() {
        AuthenticatorConfigRepresentation cfg = newConfig("foo", "require.password.update.after.registration", "true");
        String cfgId = createConfig(executionId, cfg);
        AuthenticatorConfigRepresentation cfgRep = authMgmtResource.getAuthenticatorConfig(cfgId);

        // Try to update not existent config
        try {
            authMgmtResource.updateAuthenticatorConfig("not-existent", cfgRep);
            fail("Config didn't found");
        } catch (NotFoundException nfe) {
            // Expected
        }

        // Assert nothing changed
        cfgRep = authMgmtResource.getAuthenticatorConfig(cfgId);
        assertConfig(cfgRep, cfgId, "foo", "require.password.update.after.registration", "true");

        // Update success
        cfgRep.setAlias("foo2");
        cfgRep.getConfig().put("configKey2", "configValue2");
        authMgmtResource.updateAuthenticatorConfig(cfgRep.getId(), cfgRep);

        // Assert updated
        cfgRep = authMgmtResource.getAuthenticatorConfig(cfgRep.getId());
        assertConfig(cfgRep, cfgId, "foo2",
                "require.password.update.after.registration", "true",
                "configKey2", "configValue2");
    }


    @Test
    public void testRemoveConfig() {
        AuthenticatorConfigRepresentation cfg = newConfig("foo", "require.password.update.after.registration", "true");
        String cfgId = createConfig(executionId, cfg);
        AuthenticatorConfigRepresentation cfgRep = authMgmtResource.getAuthenticatorConfig(cfgId);

        // Assert execution has our config
        AuthenticationExecutionInfoRepresentation execution = findExecutionByProvider(
                "idp-create-user-if-unique", authMgmtResource.getExecutions("firstBrokerLogin2"));
        assertEquals(cfgRep.getId(), execution.getAuthenticationConfig());


        // Test remove not-existent
        try {
            authMgmtResource.removeAuthenticatorConfig("not-existent");
            fail("Config didn't found");
        } catch (NotFoundException nfe) {
            // Expected
        }

        // Test remove our config
        authMgmtResource.removeAuthenticatorConfig(cfgId);

        // Assert config not found
        try {
            authMgmtResource.getAuthenticatorConfig(cfgRep.getId());
            fail("Not expected to find config");
        } catch (NotFoundException nfe) {
            // Expected
        }

        // Assert execution doesn't have our config
        execution = findExecutionByProvider(
                "idp-create-user-if-unique", authMgmtResource.getExecutions("firstBrokerLogin2"));
        assertNull(execution.getAuthenticationConfig());
    }

    @Test
    public void testNullsafetyIterationOverProperties() {
        String providerId = "auth-cookie";
        String providerName = "Cookie";
        AuthenticatorConfigInfoRepresentation description = authMgmtResource.getAuthenticatorConfigDescription(providerId);

        assertEquals(providerName, description.getName());
        assertTrue(description.getProperties().isEmpty());
    }

    private String createConfig(String executionId, AuthenticatorConfigRepresentation cfg) {
        Response resp = authMgmtResource.newExecutionConfig(executionId, cfg);
        assertEquals(201, resp.getStatus());
        String cfgId = ApiUtil.getCreatedId(resp);
        assertNotNull(cfgId);
        return cfgId;
    }

    private AuthenticatorConfigRepresentation newConfig(String alias, String cfgKey, String cfgValue) {
        AuthenticatorConfigRepresentation cfg = new AuthenticatorConfigRepresentation();
        cfg.setAlias(alias);
        Map<String, String> cfgMap = new HashMap<>();
        cfgMap.put(cfgKey, cfgValue);
        cfg.setConfig(cfgMap);
        return cfg;
    }

    private void assertConfig(AuthenticatorConfigRepresentation cfgRep, String id, String alias, String... fields) {
        assertEquals(id, cfgRep.getId());
        assertEquals(alias, cfgRep.getAlias());
        Assert.assertMap(cfgRep.getConfig(), fields);
    }
}
