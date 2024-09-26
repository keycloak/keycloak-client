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

import jakarta.ws.rs.core.Response;
import org.junit.jupiter.api.BeforeEach;
import org.keycloak.admin.client.resource.AuthenticationManagementResource;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.client.testsuite.AbstractAdminClientTest;
import org.keycloak.representations.idm.AuthenticationExecutionExportRepresentation;
import org.keycloak.representations.idm.AuthenticationExecutionInfoRepresentation;
import org.keycloak.representations.idm.AuthenticationFlowRepresentation;
import org.keycloak.representations.idm.AuthenticatorConfigRepresentation;
import org.keycloak.testsuite.util.ApiUtil;
import org.keycloak.testsuite.util.RealmBuilder;

import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertNotNull;


/**
 * @author <a href="mailto:mstrukel@redhat.com">Marko Strukelj</a>
 */
public abstract class AbstractAuthenticationTest extends AbstractAdminClientTest {

    static final String REALM_NAME = "test";

    static final String REQUIRED = "REQUIRED";
    static final String CONDITIONAL = "CONDITIONAL";
    static final String DISABLED = "DISABLED";
    static final String ALTERNATIVE = "ALTERNATIVE";

    RealmResource realmResource;
    AuthenticationManagementResource authMgmtResource;
    protected String testRealmId;


    @BeforeEach
    public void before() {
        realmResource = adminClient.realms().realm(REALM_NAME);
        authMgmtResource = realmResource.flows();
        testRealmId = realmResource.toRepresentation().getId();
    }


    public static AuthenticationExecutionInfoRepresentation findExecutionByProvider(String provider, List<AuthenticationExecutionInfoRepresentation> executions) {
        for (AuthenticationExecutionInfoRepresentation exec : executions) {
            if (provider.equals(exec.getProviderId())) {
                return exec;
            }
        }
        return null;
    }

    /**
     * Searches for an execution located before the provided execution on the same level of
     * an authentication flow.
     *
     * @param execution execution to find a neighbor for
     * @param executions list of executions to search in
     * @return execution, or null if not found
     */
    public static AuthenticationExecutionInfoRepresentation findPreviousExecution(AuthenticationExecutionInfoRepresentation execution, List<AuthenticationExecutionInfoRepresentation> executions) {
        for (AuthenticationExecutionInfoRepresentation exec : executions) {
            if (exec.getLevel() != execution.getLevel()) {
                continue;
            }
            if (exec.getIndex() == execution.getIndex() - 1) {
                return exec;
            }
        }
        return null;
    }

    public static AuthenticationFlowRepresentation findFlowByAlias(String alias, List<AuthenticationFlowRepresentation> flows) {
        for (AuthenticationFlowRepresentation flow : flows) {
            if (alias.equals(flow.getAlias())) {
                return flow;
            }
        }
        return null;
    }

    void compareExecution(AuthenticationExecutionInfoRepresentation expected, AuthenticationExecutionInfoRepresentation actual) {
        assertEquals(expected.getRequirement(), actual.getRequirement(), "Execution requirement - " + actual.getProviderId());
        assertEquals(expected.getDisplayName(), actual.getDisplayName(), "Execution display name - " + actual.getProviderId());
        assertEquals(expected.getConfigurable(), actual.getConfigurable(), "Execution configurable - " + actual.getProviderId());
        assertEquals(expected.getProviderId(), actual.getProviderId(), "Execution provider id - " + actual.getProviderId());
        assertEquals(expected.getLevel(), actual.getLevel(), "Execution level - " + actual.getProviderId());
        assertEquals(expected.getAuthenticationFlow(), actual.getAuthenticationFlow(), "Execution authentication flow - " + actual.getProviderId());
        assertEquals(expected.getRequirementChoices(), actual.getRequirementChoices(), "Execution requirement choices - " + actual.getProviderId());
    }

    void compareExecution(AuthenticationExecutionExportRepresentation expected, AuthenticationExecutionExportRepresentation actual) {
        assertEquals(expected.getFlowAlias(), actual.getFlowAlias(), "Execution flowAlias - " + actual.getFlowAlias());
        assertEquals(expected.getAuthenticator(), actual.getAuthenticator(), "Execution authenticator - " + actual.getAuthenticator());
        assertEquals(expected.isUserSetupAllowed(), actual.isUserSetupAllowed(), "Execution userSetupAllowed - " + actual.getAuthenticator());
        assertEquals(expected.isAuthenticatorFlow(), actual.isAuthenticatorFlow(), "Execution authenticatorFlow - " + actual.getAuthenticator());
        assertEquals(expected.getAuthenticatorConfig(), actual.getAuthenticatorConfig(), "Execution authenticatorConfig - " + actual.getAuthenticatorConfig());
        assertEquals(expected.getPriority(), actual.getPriority(), "Execution priority - " + actual.getAuthenticator());
        assertEquals(expected.getRequirement(), actual.getRequirement(), "Execution requirement - " + actual.getAuthenticator());
    }

    void compareExecutions(List<AuthenticationExecutionExportRepresentation> expected, List<AuthenticationExecutionExportRepresentation> actual) {
        assertNotNull(actual, "Executions should not be null");
        assertEquals(expected.size(), actual.size(), "Size");

        for (int i = 0; i < expected.size(); i++) {
            compareExecution(expected.get(i), actual.get(i));
        }
    }

    void compareFlows(AuthenticationFlowRepresentation expected, AuthenticationFlowRepresentation actual) {
        assertEquals(expected.getAlias(), actual.getAlias(), "Flow alias");
        assertEquals(expected.getDescription(), actual.getDescription(), "Flow description");
        assertEquals(expected.getProviderId(), actual.getProviderId(), "Flow providerId");
        assertEquals(expected.isTopLevel(), actual.isTopLevel(), "Flow top level");
        assertEquals(expected.isBuiltIn(), actual.isBuiltIn(), "Flow built-in");

        List<AuthenticationExecutionExportRepresentation> expectedExecs = expected.getAuthenticationExecutions();
        List<AuthenticationExecutionExportRepresentation> actualExecs = actual.getAuthenticationExecutions();

        if (expectedExecs == null) {
            assertTrue(actualExecs == null || actualExecs.size() == 0, "Executions should be null or empty");
        } else {
            compareExecutions(expectedExecs, actualExecs);
        }
    }

    AuthenticationFlowRepresentation newFlow(String alias, String description,
                                                       String providerId, boolean topLevel, boolean builtIn) {
        AuthenticationFlowRepresentation flow = new AuthenticationFlowRepresentation();
        flow.setAlias(alias);
        flow.setDescription(description);
        flow.setProviderId(providerId);
        flow.setTopLevel(topLevel);
        flow.setBuiltIn(builtIn);
        return flow;
    }

    AuthenticationExecutionInfoRepresentation newExecInfo(String displayName, String providerId, Boolean configurable,
                                                          int level, int index, String requirement, Boolean authFlow, String[] choices,
                                                          int priority) {

        AuthenticationExecutionInfoRepresentation execution = new AuthenticationExecutionInfoRepresentation();
        execution.setRequirement(requirement);
        execution.setDisplayName(displayName);
        execution.setConfigurable(configurable);
        execution.setProviderId(providerId);
        execution.setLevel(level);
        execution.setIndex(index);
        execution.setAuthenticationFlow(authFlow);
        execution.setPriority(priority);
        if (choices != null) {
            execution.setRequirementChoices(Arrays.asList(choices));
        }
        return execution;
    }

    void addExecInfo(List<AuthenticationExecutionInfoRepresentation> target, String displayName, String providerId, Boolean configurable,
                 int level, int index, String requirement, Boolean authFlow, String[] choices, int priority) {

        AuthenticationExecutionInfoRepresentation exec = newExecInfo(displayName, providerId, configurable, level, index, requirement, authFlow, choices, priority);
        target.add(exec);
    }

    AuthenticatorConfigRepresentation newConfig(String alias, String[] keyvalues) {
        AuthenticatorConfigRepresentation config = new AuthenticatorConfigRepresentation();
        config.setAlias(alias);

        if (keyvalues == null) {
            throw new IllegalArgumentException("keyvalues == null");
        }
        if (keyvalues.length % 2 != 0) {
            throw new IllegalArgumentException("keyvalues should have even number of elements");
        }

        LinkedHashMap<String, String> params = new LinkedHashMap<>();
        for (int i = 0; i < keyvalues.length; i += 2) {
            params.put(keyvalues[i], keyvalues[i + 1]);
        }
        config.setConfig(params);
        return config;
    }

    String createFlow(AuthenticationFlowRepresentation flowRep) {
        Response response = authMgmtResource.createFlow(flowRep);
        assertEquals(201, response.getStatus());
        response.close();
        String flowId = ApiUtil.getCreatedId(response);
        getCleanup("test").addAuthenticationFlowId(flowId);
        return flowId;
    }
}
