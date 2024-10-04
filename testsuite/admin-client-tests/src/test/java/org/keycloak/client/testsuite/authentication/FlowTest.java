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
import jakarta.ws.rs.ClientErrorException;
import jakarta.ws.rs.InternalServerErrorException;
import jakarta.ws.rs.NotFoundException;
import jakarta.ws.rs.WebApplicationException;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.Response.Status;

import org.junit.jupiter.api.Test;
import org.keycloak.admin.client.resource.ClientResource;
import org.keycloak.admin.client.resource.IdentityProviderResource;
import org.keycloak.client.testsuite.framework.KeycloakVersion;
import org.keycloak.common.util.StreamUtil;
import org.keycloak.representations.idm.AuthenticationExecutionExportRepresentation;
import org.keycloak.representations.idm.AuthenticationExecutionInfoRepresentation;
import org.keycloak.representations.idm.AuthenticationFlowRepresentation;
import org.keycloak.representations.idm.AuthenticatorConfigRepresentation;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.representations.idm.IdentityProviderRepresentation;
import org.keycloak.representations.idm.OAuth2ErrorRepresentation;
import org.keycloak.representations.idm.RealmRepresentation;

import org.keycloak.testsuite.util.ApiUtil;


import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.Charset;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.function.BiConsumer;
import java.util.function.Consumer;
import java.util.function.Predicate;
import java.util.function.Supplier;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.fail;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.testcontainers.shaded.org.hamcrest.MatcherAssert.assertThat;
import static org.testcontainers.shaded.org.hamcrest.core.StringContains.containsString;

/**
 * @author <a href="mailto:mstrukel@redhat.com">Marko Strukelj</a>
 */
public class FlowTest extends AbstractAuthenticationTest {

    // KEYCLOAK-3681: Delete top flow doesn't delete all subflows
    @Test
    public void testRemoveSubflows() {
        createFlow(newFlow("Foo", "Foo flow", "generic", true, false));
        addFlowToParent("Foo", "child");
        addFlowToParent("child", "grandchild");

        List<AuthenticationFlowRepresentation> flows = authMgmtResource.getFlows();
        AuthenticationFlowRepresentation found = findFlowByAlias("Foo", flows);
        authMgmtResource.deleteFlow(found.getId());

        createFlow(newFlow("Foo", "Foo flow", "generic", true, false));
        addFlowToParent("Foo", "child");

        // Under the old code, this would throw an error because "grandchild"
        // was left in the database
        addFlowToParent("child", "grandchild");

        authMgmtResource.deleteFlow(findFlowByAlias("Foo", authMgmtResource.getFlows()).getId());
    }

    @KeycloakVersion(min = "25.0.0")
    @Test
    public void testRemoveExecutionSubflow() {
        createFlow(newFlow("Foo", "Foo flow", "generic", true, false));
        addFlowToParent("Foo", "child");
        addFlowToParent("child", "grandchild");

        // remove the foo child but using the execution
        List<AuthenticationExecutionInfoRepresentation> fooExecutions = authMgmtResource.getExecutions("Foo");
        AuthenticationExecutionInfoRepresentation childExececution = fooExecutions.stream()
                .filter(r -> "child".equals(r.getDisplayName()) && r.getLevel() == 0).findAny().orElse(null);
        assertNotNull(childExececution);
        authMgmtResource.removeExecution(childExececution.getId());

        // check subflows were removed and can be re-created
        addFlowToParent("Foo", "child");
        addFlowToParent("child", "grandchild");

        authMgmtResource.deleteFlow(findFlowByAlias("Foo", authMgmtResource.getFlows()).getId());
    }

    private void addFlowToParent(String parentAlias, String childAlias) {
        Map<String, Object> data = new HashMap<>();
        data.put("alias", childAlias);
        data.put("type", "generic");
        data.put("description", childAlias + " flow");
        authMgmtResource.addExecutionFlow(parentAlias, data);
    }

    @Test
    public void testAddFlowWithRestrictedCharInAlias() {
        Response resp = authMgmtResource.createFlow(newFlow("fo]o", "Browser flow", "basic-flow", true, false));
        assertEquals(400, resp.getStatus());
    }

    @Test
    public void testAddRemoveFlow() {

        // test that built-in flow cannot be deleted
        List<AuthenticationFlowRepresentation> flows = authMgmtResource.getFlows();
        AuthenticationFlowRepresentation builtInFlow = flows.stream().filter(AuthenticationFlowRepresentation::isBuiltIn).findAny().orElse(null);
        assertNotNull(builtInFlow, "No built in flow in the realm");
        try {
            authMgmtResource.deleteFlow(builtInFlow.getId());
            fail("deleteFlow should fail for built in flow");
        } catch (BadRequestException e) {
            OAuth2ErrorRepresentation error = e.getResponse().readEntity(OAuth2ErrorRepresentation.class);
            assertEquals("Can't delete built in flow", error.getError());
        }

        // try create new flow using alias of already existing flow
        Response response = authMgmtResource.createFlow(newFlow("browser", "Browser flow", "basic-flow", true, false));
        try {
            assertEquals(409, response.getStatus(), "createFlow using the alias of existing flow should fail");
        } finally {
            response.close();
        }

        // try create flow without alias
        response = authMgmtResource.createFlow(newFlow(null, "Browser flow", "basic-flow", true, false));
        try {
            assertEquals(409, response.getStatus(), "createFlow using the alias of existing flow should fail");
        } finally {
            response.close();
        }


        // create new flow that should succeed
        AuthenticationFlowRepresentation newFlow = newFlow("browser-2", "Browser flow", "basic-flow", true, false);
        createFlow(newFlow);

        // check that new flow is returned in a children list
        flows = authMgmtResource.getFlows();
        AuthenticationFlowRepresentation found = findFlowByAlias("browser-2", flows);

        assertNotNull(found, "created flow visible in parent");
        compareFlows(newFlow, found);

        // check lookup flow with unexistent ID
        try {
            authMgmtResource.getFlow("id-123-notExistent");
            fail("Not expected to find unexistent flow");
        } catch (NotFoundException nfe) {
            // Expected
        }

        // check that new flow is returned individually
        AuthenticationFlowRepresentation found2 = authMgmtResource.getFlow(found.getId());
        assertNotNull(found2, "created flow visible directly");
        compareFlows(newFlow, found2);


        // add execution flow to some parent flow
        Map<String, Object> data = new HashMap<>();
        data.put("alias", "SomeFlow");
        data.put("type", "basic-flow");
        data.put("description", "Test flow");
        // This tests against a regression in KEYCLOAK-16656
        data.put("provider", "registration-page-form");

        Map<String, Object> data2 = new HashMap<>();
        data2.put("alias", "SomeFlow2");
        data2.put("type", "form-flow");
        data2.put("description", "Test flow 2");
        data2.put("provider", "registration-page-form");


        // inexistent parent flow - should fail
        try {
            authMgmtResource.addExecutionFlow("inexistent-parent-flow-alias", data);
            fail("addExecutionFlow for inexistent parent should have failed");
        } catch (Exception expected) {
            // Expected
        }

        // already existent flow - should fail
        try {
            data.put("alias", "browser");
            authMgmtResource.addExecutionFlow("browser-2", data);
            fail("addExecutionFlow should have failed as browser flow already exists");
        } catch (Exception expected) {
            // Expected
        }

        // Successfully add flow
        data.put("alias", "SomeFlow");
        authMgmtResource.addExecutionFlow("browser-2", data);
        authMgmtResource.addExecutionFlow("browser-2", data2);

        // check that new flow is returned in a children list
        flows = authMgmtResource.getFlows();
        found2 = findFlowByAlias("browser-2", flows);
        assertNotNull(found2, "created flow visible in parent");

        List<AuthenticationExecutionExportRepresentation> execs = found2.getAuthenticationExecutions();
        assertNotNull(execs);
        assertEquals( 2, execs.size());

        AuthenticationExecutionExportRepresentation expected = new AuthenticationExecutionExportRepresentation();
        expected.setFlowAlias("SomeFlow");
        expected.setUserSetupAllowed(false);
        expected.setAuthenticatorFlow(true);
        expected.setRequirement("DISABLED");
        expected.setPriority(0);
        compareExecution(expected, execs.get(0));

        expected = new AuthenticationExecutionExportRepresentation();
        expected.setFlowAlias("SomeFlow2");
        expected.setUserSetupAllowed(false);
        expected.setAuthenticator("registration-page-form");
        expected.setAuthenticatorFlow(true);
        expected.setRequirement("DISABLED");
        expected.setPriority(1);
        compareExecution(expected, execs.get(1));

        // delete non-built-in flow
        authMgmtResource.deleteFlow(found.getId());

        // check the deleted flow is no longer returned
        flows = authMgmtResource.getFlows();
        found = findFlowByAlias("browser-2", flows);
        assertNull(found, "flow deleted");

        // Check deleting flow second time will fail
        try {
            authMgmtResource.deleteFlow("id-123-notExistent");
            fail("Not expected to delete flow, which doesn't exist");
        } catch (NotFoundException nfe) {
            // Expected
        }
    }

    @KeycloakVersion(min = "26.0.0")
    @Test
    public void testRemoveUsedFlow() {
        String flowAlias = "test";
        String flowId = createFlow(newFlow(flowAlias, "Test flow", "generic", true, false));
        Runnable assertRemoveFail = () -> {
            try {
                authMgmtResource.deleteFlow(flowId);
                fail("Not expected to delete flow that is in use.");
            } catch (WebApplicationException e) {
                OAuth2ErrorRepresentation error = e.getResponse().readEntity(OAuth2ErrorRepresentation.class);
                assertThat(error.getErrorDescription(), containsString("For more on this error consult the server log"));
            }
        };

        {
            // used in realm flow
            RealmRepresentation realm = realmResource.toRepresentation();
            BiConsumer<Supplier<String>, Consumer<String>> assertRemoveFailInRealm =
                    (rollbackFlow, updateFlow) -> {
                        String rollbackValue = rollbackFlow.get();
                        try {
                            updateFlow.accept(flowAlias);
                            realmResource.update(realm);

                            assertRemoveFail.run();
                        } finally {
                            updateFlow.accept(rollbackValue);
                            realmResource.update(realm);
                        }
                    };
            assertRemoveFailInRealm.accept(realm::getBrowserFlow, realm::setBrowserFlow);
            assertRemoveFailInRealm.accept(realm::getRegistrationFlow, realm::setRegistrationFlow);
            assertRemoveFailInRealm.accept(realm::getClientAuthenticationFlow, realm::setClientAuthenticationFlow);
            assertRemoveFailInRealm.accept(realm::getDirectGrantFlow, realm::setDirectGrantFlow);
            assertRemoveFailInRealm.accept(realm::getResetCredentialsFlow, realm::setResetCredentialsFlow);
            assertRemoveFailInRealm.accept(realm::getDockerAuthenticationFlow, realm::setDockerAuthenticationFlow);
            assertRemoveFailInRealm.accept(realm::getFirstBrokerLoginFlow, realm::setFirstBrokerLoginFlow);
        }

        {
            // used by client override
            ClientRepresentation client = realmResource.clients().findByClientId("account").get(0);
            ClientResource clientResource = realmResource.clients().get(client.getId());

            Map<String, String> map = new HashMap<>();
            map.put("browser", flowId);
            try {
                client.setAuthenticationFlowBindingOverrides(map);
                clientResource.update(client);

                assertRemoveFail.run();
            } finally {
                map.put("browser", "");
                client.setAuthenticationFlowBindingOverrides(map);
                clientResource.update(client);
            }
        }

        {
            // used by idp override
            IdentityProviderRepresentation idp = new IdentityProviderRepresentation();
            idp.setAlias("idp");
            idp.setProviderId("oidc");

            Response response = realmResource.identityProviders().create(idp);
            assertNotNull(ApiUtil.getCreatedId(response));
            response.close();
            getCleanup("test").addIdentityProviderAlias(idp.getAlias());

            IdentityProviderResource idpResource = realmResource.identityProviders().get("idp");
            BiConsumer<Supplier<String>, Consumer<String>> assertRemoveFailByIdp =
                    (rollbackIdp, updateIdp) -> {
                        String rollbackValue = rollbackIdp.get();
                        try {
                            updateIdp.accept(flowAlias);
                            idpResource.update(idp);

                            assertRemoveFail.run();
                        } finally {
                            updateIdp.accept(rollbackValue);
                            idpResource.update(idp);
                        }
                    };

            assertRemoveFailByIdp.accept(idp::getFirstBrokerLoginFlowAlias, idp::setFirstBrokerLoginFlowAlias);
            assertRemoveFailByIdp.accept(idp::getPostBrokerLoginFlowAlias, idp::setPostBrokerLoginFlowAlias);
        }
    }

    @Test
    @KeycloakVersion(max = "25.0.6")
    public void testCopyFlow() throws IOException {

        HashMap<String, Object> params = new HashMap<>();
        params.put("newName", "clients");

        // copy using existing alias as new name
        Response response = authMgmtResource.copy("browser", params);
        try {
            assertEquals(response.getStatus(), Status.CONFLICT.getStatusCode(), "Copy flow using the new alias of existing flow should fail");
            String responseString = StreamUtil.readString((InputStream) response.getEntity());
            assertThat("Copy flow using the new alias of existing flow should fail", responseString, containsString("already exists"));
            assertThat("Copy flow using the new alias of existing flow should fail", responseString, containsString("flow alias"));
        } finally {
            response.close();
        }

        // copy non-existing flow
        params.clear();
        response = authMgmtResource.copy("non-existent", params);
        try {
            assertEquals(response.getStatus(), Status.NOT_FOUND.getStatusCode(), "Copy non-existing flow");

        } finally {
            response.close();
        }

        // copy that should succeed
        params.put("newName", "Copy of browser");
        response = authMgmtResource.copy("browser", params);
        try {
            assertEquals(response.getStatus(), Status.CREATED.getStatusCode(), "Copy flow");
        } finally {
            response.close();
        }

        // compare original flow with a copy - fields should be the same except id, alias, and builtIn
        List<AuthenticationFlowRepresentation> flows = authMgmtResource.getFlows();
        AuthenticationFlowRepresentation browser = findFlowByAlias("browser", flows);
        AuthenticationFlowRepresentation copyOfBrowser = findFlowByAlias("Copy of browser", flows);

        assertNotNull(browser);
        assertNotNull(copyOfBrowser);

        // adjust expected values before comparing
        browser.setAlias("Copy of browser");
        browser.setBuiltIn(false);
        browser.getAuthenticationExecutions().get(3).setFlowAlias("Copy of browser forms");
        compareFlows(browser, copyOfBrowser);

        // get new flow directly and compare
        copyOfBrowser = authMgmtResource.getFlow(copyOfBrowser.getId());
        assertNotNull(copyOfBrowser);
        compareFlows(browser, copyOfBrowser);
        authMgmtResource.deleteFlow(copyOfBrowser.getId());
    }

    @KeycloakVersion(min = "26")
    public void testCopyFlowOrg() {

        // compare original flow with a copy - fields should be the same except id, alias, and builtIn
        List<AuthenticationFlowRepresentation> flows = authMgmtResource.getFlows();
        AuthenticationFlowRepresentation browser = findFlowByAlias("browser", flows);
        AuthenticationFlowRepresentation copyOfBrowser = findFlowByAlias("Copy of browser", flows);

        assertNotNull(browser);
        assertNotNull(copyOfBrowser);

        // adjust expected values before comparing
        browser.setAlias("Copy of browser");
        browser.setBuiltIn(false);
        browser.getAuthenticationExecutions().get(3).setFlowAlias("Copy of browser Organization");
        browser.getAuthenticationExecutions().get(4).setFlowAlias("Copy of browser forms");
        compareFlows(browser, copyOfBrowser);

        // get new flow directly and compare
        copyOfBrowser = authMgmtResource.getFlow(copyOfBrowser.getId());
        assertNotNull(copyOfBrowser);
        compareFlows(browser, copyOfBrowser);
        authMgmtResource.deleteFlow(copyOfBrowser.getId());
    }

    @Test
    // KEYCLOAK-2580
    public void addExecutionFlow() {
        HashMap<String, Object> params = new HashMap<>();
        params.put("newName", "parent");
        Response response = authMgmtResource.copy("browser", params);
        assertEquals(201, response.getStatus());
        response.close();

        params = new HashMap<>();
        params.put("alias", "child");
        params.put("description", "Description");
        params.put("provider", "registration-page-form");
        params.put("type", "basic-flow");

        authMgmtResource.addExecutionFlow("parent", params);

        authMgmtResource.deleteFlow(findFlowByAlias("parent", authMgmtResource.getFlows()).getId());
    }

    @Test
    //KEYCLOAK-12741
    //test editing of authentication flows
    public void editFlowTest() {
        List<AuthenticationFlowRepresentation> flows;

        //copy an existing one first
        HashMap<String, Object> params = new HashMap<>();
        params.put("newName", "Copy of browser");
        Response response = authMgmtResource.copy("browser", params);
        try {
            assertEquals( 201, response.getStatus());
        } finally {
            response.close();
        }

        //load the newly copied flow
        flows = authMgmtResource.getFlows();
        AuthenticationFlowRepresentation testFlow = findFlowByAlias("Copy of browser", flows);
        //Set a new unique name. Should succeed
        testFlow.setAlias("Copy of browser2");
        authMgmtResource.updateFlow(testFlow.getId(), testFlow);
        flows = authMgmtResource.getFlows();
        assertEquals("Copy of browser2", findFlowByAlias("Copy of browser2", flows).getAlias());

        //Create new flow and edit the old one to have the new ones name
        AuthenticationFlowRepresentation newFlow = newFlow("New Flow", "Test description", "basic-flow", true, false);
        createFlow(newFlow);
        // check that new flow is returned in a children list
        flows = authMgmtResource.getFlows();
        AuthenticationFlowRepresentation found = findFlowByAlias("New Flow", flows);

        assertNotNull(found, "created flow visible in parent");
        compareFlows(newFlow, found);

        //try to update old flow with alias that already exists
        testFlow.setAlias("New Flow");
        try {
            authMgmtResource.updateFlow(found.getId(), testFlow);
        } catch (ClientErrorException exception){
            //expoected
        }

        //try to update old flow with an alias with illegal characters
        testFlow.setAlias("New(Flow");
        try {
            authMgmtResource.updateFlow(found.getId(), testFlow);
        } catch (ClientErrorException exception){
            //expected
        }

        flows = authMgmtResource.getFlows();

        //name should be the same for the old Flow
        assertEquals("Copy of browser2", findFlowByAlias("Copy of browser2", flows).getAlias());

        //Only update the description
        found.setDescription("New description");
        authMgmtResource.updateFlow(found.getId(), found);
        flows = authMgmtResource.getFlows();

        assertEquals("New description", findFlowByAlias("New Flow", flows).getDescription());

        //Update name and description
        found.setAlias("New Flow2");
        found.setDescription("New description2");
        authMgmtResource.updateFlow(found.getId(), found);
        flows = authMgmtResource.getFlows();

        assertEquals("New Flow2", findFlowByAlias("New Flow2", flows).getAlias());
        assertEquals("New description2", findFlowByAlias("New Flow2", flows).getDescription());
        assertNull(findFlowByAlias("New Flow", flows));

        authMgmtResource.deleteFlow(testFlow.getId());
        authMgmtResource.deleteFlow(found.getId());
    }

    @KeycloakVersion(min = "25.0.0")
    @Test
    public void editExecutionFlowTest() {
        HashMap<String, Object> params = new HashMap<>();
        List<AuthenticationExecutionInfoRepresentation> executionReps;
        //create new parent flow
        AuthenticationFlowRepresentation newFlow = newFlow("Parent-Flow", "This is a parent flow", "basic-flow", true, false);
        createFlow(newFlow);

        //create a child sub flow
        params.put("alias", "Child-Flow");
        params.put("description", "This is a child flow");
        params.put("provider", "registration-page-form");
        params.put("type", "basic-flow");

        authMgmtResource.addExecutionFlow("Parent-Flow", params);

        executionReps = authMgmtResource.getExecutions("Parent-Flow");

        //create another with the same name of the previous one. Should fail to create
        params = new HashMap<>();
        params.put("alias", "Child-Flow");
        params.put("description", "This is another child flow");
        params.put("provider", "registration-page-form");
        params.put("type", "basic-flow");

        try {
            authMgmtResource.addExecutionFlow("Parent-Flow", params);
            fail("addExecutionFlow the alias already exist");
        } catch (Exception expected) {
            // Expected
        }

        AuthenticationExecutionInfoRepresentation found = executionReps.get(0);
        found.setDisplayName("Parent-Flow");

        try {
            authMgmtResource.updateExecutions("Parent-Flow", found);
        } catch (ClientErrorException exception){
            //expected
        }

        //edit both name and description
        found.setDisplayName("Child-Flow2");
        found.setDescription("This is another child flow2");

        authMgmtResource.updateExecutions("Parent-Flow", found);
        executionReps = authMgmtResource.getExecutions("Parent-Flow");
        assertEquals("Child-Flow2", executionReps.get(0).getDisplayName());
        assertEquals("This is another child flow2", executionReps.get(0).getDescription());

        //edit only description
        found.setDescription("This is another child flow3");
        authMgmtResource.updateExecutions("Parent-Flow", found);

        executionReps = authMgmtResource.getExecutions("Parent-Flow");
        assertEquals("Child-Flow2", executionReps.get(0).getDisplayName());
        assertEquals("This is another child flow3", executionReps.get(0).getDescription());
    }

    @KeycloakVersion(min = "25.0.0")
    @Test
    public void prioritySetTest() {
        //create new parent flow
        AuthenticationFlowRepresentation newFlow = newFlow("Parent-Flow", "This is a parent flow", "basic-flow", true, false);
        createFlow(newFlow);

        HashMap<String, Object> params = new HashMap<>();
        params.put("alias", "Child-Flow1");
        params.put("description", "This is a child flow");
        params.put("provider", "registration-page-form");
        params.put("type", "basic-flow");
        params.put("priority", 50);

        authMgmtResource.addExecutionFlow("Parent-Flow", params);

        params.clear();
        params.put("alias", "Child-Flow2");
        params.put("description", "This is a second child flow");
        params.put("provider", "registration-page-form");
        params.put("type", "basic-flow");
        params.put("priority", 10);

        authMgmtResource.addExecutionFlow("Parent-Flow", params);

        params.clear();
        params.put("alias", "Child-Flow3");
        params.put("description", "This is a third child flow");
        params.put("provider", "registration-page-form");
        params.put("type", "basic-flow");
        params.put("priority", 20);

        authMgmtResource.addExecutionFlow("Parent-Flow", params);

        List<AuthenticationExecutionInfoRepresentation> executionReps = authMgmtResource.getExecutions("Parent-Flow");
        // Verify the initial order and priority value
        assertEquals("Child-Flow2", executionReps.get(0).getDisplayName());
        assertEquals(10, executionReps.get(0).getPriority());
        assertEquals("Child-Flow3", executionReps.get(1).getDisplayName());
        assertEquals(20, executionReps.get(1).getPriority());
        assertEquals("Child-Flow1", executionReps.get(2).getDisplayName());
        assertEquals(50, executionReps.get(2).getPriority());

        // Move last execution to the beginning
        AuthenticationExecutionInfoRepresentation lastToFirst = executionReps.get(2);
        lastToFirst.setPriority(5);
        authMgmtResource.updateExecutions("Parent-Flow", lastToFirst);
        executionReps = authMgmtResource.getExecutions("Parent-Flow");

        // Verify new order and priority
        assertEquals("Child-Flow1", executionReps.get(0).getDisplayName());
        assertEquals(5, executionReps.get(0).getPriority());
        assertEquals("Child-Flow2", executionReps.get(1).getDisplayName());
        assertEquals(10, executionReps.get(1).getPriority());
        assertEquals("Child-Flow3", executionReps.get(2).getDisplayName());
        assertEquals(20, executionReps.get(2).getPriority());
    }

    @Test
    public void failWithLongDescription() throws IOException {
        AuthenticationFlowRepresentation rep = authMgmtResource.getFlows().stream()
                .filter(new Predicate<AuthenticationFlowRepresentation>() {
                    @Override
                    public boolean test(AuthenticationFlowRepresentation rep) {
                        return "docker auth".equals(rep.getAlias());
                    }
                }).findAny().orElse(null);

        assertNotNull(rep);

        StringBuilder name = new StringBuilder();

        while (name.length() < 300) {
            name.append("invalid");
        }

        rep.setDescription(name.toString());

        try {
            authMgmtResource.updateFlow(rep.getId(), rep);
            fail("Should fail because the description is too long");
        } catch (InternalServerErrorException isee) {
            try (Response response = isee.getResponse()) {
                assertEquals(500, response.getStatus());
                assertFalse(StreamUtil.readString((InputStream) response.getEntity(), Charset.forName("UTF-8")).toLowerCase().contains("exception"));
            }
        } catch (Exception e) {
            fail("Unexpected exception");
        }
    }

    @Test
    public void testAddRemoveExecutionsFailInBuiltinFlow() throws IOException {
        // get a built in flow
        List<AuthenticationFlowRepresentation> flows = authMgmtResource.getFlows();
        AuthenticationFlowRepresentation flow = flows.stream().filter(AuthenticationFlowRepresentation::isBuiltIn).findFirst().orElse(null);
        assertNotNull(flow, "There is no builtin flow");

        // adding an execution should fail
        Map<String, Object> data = new HashMap<>();
        data.put("provider", "allow-access-authenticator");
        BadRequestException e = assertThrows(BadRequestException.class, () -> authMgmtResource.addExecution(flow.getAlias(), data));
        OAuth2ErrorRepresentation error = e.getResponse().readEntity(OAuth2ErrorRepresentation.class);
        assertEquals("It is illegal to add execution to a built in flow", error.getError());

        // adding a sub-flow should fail as well
        e = assertThrows(BadRequestException.class, () -> addFlowToParent(flow.getAlias(), "child"));
        error = e.getResponse().readEntity(OAuth2ErrorRepresentation.class);
        assertEquals("It is illegal to add sub-flow to a built in flow", error.getError());

        // removing any execution (execution or flow) should fail too
        List<AuthenticationExecutionInfoRepresentation> executions = authMgmtResource.getExecutions(flow.getAlias());
        assertNotNull(executions, "The builtin flow has no executions");
        assertFalse(executions.isEmpty(), "The builtin flow has no executions");
        e = assertThrows(BadRequestException.class, () -> authMgmtResource.removeExecution(executions.get(0).getId()));
        error = e.getResponse().readEntity(OAuth2ErrorRepresentation.class);
        assertEquals("It is illegal to remove execution from a built in flow", error.getError());
    }

    @Test
    public void testExecutionConfigDuplicated() {
        AuthenticationFlowRepresentation existingFlow = null;

        for (AuthenticationFlowRepresentation flow : authMgmtResource.getFlows()) {
            if (flow.getAlias().equals("browser")) {
                existingFlow = flow;
            }
        }

        assertNotNull(existingFlow);

        List<AuthenticationExecutionInfoRepresentation> executions = authMgmtResource.getExecutions(existingFlow.getAlias());
        AuthenticationExecutionInfoRepresentation executionWithConfig = null;

        for (AuthenticationExecutionInfoRepresentation execution : executions) {
            if ("identity-provider-redirector".equals(execution.getProviderId())) {
                executionWithConfig = execution;
            }
        }

        assertNotNull(executionWithConfig);

        AuthenticatorConfigRepresentation executionConfig = new AuthenticatorConfigRepresentation();

        executionConfig.setAlias("test-execution-config");

        Map<String, String> map = new HashMap<>();
        map.put("key", "value");
        executionConfig.setConfig(map);

        try (Response response = authMgmtResource.newExecutionConfig(executionWithConfig.getId(), executionConfig)) {
            getCleanup("test").addAuthenticationConfigId(ApiUtil.getCreatedId(response));
        }

        String newFlowName = "Duplicated of " + "browser";
        Map<String, Object> copyFlowParams = new HashMap<>();
        copyFlowParams.put("newName", newFlowName);
        authMgmtResource.copy(existingFlow.getAlias(), copyFlowParams).close();

        AuthenticationFlowRepresentation newFlow = null;

        for (AuthenticationFlowRepresentation flow : authMgmtResource.getFlows()) {
            if (flow.getAlias().equals(newFlowName)) {
                newFlow = flow;
            }
        }

        Set<String> existingExecutionConfigIds = authMgmtResource.getExecutions(existingFlow.getAlias())
                .stream().map(AuthenticationExecutionInfoRepresentation::getAuthenticationConfig)
                .filter(Objects::nonNull)
                .collect(Collectors.toSet());

        assertFalse(existingExecutionConfigIds.isEmpty());

        Set<String> newExecutionConfigIds = authMgmtResource.getExecutions(newFlow.getAlias())
                .stream().map(AuthenticationExecutionInfoRepresentation::getAuthenticationConfig)
                .filter(Objects::nonNull)
                .collect(Collectors.toSet());

        assertFalse(newExecutionConfigIds.isEmpty());

        for (String executionConfigId : newExecutionConfigIds) {
            assertFalse(existingExecutionConfigIds.contains(executionConfigId), "Execution config not duplicated");
        }
    }
}