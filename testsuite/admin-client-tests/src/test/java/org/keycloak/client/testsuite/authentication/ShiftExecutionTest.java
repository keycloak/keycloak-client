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

import org.junit.jupiter.api.Test;

import org.keycloak.representations.idm.AuthenticationExecutionInfoRepresentation;

import java.util.HashMap;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * @author <a href="mailto:mstrukel@redhat.com">Marko Strukelj</a>
 */
public class ShiftExecutionTest extends AbstractAuthenticationTest {

    @Test
    public void testShiftExecution() {

        // copy built-in flow so we get a new editable flow
        HashMap<String, Object> params = new HashMap<>();
        params.put("newName", "Copy of browser");
        Response response = authMgmtResource.copy("browser", params);
        try {
            assertEquals(201, response.getStatus(), "Copy flow");
        } finally {
            response.close();
        }

        // get executions
        List<AuthenticationExecutionInfoRepresentation> executions = authMgmtResource.getExecutions("Copy of browser");

        AuthenticationExecutionInfoRepresentation last = executions.get(executions.size() - 1);
        AuthenticationExecutionInfoRepresentation oneButLast = executions.get(executions.size() - 2);

        // Not possible to raisePriority of not-existent flow
        try {
            authMgmtResource.raisePriority("not-existent");
            fail("Not expected to raise priority of not existent flow");
        } catch (NotFoundException nfe) {
            // Expected
        }

        // shift last execution up
        authMgmtResource.raisePriority(last.getId());

        List<AuthenticationExecutionInfoRepresentation> executions2 = authMgmtResource.getExecutions("Copy of browser");

        AuthenticationExecutionInfoRepresentation last2 = executions2.get(executions.size() - 1);
        AuthenticationExecutionInfoRepresentation oneButLast2 = executions2.get(executions.size() - 2);

        assertEquals(last.getId(), oneButLast2.getId(), "Execution shifted up - N");
        assertEquals(oneButLast.getId(), last2.getId(), "Execution shifted up - N-1");

        // Not possible to lowerPriority of not-existent flow
        try {
            authMgmtResource.lowerPriority("not-existent");
            fail("Not expected to raise priority of not existent flow");
        } catch (NotFoundException nfe) {
            // Expected
        }

        // shift one before last down
        authMgmtResource.lowerPriority(oneButLast2.getId());

        executions2 = authMgmtResource.getExecutions("Copy of browser");

        last2 = executions2.get(executions.size() - 1);
        oneButLast2 = executions2.get(executions.size() - 2);

        assertEquals(last.getId(), last2.getId(), "Execution shifted down - N");
        assertEquals(oneButLast.getId(), oneButLast2.getId(), "Execution shifted down - N-1");
    }

    @Test
    public void testBuiltinShiftNotAllowed() {
        List<AuthenticationExecutionInfoRepresentation> executions = authMgmtResource.getExecutions("browser");

        AuthenticationExecutionInfoRepresentation last = executions.get(executions.size() - 1);
        AuthenticationExecutionInfoRepresentation oneButLast = executions.get(executions.size() - 2);

        // Not possible to raise - It's builtin flow
        try {
            authMgmtResource.raisePriority(last.getId());
            fail("Not expected to raise priority of builtin flow");
        } catch (BadRequestException nfe) {
            // Expected
        }

        // Not possible to lower - It's builtin flow
        try {
            authMgmtResource.lowerPriority(oneButLast.getId());
            fail("Not expected to lower priority of builtin flow");
        } catch (BadRequestException nfe) {
            // Expected
        }

    }
}
