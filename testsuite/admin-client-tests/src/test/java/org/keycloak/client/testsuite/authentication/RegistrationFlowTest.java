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
import org.junit.jupiter.api.Test;
import org.keycloak.representations.idm.AuthenticationFlowRepresentation;

import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.fail;

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class RegistrationFlowTest extends AbstractAuthenticationTest {

    @Test
    public void testAddExecution() {
        // Add registration flow 2
        AuthenticationFlowRepresentation flowRep = newFlow("registration2", "RegistrationFlow2", "basic-flow", true, false);
        createFlow(flowRep);

        // add registration execution form flow
        Map<String, Object> data = new HashMap<>();
        data.put("alias", "registrationForm2");
        data.put("type", "form-flow");
        data.put("description", "registrationForm2 flow");
        data.put("provider", "registration-page-form");
        authMgmtResource.addExecutionFlow("registration2", data);

        // Should fail to add execution under top level flow
        Map<String, Object> data2 = new HashMap<>();
        data2.put("provider", "registration-password-action");
        try {
            authMgmtResource.addExecution("registration2", data2);
            fail("Not expected to add execution of type 'registration-password-action' under top flow");
        } catch (BadRequestException bre) {
        }

        // Should success to add execution under form flow
        authMgmtResource.addExecution("registrationForm2", data2);
    }

    // TODO: More type-safety instead of passing generic maps

}
