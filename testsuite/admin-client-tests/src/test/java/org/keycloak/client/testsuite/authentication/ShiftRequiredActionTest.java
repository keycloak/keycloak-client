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

package org.keycloak.client.testsuite.authentication;

import jakarta.ws.rs.NotFoundException;
import org.junit.jupiter.api.Test;
import org.keycloak.representations.idm.RequiredActionProviderRepresentation;


import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * @author <a href="mailto:wadahiro@gmail.com">Hiroyuki Wada</a>
 */
public class ShiftRequiredActionTest extends AbstractAuthenticationTest {

    @Test
    public void testShiftRequiredAction() {

        // get action
        List<RequiredActionProviderRepresentation> actions = authMgmtResource.getRequiredActions();

        RequiredActionProviderRepresentation last = actions.get(actions.size() - 1);
        RequiredActionProviderRepresentation oneButLast = actions.get(actions.size() - 2);

        // Not possible to raisePriority of not-existent required action
        try {
            authMgmtResource.raisePriority("not-existent");
            fail("Not expected to raise priority of not existent required action");
        } catch (NotFoundException nfe) {
            // Expected
        }

        // shift last required action up
        authMgmtResource.raiseRequiredActionPriority(last.getAlias());

        List<RequiredActionProviderRepresentation> actions2 = authMgmtResource.getRequiredActions();

        RequiredActionProviderRepresentation last2 = actions2.get(actions.size() - 1);
        RequiredActionProviderRepresentation oneButLast2 = actions2.get(actions.size() - 2);

        assertEquals(last.getAlias(), oneButLast2.getAlias(), "Required action shifted up - N");
        assertEquals(oneButLast.getAlias(), last2.getAlias(), "Required action up - N-1");

        // Not possible to lowerPriority of not-existent required action
        try {
            authMgmtResource.lowerRequiredActionPriority("not-existent");
            fail("Not expected to raise priority of not existent required action");
        } catch (NotFoundException nfe) {
            // Expected
        }

        // shift one before last down
        authMgmtResource.lowerRequiredActionPriority(oneButLast2.getAlias());

        actions2 = authMgmtResource.getRequiredActions();

        last2 = actions2.get(actions.size() - 1);
        oneButLast2 = actions2.get(actions.size() - 2);

        assertEquals(last.getAlias(), last2.getAlias(), "Required action shifted down - N");
        assertEquals(oneButLast.getAlias(), oneButLast2.getAlias(), "Required action shifted down - N-1");
    }
}
