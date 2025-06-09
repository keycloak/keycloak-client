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

import org.junit.jupiter.api.Test;
import org.keycloak.client.testsuite.framework.KeycloakVersion;
import org.keycloak.representations.idm.RequiredActionProviderRepresentation;


import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;


/**
 * @author <a href="mailto:mstrukel@redhat.com">Marko Strukelj</a>
 */
public class RequiredActionsTest extends AbstractAuthenticationTest {

    @KeycloakVersion(min = "26.2")
    @Test
    public void testRequiredActionsMin262() {
        List<RequiredActionProviderRepresentation> result = authMgmtResource.getRequiredActions();

        List<RequiredActionProviderRepresentation> expected = new ArrayList<>();
        addRequiredAction(expected, "CONFIGURE_RECOVERY_AUTHN_CODES", "Recovery Authentication Codes", true, false, null);
        addRequiredAction(expected, "CONFIGURE_TOTP", "Configure OTP", true, false, null);
        addRequiredAction(expected, "TERMS_AND_CONDITIONS", "Terms and Conditions", false, false, null);
        addRequiredAction(expected, "UPDATE_PASSWORD", "Update Password", true, false, null);
        addRequiredAction(expected, "UPDATE_PROFILE", "Update Profile", true, false, null);
        addRequiredAction(expected, "VERIFY_EMAIL", "Verify Email", true, false, null);
        addRequiredAction(expected, "VERIFY_PROFILE", "Verify Profile", false, false, null);
        addRequiredAction(expected, "delete_account", "Delete Account", false, false, null);
        addRequiredAction(expected, "delete_credential", "Delete Credential", true, false, null);
        addRequiredAction(expected, "idp_link", "Linking Identity Provider", true, false, null);
        addRequiredAction(expected, "update_user_locale", "Update User Locale", true, false, null);
        addRequiredAction(expected, "webauthn-register", "Webauthn Register", true, false, null);
        addRequiredAction(expected, "webauthn-register-passwordless", "Webauthn Register Passwordless", true, false, null);

        compareRequiredActions(expected, sort(result));

        RequiredActionProviderRepresentation forUpdate = newRequiredAction("VERIFY_EMAIL", "Verify Email", false, false, null);
        authMgmtResource.updateRequiredAction(forUpdate.getAlias(), forUpdate);

        result = authMgmtResource.getRequiredActions();
        RequiredActionProviderRepresentation updated = findRequiredActionByAlias(forUpdate.getAlias(), result);

        assertNotNull(updated, "Required Action still there");
        compareRequiredAction(forUpdate, updated);

        forUpdate.setConfig(Collections.<String, String>emptyMap());
        authMgmtResource.updateRequiredAction(forUpdate.getAlias(), forUpdate);

        result = authMgmtResource.getRequiredActions();
        updated = findRequiredActionByAlias(forUpdate.getAlias(), result);

        assertNotNull(updated, "Required Action still there");
        compareRequiredAction(forUpdate, updated);
    }

    @KeycloakVersion(max = "26.1")
    @Test
    public void testRequiredActionsMax261() {
        List<RequiredActionProviderRepresentation> result = authMgmtResource.getRequiredActions();

        List<RequiredActionProviderRepresentation> expected = new ArrayList<>();
        addRequiredAction(expected, "CONFIGURE_TOTP", "Configure OTP", true, false, null);
        addRequiredAction(expected, "TERMS_AND_CONDITIONS", "Terms and Conditions", false, false, null);
        addRequiredAction(expected, "UPDATE_PASSWORD", "Update Password", true, false, null);
        addRequiredAction(expected, "UPDATE_PROFILE", "Update Profile", true, false, null);
        addRequiredAction(expected, "VERIFY_EMAIL", "Verify Email", true, false, null);
        addRequiredAction(expected, "VERIFY_PROFILE", "Verify Profile", false, false, null);
        addRequiredAction(expected, "delete_account", "Delete Account", false, false, null);
        addRequiredAction(expected, "delete_credential", "Delete Credential", true, false, null);
        addRequiredAction(expected, "update_user_locale", "Update User Locale", true, false, null);
        addRequiredAction(expected, "webauthn-register", "Webauthn Register", true, false, null);
        addRequiredAction(expected, "webauthn-register-passwordless", "Webauthn Register Passwordless", true, false, null);

        compareRequiredActions(expected, sort(result));

        RequiredActionProviderRepresentation forUpdate = newRequiredAction("VERIFY_EMAIL", "Verify Email", false, false, null);
        authMgmtResource.updateRequiredAction(forUpdate.getAlias(), forUpdate);

        result = authMgmtResource.getRequiredActions();
        RequiredActionProviderRepresentation updated = findRequiredActionByAlias(forUpdate.getAlias(), result);

        assertNotNull(updated, "Required Action still there");
        compareRequiredAction(forUpdate, updated);

        forUpdate.setConfig(Collections.<String, String>emptyMap());
        authMgmtResource.updateRequiredAction(forUpdate.getAlias(), forUpdate);

        result = authMgmtResource.getRequiredActions();
        updated = findRequiredActionByAlias(forUpdate.getAlias(), result);

        assertNotNull(updated, "Required Action still there");
        compareRequiredAction(forUpdate, updated);
    }

    private RequiredActionProviderRepresentation findRequiredActionByAlias(String alias, List<RequiredActionProviderRepresentation> list) {
        for (RequiredActionProviderRepresentation a: list) {
            if (alias.equals(a.getAlias())) {
                return a;
            }
        }
        return null;
    }

    private List<RequiredActionProviderRepresentation> sort(List<RequiredActionProviderRepresentation> list) {
        ArrayList<RequiredActionProviderRepresentation> sorted = new ArrayList<>(list);
        Collections.sort(sorted, new RequiredActionProviderComparator());
        return sorted;
    }

    private void compareRequiredActions(List<RequiredActionProviderRepresentation> expected, List<RequiredActionProviderRepresentation> actual) {
        assertNotNull(actual, "Actual null");
        assertEquals(expected.size(), actual.size(), "Required actions count");

        Iterator<RequiredActionProviderRepresentation> ite = expected.iterator();
        Iterator<RequiredActionProviderRepresentation> ita = actual.iterator();
        while (ite.hasNext()) {
            compareRequiredAction(ite.next(), ita.next());
        }
    }

    private void compareRequiredAction(RequiredActionProviderRepresentation expected, RequiredActionProviderRepresentation actual) {
        assertEquals(expected.getAlias(), actual.getAlias(), "alias - " + expected.getAlias());
        assertEquals(expected.getName(), actual.getName(), "name - "  + expected.getAlias());
        assertEquals(expected.isEnabled(), actual.isEnabled(), "enabled - "  + expected.getAlias());
        assertEquals(expected.isDefaultAction(), actual.isDefaultAction(), "defaultAction - "  + expected.getAlias());
        assertEquals(expected.getConfig() != null ? expected.getConfig() : Collections.<String, String>emptyMap(), actual.getConfig(), "config - " + expected.getAlias());
    }

    private void addRequiredAction(List<RequiredActionProviderRepresentation> target, String alias, String name, boolean enabled, boolean defaultAction, Map<String, String> conf) {
        target.add(newRequiredAction(alias, name, enabled, defaultAction, conf));
    }

    private RequiredActionProviderRepresentation newRequiredAction(String alias, String name, boolean enabled, boolean defaultAction, Map<String, String> conf) {
        RequiredActionProviderRepresentation action = new RequiredActionProviderRepresentation();
        action.setAlias(alias);
        action.setName(name);
        action.setEnabled(enabled);
        action.setDefaultAction(defaultAction);
        action.setConfig(conf);
        return action;
    }

    private static class RequiredActionProviderComparator implements Comparator<RequiredActionProviderRepresentation> {
        @Override
        public int compare(RequiredActionProviderRepresentation o1, RequiredActionProviderRepresentation o2) {
            return o1.getAlias().compareTo(o2.getAlias());
        }
    }
}
