package org.keycloak.client.testsuite.policyenforcer;

import java.util.Collections;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.keycloak.adapters.authorization.PolicyEnforcer;
import org.keycloak.client.testsuite.authz.AbstractAuthzTest;
import org.keycloak.representations.adapters.config.PolicyEnforcerConfig;
import org.keycloak.representations.idm.RealmRepresentation;
import org.keycloak.testsuite.util.AuthzTestUtils;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class EnforcerConfigTest extends AbstractAuthzTest {


    @Override
    public List<RealmRepresentation> getRealmsForImport() {
        RealmRepresentation realm = loadRealm(getClass().getResourceAsStream("/authorization-test/test-authz-realm.json"));
        return Collections.singletonList(realm);
    }

    @Test
    public void testMultiplePathsWithSameName() {
        PolicyEnforcer policyEnforcer = AuthzTestUtils.createPolicyEnforcer("enforcer-config-paths-same-name.json", true);
        Map<String, PolicyEnforcerConfig.PathConfig> paths = policyEnforcer.getPaths();
        assertEquals(1, paths.size());
        assertEquals(4, paths.values().iterator().next().getMethods().size());
    }

    @Test
    public void testPathConfigClaimInformationPoint() {
        PolicyEnforcer policyEnforcer = AuthzTestUtils.createPolicyEnforcer("enforcer-config-path-cip.json", true);
        Map<String, PolicyEnforcerConfig.PathConfig> paths = policyEnforcer.getPaths();

        assertEquals(1, paths.size());

        PolicyEnforcerConfig.PathConfig pathConfig = paths.values().iterator().next();
        Map<String, Map<String, Object>> cipConfig = pathConfig.getClaimInformationPointConfig();

        assertEquals(1, cipConfig.size());

        Map<String, Object> claims = cipConfig.get("claims");

        assertNotNull(claims);

        assertEquals(3, claims.size());
        assertEquals("{request.parameter['a']}", claims.get("claim-a"));
        assertEquals("{request.header['b']}", claims.get("claim-b"));
        assertEquals("{request.cookie['c']}", claims.get("claim-c"));
    }
}

