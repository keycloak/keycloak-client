package org.keycloak.client.testsuite.adminclient;

import java.util.List;

import org.junit.jupiter.api.Test;
import org.keycloak.client.testsuite.TestConstants;
import org.keycloak.representations.idm.RealmRepresentation;
import org.testcontainers.shaded.org.hamcrest.MatcherAssert;
import org.testcontainers.shaded.org.hamcrest.Matchers;

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class RealmsTest extends AbstractAdminClientTest {

    @Test
    public void realmsList() {
        List<RealmRepresentation> realms = adminClient.realms().findAll();
        MatcherAssert.assertThat(realms.stream()
                .map(RealmRepresentation::getRealm)
                .filter(realmName -> TestConstants.MASTER_REALM.equals(realmName))
                .findFirst()
                .isPresent(), Matchers.is(true));
    }
}
