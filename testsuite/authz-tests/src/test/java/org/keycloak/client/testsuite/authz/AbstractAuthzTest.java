package org.keycloak.client.testsuite.authz;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;

import org.junit.jupiter.api.BeforeEach;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.client.testsuite.framework.Inject;
import org.keycloak.client.testsuite.common.RealmImporter;
import org.keycloak.client.testsuite.common.RealmRepsSupplier;
import org.keycloak.representations.idm.RealmRepresentation;
import org.keycloak.util.JsonSerialization;

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public abstract class AbstractAuthzTest implements RealmRepsSupplier {

    @Inject
    protected Keycloak adminClient;

    @Inject
    protected RealmImporter realmImporter;

    @BeforeEach
    public void importRealms() {
        realmImporter.importRealmsIfNotImported(this);
    }

    protected RealmRepresentation loadRealm(InputStream is) {
        try {
            return JsonSerialization.readValue(is, RealmRepresentation.class);
        } catch (IOException ioe) {
            throw new UncheckedIOException(ioe);
        }
    }
}
