package org.keycloak.client.testsuite.common;

import java.util.List;

import org.keycloak.representations.idm.RealmRepresentation;

/**
 * Usually implemented by test class with the realms, which are needed by particular test. The realms are typically imported once before the test.
 *
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public interface RealmRepsSupplier {

    /**
     * Realms for import before test class
     *
     * @return realms, which will be imported
     */
    List<RealmRepresentation> getRealmsForImport();

    /**
     * Should be "Verify profile" action disabled after import of the realms?
     *
     * @return true if should be disabled, false otherwise
     */
    boolean removeVerifyProfileAtImport();
}
