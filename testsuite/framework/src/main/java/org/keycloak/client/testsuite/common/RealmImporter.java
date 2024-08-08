package org.keycloak.client.testsuite.common;

import java.util.List;
import java.util.stream.Collectors;

import org.jboss.logging.Logger;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.representations.idm.RealmRepresentation;

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class RealmImporter {

    private final Keycloak adminClient;
    private List<String> importedRealmNames;

    private static final Logger logger = Logger.getLogger(RealmImporter.class);

    public RealmImporter(Keycloak adminClient) {
        this.adminClient = adminClient;
    }

    /**
     * Import realms once per test class
     *
     * @param realmsProvider usually test instance
     */
    public void importRealmsIfNotImported(RealmRepsSupplier realmsProvider) {
        if (importedRealmNames == null) {
            List<RealmRepresentation> realmsToImport = realmsProvider.getRealmsForImport();

            importedRealmNames = realmsToImport.stream().map(realm -> {
                adminClient.realms().create(realm);
                return realm.getRealm();
            }).collect(Collectors.toList());

            logger.tracef("Imported realms: %s before test class %s", importedRealmNames, realmsProvider);
        }
    }

    public void deleteImportedRealms() {
        if (importedRealmNames == null) return;

        for (String realmName : importedRealmNames) {
            adminClient.realms().realm(realmName).remove();
        }

        logger.tracef("Deleted realms: %s after test class", importedRealmNames);
    }

}
