package org.keycloak.client.testsuite.common;

import org.keycloak.admin.client.Keycloak;
import org.keycloak.client.testsuite.framework.LifeCycle;
import org.keycloak.client.testsuite.framework.TestProviderFactory;
import org.keycloak.client.testsuite.framework.TestRegistry;

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class RealmImporterFactory implements TestProviderFactory<RealmImporter> {

    @Override
    public LifeCycle getLifeCycle() {
        return LifeCycle.CLASS;
    }

    @Override
    public Class<RealmImporter> getProviderClass() {
        return RealmImporter.class;
    }

    @Override
    public RealmImporter createProvider(TestRegistry registry) {
        Keycloak adminClient = registry.getOrCreateProvider(Keycloak.class);
        return new RealmImporter(adminClient);
    }

    @Override
    public void closeProvider(RealmImporter realmImporter) {
        realmImporter.deleteImportedRealms();
    }
}
