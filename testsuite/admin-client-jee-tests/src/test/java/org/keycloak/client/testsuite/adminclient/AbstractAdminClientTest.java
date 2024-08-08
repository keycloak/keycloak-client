package org.keycloak.client.testsuite.adminclient;

import org.keycloak.admin.client.Keycloak;
import org.keycloak.client.testsuite.framework.Inject;

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public abstract class AbstractAdminClientTest {

    @Inject
    protected Keycloak adminClient;

}
