package org.keycloak.client.testsuite.common;

import java.io.File;

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class TestEnvironment {

    public static String getProjectRootDir() {
        String userDir = System.getProperty("user.dir");
        return userDir.substring(0, userDir.lastIndexOf("keycloak-client") + 15);
    }

    public static String getTestProvidersFile() {
        return getProjectRootDir()
                + File.separator + "testsuite"
                + File.separator + "providers"
                + File.separator + "target"
                + File.separator + "keycloak-client-testsuite-providers.jar";
    }
}
