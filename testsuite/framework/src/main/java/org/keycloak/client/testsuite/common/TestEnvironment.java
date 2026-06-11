package org.keycloak.client.testsuite.common;

import java.io.File;

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class TestEnvironment {

    public static String getProjectRootDir() {
        String userDir = System.getProperty("user.dir");
        int kcClientIndex = userDir.lastIndexOf("keycloak-client");
        if (kcClientIndex == -1) {
            throw new IllegalArgumentException("Not able to find root directory. User dir was: " +userDir);
        }
        int projectRootDirIndex = userDir.indexOf(File.separator, kcClientIndex);
        if (projectRootDirIndex == -1) {
            throw new IllegalArgumentException("Not able to find file delimited within directory. User dir was: " +userDir);
        }
        return userDir.substring(0, projectRootDirIndex);
    }

    public static String getTestProvidersFile() {
        return getProjectRootDir()
                + File.separator + "testsuite"
                + File.separator + "providers"
                + File.separator + "target"
                + File.separator + "keycloak-client-testsuite-providers.jar";
    }
}
