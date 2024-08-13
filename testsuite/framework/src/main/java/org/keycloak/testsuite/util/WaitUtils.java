package org.keycloak.testsuite.util;


import org.jboss.logging.Logger;
import org.keycloak.client.testsuite.framework.KeycloakClientTestExtension;

/**
 *
 * @author Petr Mensik
 * @author tkyjovsk
 * @author Vaclav Muzikar <vmuzikar@redhat.com>
 */
public class WaitUtils {

    private static final Logger logger = Logger.getLogger(KeycloakClientTestExtension.class);

    public static void pause(long millis) {
        if (millis > 0) {
            logger.infof("Wait: %d ms", millis);
            try {
                Thread.sleep(millis);
            } catch (InterruptedException ex) {
                logger.error("Interrupted", ex);
                Thread.currentThread().interrupt();
            }
        }
    }
}
