package org.keycloak.client.testsuite.framework;

import java.lang.reflect.Field;
import java.lang.reflect.Method;

import org.jboss.logging.Logger;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.extension.AfterAllCallback;
import org.junit.jupiter.api.extension.AfterEachCallback;
import org.junit.jupiter.api.extension.BeforeEachCallback;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.keycloak.client.testsuite.TestConstants;

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class KeycloakClientTestExtension implements BeforeEachCallback, AfterEachCallback, AfterAllCallback {

    private static final Logger logger = Logger.getLogger(KeycloakClientTestExtension.class);

    @Override
    public void beforeEach(ExtensionContext context) {
        logger.tracef("beforeEach: %s, my instance: %s", context, this);

        try {
            if (context.getTestInstance().isPresent()) {
                Object testInstance = context.getTestInstance().get();
                Class testClass = testInstance.getClass();
                while (!testClass.equals(Object.class)) {
                    for (Field field : testClass.getDeclaredFields()) {
                        if (field.isAnnotationPresent(Inject.class)) {
                            field.setAccessible(true);

                            if (field.get(testInstance) == null) {
                                Class<?> fieldType = field.getType();
                                Object provider = TestRegistry.INSTANCE.getOrCreateProvider(fieldType);
                                field.set(testInstance, provider);
                            }
                        }

                    }

                    testClass = testClass.getSuperclass();
                }
            }
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

        Method method = context.getRequiredTestMethod();
        if (method.isAnnotationPresent(KeycloakVersion.class)) {
            KeycloakVersion annotation = method.getAnnotation(KeycloakVersion.class);
            String currentVersion = System.getProperty(TestConstants.PROPERTY_KEYCLOAK_VERSION, TestConstants.KEYCLOAK_VERSION_DEFAULT);
            String requiredMinVersion = annotation.min();
            String requiredMaxVersion = annotation.max();
            if(requiredMinVersion != null && !requiredMinVersion.isEmpty()) {
                Assumptions.assumeTrue(compareVersions(currentVersion, requiredMinVersion) >= 0, "Test skipped because the current version: " + currentVersion + " is lower then required: " + requiredMinVersion);
            }
            if(requiredMaxVersion != null && !requiredMaxVersion.isEmpty()) {
                Assumptions.assumeTrue(compareVersions(currentVersion, requiredMaxVersion) <= 0, "Test skipped because the current version: " + currentVersion + " is higher then required: " + requiredMaxVersion);
            }
        }
    }

    @Override
    public void afterEach(ExtensionContext context) throws Exception {
        logger.tracef("afterEach: %s, my instance: %s", context, this);
        // Method lifecycle cleanup may need to be done here (if needed)
    }

    @Override
    public void afterAll(ExtensionContext context) {
        logger.tracef("afterAll: %s, my instance: %s", context, this);

        TestRegistry.INSTANCE.afterTestClass(context.getTestClass());
    }

    private int compareVersions(String currentVersion, String requiredVersion) {

        currentVersion = removeSuffix(currentVersion);
        requiredVersion = removeSuffix(requiredVersion);

        if (currentVersion.equals(TestConstants.KEYCLOAK_VERSION_DEFAULT)) {
            currentVersion = "9999";
        }
        if (requiredVersion.equals(TestConstants.KEYCLOAK_VERSION_DEFAULT)) {
            requiredVersion = "9999";
        }

        String[] currentVersionParts = currentVersion.split("\\.");
        String[] requiredVersionParts = requiredVersion.split("\\.");

        int length = Math.max(currentVersionParts.length, requiredVersionParts.length);
        for (int i = 0; i < length; i++) {
            int part1 = i < currentVersionParts.length ? Integer.parseInt(currentVersionParts[i]) : 0;
            int part2 = i < requiredVersionParts.length ? Integer.parseInt(requiredVersionParts[i]) : 0;

            if (part1 != part2) {
                return Integer.compare(part1, part2);
            }
        }
        return 0; // same version
    }

    public static String removeSuffix(String version) {
        int index = version.indexOf('-');
        return (index == -1) ? version : version.substring(0, index);
    }
}
