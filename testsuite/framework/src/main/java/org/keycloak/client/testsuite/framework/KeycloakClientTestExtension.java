package org.keycloak.client.testsuite.framework;

import java.lang.reflect.Field;

import org.jboss.logging.Logger;
import org.junit.jupiter.api.extension.AfterAllCallback;
import org.junit.jupiter.api.extension.AfterEachCallback;
import org.junit.jupiter.api.extension.BeforeEachCallback;
import org.junit.jupiter.api.extension.ExtensionContext;

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
}
