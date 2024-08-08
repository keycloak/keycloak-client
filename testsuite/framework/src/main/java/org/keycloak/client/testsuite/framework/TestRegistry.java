package org.keycloak.client.testsuite.framework;

import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.Function;

import org.apache.http.impl.client.CloseableHttpClient;
import org.jboss.logging.Logger;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.client.testsuite.common.AdminClientFactory;
import org.keycloak.client.testsuite.common.HttpClientFactory;
import org.keycloak.client.testsuite.server.KeycloakServerProvider;
import org.keycloak.client.testsuite.server.KeycloakServerProviderFactory;
import org.keycloak.client.testsuite.common.RealmImporter;
import org.keycloak.client.testsuite.common.RealmImporterFactory;

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class TestRegistry {

    private static final Logger logger = Logger.getLogger(TestRegistry.class);

    private final Map<Class<?>, TestProviderFactory<?>> factories = new ConcurrentHashMap<>();

    private final Map<Class<?>, Object> instances = new ConcurrentHashMap<>();

    // Sorted by last added classes being first, so we can cleanup in correct order
    private final List<Class<?>> currentInstanceClasses = new CopyOnWriteArrayList<>();

    public static TestRegistry INSTANCE = new TestRegistry();

    private TestRegistry() {
        // Hardcoded for now... See if need to use ServiceLoader or something more flexible in the future...
        factories.put(KeycloakServerProvider.class, new KeycloakServerProviderFactory());
        factories.put(Keycloak.class, new AdminClientFactory());
        factories.put(CloseableHttpClient.class, new HttpClientFactory());
        factories.put(RealmImporter.class, new RealmImporterFactory());

        Runtime.getRuntime().addShutdownHook(new Thread(this::afterAllTestClasses));
    }

    // Triggered after test class. Should close providers of the lifecycle of test class
    void afterTestClass(Optional<Class<?>> testClass) {
        closeAllInstancesOfSpecifiedLifecycle(LifeCycle.CLASS, provider -> String.format("Closing provider '%s' after test class '%s' finished", provider, testClass.isPresent() ? testClass.get() : "empty"));
    }

    // Triggered after whole testsuite is finished. Should close providers of the global lifecycle
    private void afterAllTestClasses() {
        logger.infof("Closing test registry");

        // Finish test providers as well in case they exists.
        // Ideally should not be needed as the method should be called from AfterAll callback, but calling here as well just for the case when the shutdown was called unexpectedly by kill signal or something like that, which means that AfterAll callback was not triggered
        afterTestClass(Optional.empty());
        closeAllInstancesOfSpecifiedLifecycle(LifeCycle.GLOBAL, provider -> String.format("Closing provider '%s' after all tests are finished", provider));
    }

    private void closeAllInstancesOfSpecifiedLifecycle(LifeCycle targetLifecycle, Function<Object, String> logMessageFromProvider) {
        Set<Class<?>> toRemove = new HashSet<>();
        for (int i=currentInstanceClasses.size() - 1 ; i >= 0 ; i--) {
            Class<?> providerClass = currentInstanceClasses.get(i);
            Object provider = instances.get(providerClass);
            TestProviderFactory factory = factories.get(providerClass);
            if (factory.getLifeCycle() == targetLifecycle) {
                if (logger.isTraceEnabled()) {
                    String logMessage = logMessageFromProvider.apply(provider);
                    logger.tracef(logMessage);
                }
                factory.closeProvider(provider);
                toRemove.add(providerClass);
            }
        }

        for (Class<?> clazz : toRemove) {
            instances.remove(clazz);
            currentInstanceClasses.remove(clazz);
        }
    }

    public <T> T getOrCreateProvider(Class<T> providerClass) {
        T provider = (T) instances.get(providerClass);
        if (provider != null) {
            logger.tracef("Successfully obtained existing provider '%s' of providerClass '%s'", provider, providerClass);
        } else {
            TestProviderFactory<T> factory = (TestProviderFactory<T>) factories.get(providerClass);
            if (factory == null) {
                throw new IllegalStateException("No factory for providerClass " + providerClass);
            }
            provider = factory.createProvider(this);
            logger.tracef("Created provider '%s' of type '%s' with factory '%s'", provider, providerClass, factory);
            instances.put(providerClass, provider);
            currentInstanceClasses.add((Class) providerClass);
        }
        return provider;
    }
}
