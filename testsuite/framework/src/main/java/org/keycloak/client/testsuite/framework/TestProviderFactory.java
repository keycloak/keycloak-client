package org.keycloak.client.testsuite.framework;

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public interface TestProviderFactory<T> {

    LifeCycle getLifeCycle();

    Class<T> getProviderClass();

    T createProvider(TestRegistry registry);

    void closeProvider(T provider);

}
