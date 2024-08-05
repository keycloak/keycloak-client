package org.keycloak.client.testsuite;

import java.lang.reflect.Field;

import org.jboss.resteasy.client.jaxrs.ResteasyClient;
import org.junit.jupiter.api.Test;
import org.keycloak.admin.client.Keycloak;
import org.testcontainers.shaded.org.hamcrest.MatcherAssert;

import static org.testcontainers.shaded.org.hamcrest.Matchers.equalTo;

/**
 * Test that I have correct versions of admin-client (admin-client VS admin-client-jee) and corresponding libraries on classpath
 *
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class ClasspathJakartaTest {

    @Test
    public void testCorrectResteasyClient() throws Exception {
        Field clientField = Keycloak.class.getDeclaredField("client");
        Class clientFieldClass = clientField.getType();
        MatcherAssert.assertThat(getExpectedClientFieldClass(), equalTo(clientFieldClass.getName()));
    }

    @Test
    public void testResteasyVersion() throws Exception {
        Class resteasyClientSuperclass = ResteasyClient.class.getInterfaces()[0];
        MatcherAssert.assertThat(getExpectedClientFieldClass(), equalTo(resteasyClientSuperclass.getName()));
    }

    protected String getExpectedClientFieldClass() {
        return "jakarta.ws.rs.client.Client";
    }

}
