package org.keycloak.client.testsuite.adminclientjee;

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class ClasspathJEETest extends org.keycloak.client.testsuite.adminclient.ClasspathTest {

    @Override
    protected String getExpectedClientFieldClass() {
        return "javax.ws.rs.client.Client";
    }
}
