package org.keycloak.client.testsuite.framework;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
public @interface KeycloakVersion {
    String min() default "";
    String max() default "";;
}
