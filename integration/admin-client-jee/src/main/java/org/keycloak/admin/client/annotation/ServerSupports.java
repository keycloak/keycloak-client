package org.keycloak.admin.client.annotation;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Annotation to be used on "resource" interfaces or some methods on those interfaces pointing to REST endpoints.
 *
 * Indicates from which Keycloak server is the particular REST endpoint supported. If used on class, it means that whole resource is supported from that version.
 *
 * Note @Retention type SOURCE, so annotation is removed after compilation
 *
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
@Target({ElementType.TYPE, ElementType.METHOD})
@Retention(RetentionPolicy.SOURCE)
public @interface ServerSupports {

    /**
     * @return from which version of Keycloak server is this method supported. Empty means that it was supported from early Keycloak version
     */
    String from() default "";

    /**
     * @return to which version of Keycloak server is this method supported. Useful for deprecated REST methods, which are not supported on latest Keycloak
     * server or are planned to be removed on that version
     */
    String to() default "";
}
