package org.keycloak.json;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;


import com.fasterxml.jackson.annotation.JacksonAnnotationsInside;

/**
 * Marks a {@code MultivaluedHashMap<String, String>} field with compact serialization:
 * single-valued entries become plain values, boolean-looking strings become JSON booleans.
 * <p>
 * With Jackson 2, the meta-annotation expands automatically via {@link JacksonAnnotationsInside}.
 * With Jackson 3, the {@code KeycloakAnnotationIntrospector3} handles this annotation directly.
 */
@Target({ElementType.FIELD, ElementType.METHOD, ElementType.PARAMETER})
@Retention(RetentionPolicy.RUNTIME)
@JacksonAnnotationsInside
public @interface MultivaluedHashMapValue {
}
