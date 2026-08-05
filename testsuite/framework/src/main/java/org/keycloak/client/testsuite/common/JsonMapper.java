package org.keycloak.client.testsuite.common;

import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Method;

// TODO: remove this and use KeycloakJsonMapperFactory directly once keycloak/keycloak#50848 merges
// and the nightly sync populates KeycloakJsonMapperFactory in client-common-synced
/**
 * Resolves a JSON mapper at runtime: prefers KeycloakJsonMapperFactory (jackson-agnostic)
 * when available, falls back to JsonSerialization (jackson 2) otherwise.
 */
public final class JsonMapper {

    private static final Object MAPPER;
    private static final Method READ_VALUE_IS;
    private static final Method READ_VALUE_STRING;
    private static final Method READ_VALUE_BYTES;
    private static final Method WRITE_VALUE_AS_STRING;

    static {
        Object mapper;
        try {
            Class<?> factory = Class.forName("org.keycloak.json.KeycloakJsonMapperFactory");
            mapper = factory.getMethod("mapper").invoke(null);
        } catch (Exception e) {
            try {
                Class<?> jsonSer = Class.forName("org.keycloak.util.JsonSerialization");
                mapper = jsonSer.getField("mapper").get(null);
            } catch (Exception ex) {
                throw new RuntimeException("Neither KeycloakJsonMapperFactory nor JsonSerialization found", ex);
            }
        }
        MAPPER = mapper;
        try {
            READ_VALUE_IS = MAPPER.getClass().getMethod("readValue", InputStream.class, Class.class);
            READ_VALUE_STRING = MAPPER.getClass().getMethod("readValue", String.class, Class.class);
            READ_VALUE_BYTES = MAPPER.getClass().getMethod("readValue", byte[].class, Class.class);
            WRITE_VALUE_AS_STRING = MAPPER.getClass().getMethod("writeValueAsString", Object.class);
        } catch (NoSuchMethodException e) {
            throw new RuntimeException("Mapper does not have expected methods", e);
        }
    }

    private JsonMapper() {}

    @SuppressWarnings("unchecked")
    public static <T> T readValue(InputStream is, Class<T> type) throws IOException {
        try {
            return (T) READ_VALUE_IS.invoke(MAPPER, is, type);
        } catch (Exception e) {
            throw unwrap(e);
        }
    }

    @SuppressWarnings("unchecked")
    public static <T> T readValue(String src, Class<T> type) throws IOException {
        try {
            return (T) READ_VALUE_STRING.invoke(MAPPER, src, type);
        } catch (Exception e) {
            throw unwrap(e);
        }
    }

    @SuppressWarnings("unchecked")
    public static <T> T readValue(byte[] src, Class<T> type) throws IOException {
        try {
            return (T) READ_VALUE_BYTES.invoke(MAPPER, src, type);
        } catch (Exception e) {
            throw unwrap(e);
        }
    }

    public static String writeValueAsString(Object value) throws IOException {
        try {
            return (String) WRITE_VALUE_AS_STRING.invoke(MAPPER, value);
        } catch (Exception e) {
            throw unwrap(e);
        }
    }

    private static IOException unwrap(Exception e) {
        Throwable cause = e.getCause();
        if (cause instanceof IOException) return (IOException) cause;
        return new IOException(cause != null ? cause : e);
    }
}
