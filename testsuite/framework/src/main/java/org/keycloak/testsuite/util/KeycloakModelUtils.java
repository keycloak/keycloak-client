/*
 * Copyright 2016 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.keycloak.testsuite.util;

import org.jboss.logging.Logger;

import java.util.UUID;

/**
 * Set of helper methods, which are useful in various model implementations.
 *
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>,
 * <a href="mailto:daniel.fesenmeyer@bosch.io">Daniel Fesenmeyer</a>
 */
public final class KeycloakModelUtils {

    private static final Logger logger = Logger.getLogger(KeycloakModelUtils.class);

    public static final String AUTH_TYPE_CLIENT_SECRET = "client-secret";
    public static final String AUTH_TYPE_CLIENT_SECRET_JWT = "client-secret-jwt";

    public static final String GROUP_PATH_SEPARATOR = "/";
    public static final String GROUP_PATH_ESCAPE = "~";
    private static final char CLIENT_ROLE_SEPARATOR = '.';

    private KeycloakModelUtils() {
    }

    public static String generateId() {
        return UUID.randomUUID().toString();
    }

}
