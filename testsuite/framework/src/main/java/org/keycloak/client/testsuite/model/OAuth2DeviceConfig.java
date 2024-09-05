/*
 *
 *  * Copyright 2021  Red Hat, Inc. and/or its affiliates
 *  * and other contributors as indicated by the @author tags.
 *  *
 *  * Licensed under the Apache License, Version 2.0 (the "License");
 *  * you may not use this file except in compliance with the License.
 *  * You may obtain a copy of the License at
 *  *
 *  * http://www.apache.org/licenses/LICENSE-2.0
 *  *
 *  * Unless required by applicable law or agreed to in writing, software
 *  * distributed under the License is distributed on an "AS IS" BASIS,
 *  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  * See the License for the specific language governing permissions and
 *  * limitations under the License.
 *
 */

package org.keycloak.client.testsuite.model;

import java.io.Serializable;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public final class OAuth2DeviceConfig implements Serializable {

    // 10 minutes
    public static final int DEFAULT_OAUTH2_DEVICE_CODE_LIFESPAN = 600;
    // 5 seconds
    public static final int DEFAULT_OAUTH2_DEVICE_POLLING_INTERVAL = 5;

    // realm attribute names
    public static String OAUTH2_DEVICE_CODE_LIFESPAN = "oauth2DeviceCodeLifespan";
    public static String OAUTH2_DEVICE_POLLING_INTERVAL = "oauth2DevicePollingInterval";

    // client attribute names
    public static String OAUTH2_DEVICE_CODE_LIFESPAN_PER_CLIENT = "oauth2.device.code.lifespan";
    public static String OAUTH2_DEVICE_POLLING_INTERVAL_PER_CLIENT = "oauth2.device.polling.interval";
    public static final String OAUTH2_DEVICE_AUTHORIZATION_GRANT_ENABLED = "oauth2.device.authorization.grant.enabled";

    private int lifespan = DEFAULT_OAUTH2_DEVICE_CODE_LIFESPAN;
    private int poolingInterval = DEFAULT_OAUTH2_DEVICE_POLLING_INTERVAL;
}
