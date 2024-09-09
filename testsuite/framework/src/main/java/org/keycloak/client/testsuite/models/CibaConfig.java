/*
 * Copyright 2020 Red Hat, Inc. and/or its affiliates
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
package org.keycloak.client.testsuite.models;


import java.util.Arrays;
import java.util.List;

public class CibaConfig {

    // Constants
    public static final String CIBA_POLL_MODE = "poll";
    public static final String CIBA_PING_MODE = "ping";
    public static final String CIBA_PUSH_MODE = "push";
    public static final List<String> CIBA_SUPPORTED_MODES = Arrays.asList(CIBA_POLL_MODE, CIBA_PING_MODE);

    // realm attribute names
    public static final String CIBA_BACKCHANNEL_TOKEN_DELIVERY_MODE = "cibaBackchannelTokenDeliveryMode";
    public static final String CIBA_EXPIRES_IN = "cibaExpiresIn";
    public static final String CIBA_INTERVAL = "cibaInterval";
    public static final String CIBA_AUTH_REQUESTED_USER_HINT = "cibaAuthRequestedUserHint";

    // default value
    public static final String DEFAULT_CIBA_POLICY_TOKEN_DELIVERY_MODE = CIBA_POLL_MODE;
    public static final int DEFAULT_CIBA_POLICY_EXPIRES_IN = 120;
    public static final int DEFAULT_CIBA_POLICY_INTERVAL = 5;
    public static final String DEFAULT_CIBA_POLICY_AUTH_REQUESTED_USER_HINT = "login_hint";

    private String backchannelTokenDeliveryMode = DEFAULT_CIBA_POLICY_TOKEN_DELIVERY_MODE;
    private int expiresIn = DEFAULT_CIBA_POLICY_EXPIRES_IN;
    private int poolingInterval = DEFAULT_CIBA_POLICY_INTERVAL;
    private String authRequestedUserHint = DEFAULT_CIBA_POLICY_AUTH_REQUESTED_USER_HINT;

    // client attribute names
    public static final String OIDC_CIBA_GRANT_ENABLED = "oidc.ciba.grant.enabled";
    public static final String CIBA_BACKCHANNEL_TOKEN_DELIVERY_MODE_PER_CLIENT = "ciba.backchannel.token.delivery.mode";
    public static final String CIBA_BACKCHANNEL_CLIENT_NOTIFICATION_ENDPOINT = "ciba.backchannel.client.notification.endpoint";
    public static final String CIBA_BACKCHANNEL_AUTH_REQUEST_SIGNING_ALG = "ciba.backchannel.auth.request.signing.alg";

}
