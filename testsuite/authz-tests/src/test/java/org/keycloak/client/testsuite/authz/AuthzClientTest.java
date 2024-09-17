/*
 * Copyright 2024 Red Hat, Inc. and/or its affiliates
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

package org.keycloak.client.testsuite.authz;

import java.io.ByteArrayInputStream;
import java.util.Iterator;
import java.util.Map;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.keycloak.authorization.client.AuthzClient;
import org.testcontainers.shaded.org.hamcrest.MatcherAssert;
import org.testcontainers.shaded.org.hamcrest.Matchers;

public class AuthzClientTest {

    @Test
    public void testCreateWithEnvVars() {
        String configuration =
                """
                {
                  "realm": "${env.%s}",
                  "auth-server-url": "${env.%s}",
                  "ssl-required": "external",
                  "enable-cors": true,
                  "resource": "my-server",
                  "credentials": {
                    "secret": "${env.KEYCLOAK_SECRET}"
                  },
                  "policy-enforcer": {
                    "enforcement-mode": "ENFORCING"
                  }
                }
                """;

        RuntimeException runtimeException = Assertions.assertThrows(RuntimeException.class, () -> {
            Map<String, String> env = System.getenv();
            Assertions.assertTrue(env.size() > 1);
            Iterator<String> names = env.keySet().iterator();
            String conf = String.format(configuration, names.next(), names.next());
            System.err.println(conf);
            AuthzClient.create(new ByteArrayInputStream(conf.getBytes()));
        });

        MatcherAssert.assertThat(runtimeException.getMessage(), Matchers.containsString("Could not obtain configuration from server"));
    }
}
