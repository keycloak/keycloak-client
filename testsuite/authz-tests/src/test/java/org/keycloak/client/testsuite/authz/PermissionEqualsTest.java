/*
 * Copyright 2018 Red Hat, Inc. and/or its affiliates
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

import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.keycloak.representations.idm.authorization.Permission;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class PermissionEqualsTest {

    @Test
    public void testEquals() {
        Assertions.assertTrue(new Permission("1", null, Collections.emptySet(), Collections.emptyMap()).equals(
                new Permission("1", null, Collections.emptySet(), Collections.emptyMap())
        ));
        Assertions.assertFalse(new Permission("1", null, Collections.emptySet(), Collections.emptyMap()).equals(
                new Permission("2", null, Collections.emptySet(), Collections.emptyMap())
        ));
        Assertions.assertFalse(new Permission("1", null, new HashSet<>(Arrays.asList("read", "write")), Collections.emptyMap()).equals(
                new Permission("1", null, Collections.emptySet(), Collections.emptyMap())
        ));
        Assertions.assertTrue(new Permission("1", null, new HashSet<>(Arrays.asList("read", "write")), Collections.emptyMap()).equals(
                new Permission("1", null, new HashSet<>(Arrays.asList("read", "write")), Collections.emptyMap())
        ));
        Assertions.assertTrue(new Permission("1", null, new HashSet<>(Arrays.asList("read", "write")), Collections.emptyMap()).equals(
                new Permission("1", null, new HashSet<>(Arrays.asList("write")), Collections.emptyMap())
        ));
        Assertions.assertFalse(new Permission("1", null, new HashSet<>(Arrays.asList("read")), Collections.emptyMap()).equals(
                new Permission("1", null, new HashSet<>(Arrays.asList("write")), Collections.emptyMap())
        ));
        Assertions.assertFalse(new Permission(null, null, new HashSet<>(Arrays.asList("write")), Collections.emptyMap()).equals(
                new Permission("1", null, new HashSet<>(Arrays.asList("write")), Collections.emptyMap())
        ));
        Assertions.assertFalse(new Permission("1", null, new HashSet<>(Arrays.asList("write")), Collections.emptyMap()).equals(
                new Permission(null, null, new HashSet<>(Arrays.asList("write")), Collections.emptyMap())
        ));
        Assertions.assertTrue(new Permission(null, null, new HashSet<>(Arrays.asList("write")), Collections.emptyMap()).equals(
                new Permission(null, null, new HashSet<>(Arrays.asList("write")), Collections.emptyMap())
        ));
        Assertions.assertTrue(new Permission(null, null, new HashSet<>(Arrays.asList("read", "write")), Collections.emptyMap()).equals(
                new Permission(null, null, new HashSet<>(Arrays.asList("read")), Collections.emptyMap())
        ));
        Assertions.assertFalse(new Permission(null, null, new HashSet<>(Arrays.asList("read", "write")), Collections.emptyMap()).equals(
                new Permission(null, null, new HashSet<>(Arrays.asList("update")), Collections.emptyMap())
        ));
        Assertions.assertFalse(new Permission(null, null, Collections.emptySet(), Collections.emptyMap()).equals(
                new Permission(null, null, new HashSet<>(Arrays.asList("read")), Collections.emptyMap())
        ));
    }
}