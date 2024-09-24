/*
 * Copyright 2017 Red Hat, Inc. and/or its affiliates
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

package org.keycloak.client.testsuite.authz.admin;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.keycloak.authorization.client.AuthzClient;
import org.keycloak.representations.idm.authorization.ResourceRepresentation;
import org.keycloak.representations.idm.authorization.ScopeRepresentation;
import org.testcontainers.shaded.org.hamcrest.MatcherAssert;
import org.testcontainers.shaded.org.hamcrest.Matchers;

/**
 *
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class ResourceManagementWithAuthzClientTest extends ResourceManagementTest {

    private AuthzClient authzClient;

    @Test
    public void testFindMatchingUri() {
        doCreateResource(new ResourceRepresentation("/*", Collections.emptySet(), "/*", null));
        doCreateResource(new ResourceRepresentation("/resources/*", Collections.emptySet(), "/resources/*", null));
        doCreateResource(new ResourceRepresentation("/resources-a/*", Collections.emptySet(), "/resources-a/*", null));
        doCreateResource(new ResourceRepresentation("/resources-b/{pattern}", Collections.emptySet(), "/resources-b/{pattern}", null));
        doCreateResource(new ResourceRepresentation("/resources-c/{pattern}/*", Collections.emptySet(), "/resources-c/{pattern}/*", null));
        doCreateResource(new ResourceRepresentation("/resources/{pattern}/{pattern}/*", Collections.emptySet(), "/resources/{pattern}/{pattern}/*", null));
        doCreateResource(new ResourceRepresentation("/resources/{pattern}/sub-resources/{pattern}/*", Collections.emptySet(), "/resources/{pattern}/sub-resources/{pattern}/*", null));
        doCreateResource(new ResourceRepresentation("/resources/{pattern}/sub-resource", Collections.emptySet(), "/resources/{pattern}/sub-resources/{pattern}/*", null));
        doCreateResource(new ResourceRepresentation("/rest/{version}/loader/loadTwo", Collections.emptySet(), "/rest/{version}/loader/loadTwo", null));
        doCreateResource(new ResourceRepresentation("/rest/{version}/loader/load", Collections.emptySet(), "/rest/{version}/loader/load", null));
        doCreateResource(new ResourceRepresentation(
                "/rest/{version}/carts/{cartId}/cartactions/{actionId}", Collections.emptySet(), "/rest/{version}/carts/{cartId}/cartactions/{actionId}", null));
        doCreateResource(new ResourceRepresentation("/rest/v1/carts/{cartId}/cartactions/123", Collections.emptySet(), "/rest/v1/carts/{cartId}/cartactions/123", null));
        doCreateResource(new ResourceRepresentation("Dummy Name", Collections.emptySet(),
                new HashSet<>(Arrays.asList("/dummy/605dc7ff310256017a2ec84f", "/dummy/605dc7ff310256017a2ec84f/*")), null));

        getAuthzClient();

        List<ResourceRepresentation> resources = authzClient.protection().resource().findByMatchingUri("/test");

        Assertions.assertNotNull(resources);
        Assertions.assertEquals(1, resources.size());
        Assertions.assertEquals("/*", resources.get(0).getUri());

        resources = authzClient.protection().resource().findByMatchingUri("/resources-a/test");

        Assertions.assertNotNull(resources);
        Assertions.assertEquals(1, resources.size());
        Assertions.assertEquals("/resources-a/*", resources.get(0).getUri());

        resources = authzClient.protection().resource().findByMatchingUri("/resources");

        Assertions.assertNotNull(resources);
        Assertions.assertEquals(1, resources.size());
        Assertions.assertEquals("/resources/*", resources.get(0).getUri());

        resources = authzClient.protection().resource().findByMatchingUri("/resources/");

        Assertions.assertNotNull(resources);
        Assertions.assertEquals(1, resources.size());
        Assertions.assertEquals("/resources/*", resources.get(0).getUri());

        resources = authzClient.protection().resource().findByMatchingUri("/resources-b/a");

        Assertions.assertNotNull(resources);
        Assertions.assertEquals(1, resources.size());
        Assertions.assertEquals("/resources-b/{pattern}", resources.get(0).getUri());

        resources = authzClient.protection().resource().findByMatchingUri("/resources-c/a/b");

        Assertions.assertNotNull(resources);
        Assertions.assertEquals(1, resources.size());
        Assertions.assertEquals("/resources-c/{pattern}/*", resources.get(0).getUri());

        resources = authzClient.protection().resource().findByMatchingUri("/resources/a/b/c");

        Assertions.assertNotNull(resources);
        Assertions.assertEquals(1, resources.size());
        Assertions.assertEquals("/resources/{pattern}/{pattern}/*", resources.get(0).getUri());

        resources = authzClient.protection().resource().findByMatchingUri("/resources/a/sub-resources/c/d");

        Assertions.assertNotNull(resources);
        Assertions.assertEquals(1, resources.size());
        Assertions.assertEquals("/resources/{pattern}/sub-resources/{pattern}/*", resources.get(0).getUri());

        resources = authzClient.protection().resource().findByMatchingUri("/rest/v1/loader/load");

        Assertions.assertNotNull(resources);
        Assertions.assertEquals(1, resources.size());
        Assertions.assertEquals("/rest/{version}/loader/load", resources.get(0).getUri());

        resources = authzClient.protection().resource().findByMatchingUri("/rest/v2/carts/123/cartactions/123");

        Assertions.assertNotNull(resources);
        Assertions.assertEquals(1, resources.size());
        Assertions.assertEquals("/rest/{version}/carts/{cartId}/cartactions/{actionId}", resources.get(0).getUri());

        resources = authzClient.protection().resource().findByMatchingUri("/rest/v2/carts/{cartId}/cartactions/123");

        Assertions.assertNotNull(resources);
        Assertions.assertEquals(1, resources.size());
        Assertions.assertEquals("/rest/{version}/carts/{cartId}/cartactions/{actionId}", resources.get(0).getUri());

        resources = authzClient.protection().resource().findByMatchingUri("/rest/{version}/carts/123/cartactions/123");

        Assertions.assertNotNull(resources);
        Assertions.assertEquals(1, resources.size());
        Assertions.assertEquals("/rest/{version}/carts/{cartId}/cartactions/{actionId}", resources.get(0).getUri());

        resources = authzClient.protection().resource().findByMatchingUri("/rest/{version}/carts/{cartId}/cartactions/123");

        Assertions.assertNotNull(resources);
        Assertions.assertEquals(1, resources.size());
        Assertions.assertEquals("/rest/{version}/carts/{cartId}/cartactions/{actionId}", resources.get(0).getUri());

        resources = authzClient.protection().resource().findByMatchingUri("/rest/v1/carts/123/cartactions/123");

        Assertions.assertNotNull(resources);
        Assertions.assertEquals(1, resources.size());
        Assertions.assertEquals("/rest/v1/carts/{cartId}/cartactions/123", resources.get(0).getUri());

        resources = authzClient.protection().resource().findByMatchingUri("/rest/v1/carts/{cartId}/cartactions/123");

        Assertions.assertNotNull(resources);
        Assertions.assertEquals(1, resources.size());
        Assertions.assertEquals("/rest/v1/carts/{cartId}/cartactions/123", resources.get(0).getUri());

        resources = authzClient.protection().resource().findByMatchingUri("/rest/v1/carts/345/cartactions/123");

        Assertions.assertNotNull(resources);
        Assertions.assertEquals(1, resources.size());
        Assertions.assertEquals("/rest/v1/carts/{cartId}/cartactions/123", resources.get(0).getUri());

        resources = authzClient.protection().resource().findByMatchingUri("/rest/v2/carts/345/cartactions/123");

        Assertions.assertNotNull(resources);
        Assertions.assertEquals(1, resources.size());
        Assertions.assertEquals("/rest/{version}/carts/{cartId}/cartactions/{actionId}", resources.get(0).getUri());

        resources = authzClient.protection().resource().findByMatchingUri("/dummy/605dc7ff310256017a2ec84f/nestedObject/605dc7fe310256017a2ec84c");

        Assertions.assertNotNull(resources);
        Assertions.assertEquals(1, resources.size());
        Assertions.assertEquals("Dummy Name", resources.get(0).getName());
    }

    @Test
    public void testUpdateUri() {
        getAuthzClient();

        doRemoveResource(authzClient.protection().resource().findByName("Default Resource"));

        doCreateResource(new ResourceRepresentation("/api/v1/*", Collections.emptySet(), "/api/v1/*", null));

        List<ResourceRepresentation> resources = authzClient.protection().resource().findByMatchingUri("/api/v1/servers");

        Assertions.assertNotNull(resources);
        Assertions.assertEquals(1, resources.size());
        Assertions.assertEquals("/api/v1/*", resources.get(0).getUri());

        resources.get(0).getUris().clear();
        resources.get(0).getUris().add("/api/v2/*");

        authzClient.protection().resource().update(resources.get(0));

        resources = authzClient.protection().resource().findByMatchingUri("/api/v1/servers");

        Assertions.assertNotNull(resources);
        Assertions.assertEquals(0, resources.size());

        resources = authzClient.protection().resource().findByMatchingUri("/api/v2");

        Assertions.assertNotNull(resources);
        Assertions.assertEquals(1, resources.size());
        Assertions.assertEquals("/api/v2/*", resources.get(0).getUri());
    }

    @Test
    public void testFindDeep() {
        ResourceRepresentation resource1 = new ResourceRepresentation("/*", new HashSet<>());

        resource1.addScope("a", "b", "c");
        resource1.setType("type");

        Map<String, List<String>> attributes = new HashMap<>();

        attributes.put("a", Arrays.asList("a"));
        attributes.put("b", Arrays.asList("b"));
        attributes.put("c", Arrays.asList("c"));

        resource1.setAttributes(attributes);

        resource1.setIconUri("icon");
        resource1.setUris(new HashSet<>(Arrays.asList("/a", "/b", "/c")));

        ResourceRepresentation resource = doCreateResource(resource1);
        getAuthzClient();
        List<ResourceRepresentation> representations = authzClient.protection().resource().find(resource.getId(), null, null, null, null, null, false, true,null, null);

        Assertions.assertEquals(1, representations.size());
        Assertions.assertEquals(resource.getId(), representations.get(0).getId());
        Assertions.assertEquals(resource.getName(), representations.get(0).getName());
        Assertions.assertEquals(resource.getIconUri(), representations.get(0).getIconUri());
        MatcherAssert.assertThat(resource.getUris(), Matchers.containsInAnyOrder(representations.get(0).getUris().toArray()));
        MatcherAssert.assertThat(resource.getAttributes().entrySet(), Matchers.containsInAnyOrder(representations.get(0).getAttributes().entrySet().toArray()));
    }

    @Override
    protected ResourceRepresentation doCreateResource(ResourceRepresentation newResource) {
        ResourceRepresentation resource = toResourceRepresentation(newResource);

        getAuthzClient();
        ResourceRepresentation response = authzClient.protection().resource().create(resource);

        return toResourceRepresentation(authzClient, response.getId());
    }

    @Override
    protected ResourceRepresentation doUpdateResource(ResourceRepresentation resource) {
        getAuthzClient();

        authzClient.protection().resource().update(toResourceRepresentation(resource));

        return toResourceRepresentation(authzClient, resource.getId());
    }

    @Override
    protected void doRemoveResource(ResourceRepresentation resource) {
        getAuthzClient().protection().resource().delete(resource.getId());
    }

    private ResourceRepresentation toResourceRepresentation(AuthzClient authzClient, String id) {
        ResourceRepresentation created = authzClient.protection().resource().findById(id);
        ResourceRepresentation resourceRepresentation = new ResourceRepresentation();

        resourceRepresentation.setId(created.getId());
        resourceRepresentation.setName(created.getName());
        resourceRepresentation.setIconUri(created.getIconUri());
        resourceRepresentation.setUris(created.getUris());
        resourceRepresentation.setType(created.getType());
        resourceRepresentation.setOwner(created.getOwner());
        resourceRepresentation.setScopes(created.getScopes().stream().map(scopeRepresentation -> {
            ScopeRepresentation scope = new ScopeRepresentation();

            scope.setId(scopeRepresentation.getId());
            scope.setName(scopeRepresentation.getName());
            scope.setIconUri(scopeRepresentation.getIconUri());

            return scope;
        }).collect(Collectors.toSet()));

        resourceRepresentation.setAttributes(created.getAttributes());

        return resourceRepresentation;
    }

    private ResourceRepresentation toResourceRepresentation(ResourceRepresentation newResource) {
        ResourceRepresentation resource = new ResourceRepresentation();

        resource.setId(newResource.getId());
        resource.setName(newResource.getName());
        resource.setIconUri(newResource.getIconUri());

        if (newResource.getUris() != null && !newResource.getUris().isEmpty()) {
            resource.setUris(newResource.getUris());
        } else {
            resource.setUri(newResource.getUri());
        }

        resource.setType(newResource.getType());

        if (newResource.getOwner() != null) {
            resource.setOwner(newResource.getOwner().getId());
        }

        resource.setScopes(newResource.getScopes().stream().map(scopeRepresentation -> {
            ScopeRepresentation scope = new ScopeRepresentation();

            scope.setName(scopeRepresentation.getName());
            scope.setIconUri(scopeRepresentation.getIconUri());

            return scope;
        }).collect(Collectors.toSet()));

        resource.setAttributes(newResource.getAttributes());


        return resource;
    }

    private AuthzClient getAuthzClient() {
        if (authzClient == null) {
            authzClient = getAuthzClient("/authorization-test/default-keycloak.json");
        }

        return authzClient;
    }
}