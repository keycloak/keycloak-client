/*
  Copyright 2016 Red Hat, Inc. and/or its affiliates
  and other contributors as indicated by the @author tags.

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

 */

package org.keycloak.client.testsuite.authz.admin;

import jakarta.ws.rs.NotFoundException;
import jakarta.ws.rs.core.Response;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.keycloak.admin.client.resource.ResourceResource;
import org.keycloak.admin.client.resource.ResourcesResource;
import org.keycloak.authorization.client.util.HttpResponseException;
import org.keycloak.representations.idm.authorization.PolicyRepresentation;
import org.keycloak.representations.idm.authorization.ResourceOwnerRepresentation;
import org.keycloak.representations.idm.authorization.ResourceRepresentation;
import org.keycloak.representations.idm.authorization.ScopePermissionRepresentation;
import org.keycloak.representations.idm.authorization.ScopeRepresentation;
import org.testcontainers.shaded.org.hamcrest.MatcherAssert;
import org.testcontainers.shaded.org.hamcrest.Matchers;

/**
 *
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class ResourceManagementTest extends AbstractAuthorizationTest {

    @Test
    public void testCreate() {
        ResourceRepresentation newResource = createResource();

        Assertions.assertEquals("Test Resource", newResource.getName());
        Assertions.assertEquals("/test/*", newResource.getUri());
        Assertions.assertEquals("test-resource", newResource.getType());
        Assertions.assertEquals("icon-test-resource", newResource.getIconUri());

        Map<String, List<String>> attributes = newResource.getAttributes();

        Assertions.assertEquals(2, attributes.size());

        Assertions.assertTrue(attributes.containsKey("a"));
        Assertions.assertTrue(attributes.containsKey("b"));
        Assertions.assertTrue(attributes.get("a").containsAll(Arrays.asList("a1", "a2", "a3")));
        Assertions.assertEquals(3, attributes.get("a").size());
        Assertions.assertTrue(attributes.get("b").containsAll(Arrays.asList("b1")));
        Assertions.assertEquals(1, attributes.get("b").size());
    }

    @Test
    public void testCreateWithResourceType() {
        ResourceRepresentation newResource = new ResourceRepresentation();

        newResource.setName("test");
        newResource.setDisplayName("display");
        newResource.setType("some-type");

        newResource = doCreateResource(newResource);

        ResourceResource resource = getClientResource().authorization().resources().resource(newResource.getId());

        Assertions.assertTrue(resource.permissions().isEmpty());
    }

    @Test
    public void testQueryAssociatedPermissions() {
        ResourceRepresentation newResource = new ResourceRepresentation();

        newResource.setName("r1");
        newResource.setType("some-type");
        newResource.addScope("GET");

        newResource = doCreateResource(newResource);

        ResourceResource resource = getClientResource().authorization().resources().resource(newResource.getId());

        ScopePermissionRepresentation permission = new ScopePermissionRepresentation();

        permission.setName(newResource.getName());
        permission.addResource(newResource.getName());
        permission.addScope("GET");

        getClientResource().authorization().permissions().scope().create(permission);

        Assertions.assertFalse(resource.permissions().isEmpty());
    }

    @Test
    public void testQueryTypedResourcePermissions() {
        ResourceRepresentation r1 = new ResourceRepresentation();

        r1.setName("r1");
        r1.setType("some-type");
        r1.addScope("GET");

        r1 = doCreateResource(r1);

        ScopePermissionRepresentation permission = new ScopePermissionRepresentation();

        permission.setName(r1.getName());
        permission.addResource(r1.getName());
        permission.addScope("GET");

        getClientResource().authorization().permissions().scope().create(permission);

        ResourceRepresentation r2 = new ResourceRepresentation();

        r2.setName("r2");
        r2.setType("some-type");
        r2.addScope("GET");

        r2 = doCreateResource(r2);

        permission = new ScopePermissionRepresentation();

        permission.setName(r2.getName());
        permission.addResource(r2.getName());
        permission.addScope("GET");

        getClientResource().authorization().permissions().scope().create(permission);

        ResourceResource resource2 = getClientResource().authorization().resources().resource(r2.getId());
        List<PolicyRepresentation> permissions = resource2.permissions();

        Assertions.assertEquals(1, permissions.size());
        Assertions.assertEquals(r2.getName(), permissions.get(0).getName());

        ResourceResource resource1 = getClientResource().authorization().resources().resource(r1.getId());

        permissions = resource1.permissions();

        Assertions.assertEquals(1, permissions.size());
        Assertions.assertEquals(r1.getName(), permissions.get(0).getName());
    }

    @Test
    public void testQueryTypedResourcePermissionsForResourceInstances() {
        ResourceRepresentation r1 = new ResourceRepresentation();

        r1.setName("r1");
        r1.setType("some-type");
        r1.addScope("GET");

        r1 = doCreateResource(r1);

        ScopePermissionRepresentation permission = new ScopePermissionRepresentation();

        permission.setName(r1.getName());
        permission.addResource(r1.getName());
        permission.addScope("GET");

        getClientResource().authorization().permissions().scope().create(permission);

        ResourceRepresentation r2 = new ResourceRepresentation();

        r2.setName("r2");
        r2.setType("some-type");
        r2.addScope("GET");

        r2 = doCreateResource(r2);

        permission = new ScopePermissionRepresentation();

        permission.setName(r2.getName());
        permission.addResource(r2.getName());
        permission.addScope("GET");

        getClientResource().authorization().permissions().scope().create(permission);

        ResourceRepresentation rInstance = new ResourceRepresentation();

        rInstance.setName("rInstance");
        rInstance.setType("some-type");
        rInstance.setOwner("marta");
        rInstance.addScope("GET", "POST");

        rInstance = doCreateResource(rInstance);

        List<PolicyRepresentation> permissions = getClientResource().authorization().resources().resource(rInstance.getId()).permissions();

        Assertions.assertEquals(2, permissions.size());

        permission = new ScopePermissionRepresentation();

        permission.setName("POST permission");
        permission.addScope("POST");

        getClientResource().authorization().permissions().scope().create(permission);

        permissions = getClientResource().authorization().resources().resource(rInstance.getId()).permissions();

        Assertions.assertEquals(3, permissions.size());
    }

    @Test
    public void failCreateWithSameName() {
        final ResourceRepresentation newResource1 = createResource();

        RuntimeException re = Assertions.assertThrows(RuntimeException.class, () -> doCreateResource(newResource1));
        MatcherAssert.assertThat(re.getCause(), Matchers.instanceOf(HttpResponseException.class));
        Assertions.assertEquals(409, HttpResponseException.class.cast(re.getCause()).getStatusCode());

        newResource1.setName(newResource1.getName() + " Another");

        final ResourceRepresentation newResource2 = doCreateResource(newResource1);

        Assertions.assertNotNull(newResource2.getId());
        Assertions.assertEquals("Test Resource Another", newResource2.getName());
    }

    @Test
    public void failCreateWithSameNameDifferentOwner() {
        ResourceRepresentation martaResource = createResource("Resource A", "marta", null, null, null);
        ResourceRepresentation koloResource = createResource("Resource A", "kolo", null, null, null);

        Assertions.assertNotNull(martaResource.getId());
        Assertions.assertNotNull(koloResource.getId());
        Assertions.assertNotEquals(martaResource.getId(), koloResource.getId());

        Assertions.assertEquals(2, getClientResource().authorization().resources().findByName(martaResource.getName()).size());

        List<ResourceRepresentation> martaResources = getClientResource().authorization().resources().findByName(martaResource.getName(), "marta");

        Assertions.assertEquals(1, martaResources.size());
        Assertions.assertEquals(martaResource.getId(), martaResources.get(0).getId());

        List<ResourceRepresentation> koloResources = getClientResource().authorization().resources().findByName(martaResource.getName(), "kolo");

        Assertions.assertEquals(1, koloResources.size());
        Assertions.assertEquals(koloResource.getId(), koloResources.get(0).getId());
    }

    @Test
    public void testUpdate() {
        ResourceRepresentation resource = createResource();

        resource.setType("changed");
        resource.setIconUri("changed");
        resource.setUri("changed");

        Map<String, List<String>> attributes = resource.getAttributes();

        attributes.remove("a");
        attributes.put("c", Arrays.asList("c1", "c2"));
        attributes.put("b", Arrays.asList("changed"));

        resource = doUpdateResource(resource);

        Assertions.assertEquals("changed", resource.getIconUri());
        Assertions.assertEquals("changed", resource.getType());
        Assertions.assertEquals("changed", resource.getUri());

        attributes = resource.getAttributes();

        Assertions.assertEquals(2, attributes.size());

        Assertions.assertFalse(attributes.containsKey("a"));
        Assertions.assertTrue(attributes.containsKey("b"));
        Assertions.assertTrue(attributes.get("b").containsAll(Arrays.asList("changed")));
        Assertions.assertEquals(1, attributes.get("b").size());
        Assertions.assertTrue(attributes.get("c").containsAll(Arrays.asList("c1", "c2")));
        Assertions.assertEquals(2, attributes.get("c").size());
    }

    @Test
    public void testDelete() {
        ResourceRepresentation resource = createResource();

        doRemoveResource(resource);

        NotFoundException nfe = Assertions.assertThrows(NotFoundException.class,
                () -> getClientResource().authorization().resources().resource(resource.getId()).toRepresentation());
        Assertions.assertEquals(404, nfe.getResponse().getStatus());
    }

    @Test
    public void testAssociateScopes() {
        ResourceRepresentation updated = createResourceWithDefaultScopes();

        Assertions.assertEquals(3, updated.getScopes().size());

        Assertions.assertTrue(containsScope("Scope A", updated));
        Assertions.assertTrue(containsScope("Scope B", updated));
        Assertions.assertTrue(containsScope("Scope C", updated));
    }

    @Test
    public void testUpdateScopes() {
        ResourceRepresentation resource = createResourceWithDefaultScopes();
        Set<ScopeRepresentation> scopes = new HashSet<>(resource.getScopes());

        Assertions.assertEquals(3, scopes.size());
        Assertions.assertTrue(scopes.removeIf(scopeRepresentation -> scopeRepresentation.getName().equals("Scope B")));

        resource.setScopes(scopes);

        ResourceRepresentation updated = doUpdateResource(resource);

        Assertions.assertEquals(2, resource.getScopes().size());

        Assertions.assertFalse(containsScope("Scope B", updated));
        Assertions.assertTrue(containsScope("Scope A", updated));
        Assertions.assertTrue(containsScope("Scope C", updated));

        scopes = new HashSet<>(updated.getScopes());

        Assertions.assertTrue(scopes.removeIf(scopeRepresentation -> scopeRepresentation.getName().equals("Scope A")));
        Assertions.assertTrue(scopes.removeIf(scopeRepresentation -> scopeRepresentation.getName().equals("Scope C")));

        updated.setScopes(scopes);

        updated = doUpdateResource(updated);

        Assertions.assertEquals(0, updated.getScopes().size());
    }

    private ResourceRepresentation createResourceWithDefaultScopes() {
        ResourceRepresentation resource = createResource();

        Assertions.assertEquals(0, resource.getScopes().size());

        HashSet<ScopeRepresentation> scopes = new HashSet<>();

        scopes.add(createScope("Scope A", "").toRepresentation());
        scopes.add(createScope("Scope B", "").toRepresentation());
        scopes.add(createScope("Scope C", "").toRepresentation());

        resource.setScopes(scopes);

        return doUpdateResource(resource);
    }

    private boolean containsScope(String scopeName, ResourceRepresentation resource) {
        Set<ScopeRepresentation> scopes = resource.getScopes();

        if (scopes != null) {
            for (ScopeRepresentation scope : scopes) {
                if (scope.getName().equals(scopeName)) {
                    return true;
                }
            }
        }

        return false;
    }

    private ResourceRepresentation createResource() {
        return createResource("Test Resource", null, "/test/*", "test-resource", "icon-test-resource");
    }

    private ResourceRepresentation createResource(String name, String owner, String uri, String type, String iconUri) {
        ResourceRepresentation newResource = new ResourceRepresentation();

        newResource.setName(name);
        newResource.setUri(uri);
        newResource.setType(type);
        newResource.setIconUri(iconUri);
        newResource.setOwner(owner != null ? new ResourceOwnerRepresentation(owner) : null);

        Map<String, List<String>> attributes = new HashMap<>();

        attributes.put("a", Arrays.asList("a1", "a2", "a3"));
        attributes.put("b", Arrays.asList("b1"));

        newResource.setAttributes(attributes);

        return doCreateResource(newResource);
    }

    protected ResourceRepresentation doCreateResource(ResourceRepresentation newResource) {
        ResourcesResource resources = getClientResource().authorization().resources();

        try (Response response = resources.create(newResource)) {

            int status = response.getStatus();

            if (status != Response.Status.CREATED.getStatusCode()) {
                throw new RuntimeException(new HttpResponseException("Error", status, "", null));
            }

            ResourceRepresentation stored = response.readEntity(ResourceRepresentation.class);

            return resources.resource(stored.getId()).toRepresentation();
        }
    }

    protected ResourceRepresentation doUpdateResource(ResourceRepresentation resource) {
        ResourcesResource resources = getClientResource().authorization().resources();
        ResourceResource existing = resources.resource(resource.getId());

        existing.update(resource);

        return resources.resource(resource.getId()).toRepresentation();
    }

    protected void doRemoveResource(ResourceRepresentation resource) {
        ResourcesResource resources = getClientResource().authorization().resources();
        resources.resource(resource.getId()).remove();
    }
}