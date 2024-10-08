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
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.keycloak.admin.client.resource.ResourceScopeResource;
import org.keycloak.admin.client.resource.ResourcesResource;
import org.keycloak.representations.idm.authorization.ResourceRepresentation;
import org.keycloak.representations.idm.authorization.ScopePermissionRepresentation;
import org.keycloak.representations.idm.authorization.ScopeRepresentation;

/**
 *
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class ScopeManagementTest extends AbstractAuthorizationTest {

    @Test
    public void testCreate() {
        ScopeRepresentation newScope = createDefaultScope().toRepresentation();

        Assertions.assertEquals("Test Scope", newScope.getName());
        Assertions.assertEquals("Scope Icon", newScope.getIconUri());
    }

    @Test
    public void testUpdate() {
        ResourceScopeResource scopeResource = createDefaultScope();
        ScopeRepresentation scope = scopeResource.toRepresentation();

        scope.setName("changed");
        scope.setIconUri("changed");

        scopeResource.update(scope);

        scope = scopeResource.toRepresentation();

        Assertions.assertEquals("changed", scope.getName());
        Assertions.assertEquals("changed", scope.getIconUri());
    }

    @Test
    public void testNotUpdateOnResourceUpdate() {
        ResourceScopeResource scopeResource = createDefaultScope();
        ScopeRepresentation scope = scopeResource.toRepresentation();

        scope.setName("changed");
        scope.setDisplayName("changed");
        scope.setIconUri("changed");

        scopeResource.update(scope);

        scope = scopeResource.toRepresentation();

        Assertions.assertEquals("changed", scope.getName());
        Assertions.assertEquals("changed", scope.getDisplayName());
        Assertions.assertEquals("changed", scope.getIconUri());

        ResourcesResource resources = getClientResource().authorization().resources();
        ResourceRepresentation resource;

        try (Response response = resources
                .create(new ResourceRepresentation(UUID.randomUUID().toString(), scope.getName()))) {
            resource = response.readEntity(ResourceRepresentation.class);
        }

        resource.getScopes().iterator().next().setDisplayName(null);
        resources.resource(resource.getId()).update(resource);

        scope = scopeResource.toRepresentation();

        Assertions.assertEquals("changed", scope.getName());
        Assertions.assertEquals("changed", scope.getDisplayName());
        Assertions.assertEquals("changed", scope.getIconUri());
    }

    @Test
    public void testDelete() {
        ResourceScopeResource scopeResource = createDefaultScope();

        scopeResource.remove();

        NotFoundException nfe = Assertions.assertThrows(NotFoundException.class, () -> scopeResource.toRepresentation());
        Assertions.assertEquals(404, nfe.getResponse().getStatus());
    }

    @Test
    public void testDeleteAndPolicyUpdate() {
        ResourceScopeResource scopeResource = createDefaultScope();

        ScopeRepresentation scopeRepresentation = scopeResource.toRepresentation();
        ScopePermissionRepresentation representation = new ScopePermissionRepresentation();

        representation.setName(scopeRepresentation.getName());
        representation.addScope(scopeRepresentation.getId());

        getClientResource().authorization().permissions().scope().create(representation);

        ScopePermissionRepresentation permissionRepresentation = getClientResource().authorization().permissions().scope()
                .findByName(scopeRepresentation.getName());
        List<ScopeRepresentation> scopes = getClientResource().authorization().policies()
                .policy(permissionRepresentation.getId()).scopes();

        Assertions.assertEquals(1, scopes.size());

        scopeResource.remove();

        NotFoundException nfe = Assertions.assertThrows(NotFoundException.class,
                () -> getClientResource().authorization().policies().policy(permissionRepresentation.getId()).scopes());
        Assertions.assertEquals(404, nfe.getResponse().getStatus());
    }
}
