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

package org.keycloak.client.testsuite.client;

import com.fasterxml.jackson.core.type.TypeReference;
import org.keycloak.admin.client.resource.ProtocolMappersResource;

import org.keycloak.representations.idm.ProtocolMapperRepresentation;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 *
 * @author Stan Silvert ssilvert@redhat.com (C) 2016 Red Hat Inc.
 */
public abstract class AbstractProtocolMapperTest extends AbstractClientTest {

    protected Map<String, List<ProtocolMapperRepresentation>> builtinMappers = null;

    protected void initBuiltinMappers() {
        builtinMappers = adminClient.serverInfo().getInfo().getBuiltinProtocolMappers();
    }

    protected ProtocolMapperRepresentation makeMapper(String protocol, String name, String mapperType, Map<String, String> config) {
        ProtocolMapperRepresentation rep = new ProtocolMapperRepresentation();
        rep.setProtocol(protocol);
        rep.setName(name);
        rep.setProtocolMapper(mapperType);
        rep.setConfig(config);
        return rep;
    }

    protected ProtocolMapperRepresentation makeSamlMapper(String name) {
        Map<String, String> config = new HashMap<>();
        config.put("role", "account.view-profile");
        config.put("new.role.name", "new-role-name");
        return makeMapper("saml", name, "saml-role-name-mapper", config);
    }

    protected ProtocolMapperRepresentation makeOidcMapper(String name) {
        Map<String, String> config = new HashMap<>();
        config.put("role", "myrole");
        return makeMapper("openid-connect", name, "oidc-hardcoded-role-mapper", config);
    }

    protected void assertEqualMappers(ProtocolMapperRepresentation original, ProtocolMapperRepresentation created) {
        assertNotNull(created);
        assertEquals(original.getName(), created.getName());
        assertEquals(original.getConfig(), created.getConfig());
        assertEquals(original.getProtocol(), created.getProtocol());
        assertEquals(original.getProtocolMapper(), created.getProtocolMapper());
    }

    protected boolean containsMapper(List<ProtocolMapperRepresentation> mappers, ProtocolMapperRepresentation mapper) {
        for (ProtocolMapperRepresentation listedMapper : mappers) {
            if (listedMapper.getName().equals(mapper.getName())) return true;
        }

        return false;
    }

    protected List<ProtocolMapperRepresentation> mappersToAdd(List<ProtocolMapperRepresentation> oldMappers,
                                                            List<ProtocolMapperRepresentation> builtins) {
        List<ProtocolMapperRepresentation> mappersToAdd = new ArrayList<>();
        for (ProtocolMapperRepresentation builtin : builtins) {
            if (!containsMapper(oldMappers, builtin)) mappersToAdd.add(builtin);
        }

        return mappersToAdd;
    }

    protected void testAddAllBuiltinMappers(ProtocolMappersResource resource, String protocolName) {
        List<ProtocolMapperRepresentation> oldMappers = resource.getMappersPerProtocol(protocolName);
        List<ProtocolMapperRepresentation> builtins = builtinMappers.get(protocolName);

        List<ProtocolMapperRepresentation> mappersToAdd = mappersToAdd(oldMappers, builtins);

        // This is used by admin console to add builtin mappers
        resource.createMapper(mappersToAdd);

        List<ProtocolMapperRepresentation> newMappers = resource.getMappersPerProtocol(protocolName);

        for (ProtocolMapperRepresentation rep : mappersToAdd) {
            assertTrue(containsMapper(newMappers, rep));
        }
    }
}
