package org.keycloak.client.testsuite.authz;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.keycloak.adapters.authorization.cip.spi.ClaimInformationPointProvider;
import org.keycloak.adapters.authorization.cip.spi.ClaimInformationPointProviderFactory;
import org.keycloak.adapters.authorization.spi.HttpRequest;

public class MyCustomCIPFactory implements ClaimInformationPointProviderFactory<MyCustomCIP> {

    @Override
    public String getName() {
        return "my-custom-cip";
    }

    @Override
    public MyCustomCIP create(Map<String, Object> config) {
        return new MyCustomCIP(config);
    }
}

class MyCustomCIP implements ClaimInformationPointProvider {

    private final Map<String, Object> config;

    MyCustomCIP(Map<String, Object> config) {
        this.config = config;
    }

    @Override
    public Map<String, List<String>> resolve(HttpRequest request) {
        Map<String, List<String>> claims = new HashMap<>();

        claims.put("resolved-claim", Arrays.asList(config.get("claim-value").toString()));

        return claims;
    }
}

