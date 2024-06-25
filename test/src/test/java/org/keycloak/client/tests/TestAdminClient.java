package org.keycloak.client.tests;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.representations.idm.RealmRepresentation;
import org.keycloak.representations.idm.UserRepresentation;

import java.util.Optional;

public class TestAdminClient {

    @Test
    public void getRealm() {
        Keycloak keycloak = Keycloak.getInstance("http://localhost:8080", "master", "admin", "admin", "admin-cli");

        RealmRepresentation realmRepresentation = keycloak.realm("master").toRepresentation();
        Assertions.assertNotNull(realmRepresentation);
        Assertions.assertEquals("master", realmRepresentation.getRealm());
    }

    @Test
    public void getUser() {
        Keycloak keycloak = Keycloak.getInstance("http://localhost:8080", "master", "admin", "admin", "admin-cli");

        Optional<UserRepresentation> first = keycloak.realm("master").users().search("admin").stream().findFirst();
        Assertions.assertTrue(first.isPresent());
        Assertions.assertEquals("admin", first.get().getUsername());
    }

}