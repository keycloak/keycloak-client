<<<<<<< HEAD
<<<<<<< HEAD
# keycloak-client
Keycloak-client java modules
=======
# Keyloak standalone client
=======
# Keycloak standalone client
>>>>>>> 41bb4f7 (Moving admin-client and the classes it needs from Keycloak to Keycloak-client)

PoC showing a standalone Keycloak client that can be used without any direct dependencies on Keycloak.

The modules `integration/admin-client` and `integration/admin-client-jee` are modules for Java Keycloak admin client. The modules `client-common` and `client-core`
contain just subsets of the classes, from Keycloak modules `common` and `core`, which are needed by `admin-client`.

In this prototype, the classes from `common` and `core` Keycloak modules were copied from Keycloak and classes from `admin-client-*` were also copied from Keycloak 

### How to sync classes from Keycloak repository

<<<<<<< HEAD
Running `mvn dependency:tree -f test` will show that the example use of the admin client has no dependencies
on Keycloak server JARs.
>>>>>>> 8daf0a5 (PoC shaded admin client)
=======
- Tested with OpenJDK 17.0.11 and Maven 3.6.3

- Go to `keycloak` repository with Keycloak sources and add the remote repository if not already present (TODO: Replace with `upstream` once https://github.com/keycloak/keycloak/pull/30588 is merged)
```
git remote add mposolda git@github.com:mposolda/keycloak.git
```

- Sync the Java classes from the specified branch of the `keycloak` repository
```
.github/scripts/sync-keycloak-sources.sh  keycloak-admin-client-orig ../keycloak mposolda
```

- Check the synced classes by running `git status` or `git diff` to see what Java classes were copied from the `keycloak` repository 

- Run `mvn clean install` on this project

- Run the tests (TODO: Should be done automatically and don't require manually start Keycloak server):
  - Manually run Keycloak server `./kc.sh start-dev` and make sure that `admin/admin` exists
  - Run manually tests like `TestAdminClient`

- Send PR with the synced Java classes

WARNING: Make sure to not include any quarkus dependencies OR any keycloak server dependencies to this project and to parent pom. The testsuite module is the only exception where Keycloak
dependencies might be present.
>>>>>>> 41bb4f7 (Moving admin-client and the classes it needs from Keycloak to Keycloak-client)
