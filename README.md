# keycloak-client

Keycloak-client java modules

The files in the modules:

* [admin-client](admin-client)
* [admin-client-jee](admin-client-jee)
* [authz-client](authz-client)
* [policy-enforcer](policy-enforcer)

are not "owned" by this repository and hence the Java files should ideally not be directly updated. Those files are "owned" by the [main Keycloak server repository](https://github.com/keycloak/keycloak)
and hence are supposed to be updated there (whenever needed) and synced into this repository by the bash script [sync-keycloak-sources.sh](.github/scripts/sync-keycloak-sources.sh)

## Syncing the files from Keycloak repository

* Checkout [main Keycloak server repository](https://github.com/keycloak/keycloak) and build it on your laptop to make sure latest Keycloak stuff available in your local maven repository.

* Run [sync-keycloak-sources.sh](.github/scripts/sync-keycloak-sources.sh)

* Send PR with the changes to update corresponding branch (usually `main`) of [Keycloak client repository](https://github.com/keycloak/keycloak-client)

## Building the project

```
mvn clean install -DskipTests=true
```

## Running the testsuite

```
cd testsuite
mvn clean install
```

By default testsuite starts Keycloak server inside docker image, which is based on testcontainers. So it uses white-box testing from the point of view of the Keycloak server. 

When running with the argument `keycloak.lifecycle` like:

```
mvn clean install -Dkeycloak.lifecycle=remote
```

The testsuite won't start the Keycloak server, but instead tests will try to use Keycloak server, which is already started on this laptop where testsuite is running.

It is also possible to use different version of Keycloak server. By default, it uses `nightly` docker image, but can be overriden by the parameter like this:

```
mvn clean install -Dkeycloak.version.docker.image=24.0
```

