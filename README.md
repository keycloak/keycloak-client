# keycloak-client

Keycloak-client java modules

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

