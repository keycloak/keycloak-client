# Keycloak-client libraries

Keycloak-client is a set of Java libraries, which can be used in the client applications to invoke Keycloak server public 
APIs. This include Keycloak admin REST API and API for calling authorization services or enforcing access decisions by using 
policy enforcer.

The core functionality is in the modules:
* [admin-client](admin-client) - Java library for invoke Keycloak Admin REST API
* [authorization-client](authz-client) - Java library for invoke Authorization API
* [policy-enforcer](policy-enforcer) - Java library for enforce authorization decisions. It consumes the authorization-client
* [common module](client-common-synced) - Common classes and JSON representation mapping classes, which are used by other 
  libraries from above 
* [documentation](docs) - Documentation
* [testsuite](testsuite) - Testsuite

The client libraries have release lifecycle independent of Keycloak server releases. The libraries don't have any direct 
dependency on Keycloak server libraries.  

## Synchronized modules

The files in the modules:

* [client-common-synced](client-common-synced)
* [admin-client](admin-client)
* [authz-client](authz-client)

are not "owned" by this repository and hence the Java files should ideally not be directly updated. Those files are "owned" by the [main Keycloak server repository](https://github.com/keycloak/keycloak)
and hence are supposed to be updated there (whenever needed) and synced into this repository by the bash script [sync-keycloak-sources.sh](.github/scripts/sync-keycloak-sources.sh)

The reason is, that for better interoperability and to avoid issues with the transitive dependencies, we want Keycloak-client libraries to not be
dependent on the Keycloak server and, at the same time, Keycloak server not to be dependent on Keycloak-client libraries. But still have a way to
re-use some of those classes between both Keycloak and Keycloak-client libraries.

> [!NOTE] 
> **client-common-synced** module will be synced from Keycloak Main repository for the future and is a dependency of rest of the modules in this repository. Modules **admin-client** and **authz-client** may move to this repository in the future, therefore they are separated.

### Syncing the files from Keycloak repository

Syncing can be done by triggering the [Sync workflow](.github/workflows/sync-and-send-pr.yml) (permissions required). If it needs to be done by manually, then those steps might be needed: 

* Fetch [main Keycloak server repository](https://github.com/keycloak/keycloak) and checkout the last `release/X.Y` branch (For example `git checkout release/26.0`). Note that we usually cannot
sync from the server `main` branch as it is under development and there is still a chance that some things being developed here would be later updated/removed. Which could be an issue as for client, we
want to preserve backwards compatibility.

* build it on your laptop to make sure latest Keycloak stuff available in your local maven repository.

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

## Building the documentation

Documentation is in the module [docs](docs). It is automatically build when you build the project. For reviewing the 
build documentation, you can check the file `docs/guides/target/generated-docs/securing-apps/index.html`. After the 
release of the particular keycloak-client version, the documentation can be seen inside [the guides on the Keycloak web page](https://www.keycloak.org/guides#securing-apps).

## Reporting the bug or feature request

Please create new issue [here](https://github.com/keycloak/keycloak-client/issues) if it does not yet exists.
