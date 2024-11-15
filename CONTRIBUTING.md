# Keycloak Client libraries

Keycloak is an Open Source Identity and Access Management solution for modern Applications and Services. Keycloak-client is a set of Java libraries, which can be used in the client applications to invoke Keycloak server public
APIs.

Most of the contribution rules from the [main Keycloak repository](https://github.com/keycloak/keycloak/blob/main/CONTRIBUTING.md) applies to the
Keycloak client libraries as well. Below some rules specific to client libraries.

## Building and working with the codebase

See [README](README.md) for some general rules with the details about client libraries codebase, documentation and the 
testsuite.

## Syncing the files

As pointed in the [README](README.md) some files are not "owned" by this repository, but are periodically synced from the 
Keycloak codebase main repository. So if you want to update any of these files, it needs to be updated first in the [main 
Keycloak codebase](https://github.com/keycloak/keycloak). So in general, the steps needed are usually:

1) Possibly create the [issue in the keycloak-client](https://github.com/keycloak/keycloak-client/issues) with the 
   description of the bug or RFE (This is not specific to syncing, but it 
   usually always needed for any change anywhere in keycloak-client). This step can be omitted if you think that all the 
   files, which need changing, are owned by keycloak repository.  
2) Create also [the issue in keycloak](https://github.com/keycloak/keycloak/issues)
3) Send [PR to keycloak](https://github.com/keycloak/keycloak/pulls) with your changes in the client files. This may 
   eventually require more changes in other files too (like for example adding the test in the main Keycloak repository etc)
4) Once the PR is merged, it needs to be available under last release branch. For example https://github.com/keycloak/keycloak/tree/release/26.0 . So
   it is needed to either wait for Keycloak major or minor release (this happen once in 3-4 months. During the major/minor 
   release, the new `release/XY` branch is created from the current `main` branch and this one then will be used as a base 
   for syncing to keycloak-client) or make sure that your 
   issue is backported to the last `release/XY` branch in the keycloak repository.
5) Once the above is done, you can sync the sources to Keycloak-client and send the PR in keycloak-client. However this step is 
   possibly not needed to be done as we have GH workflow, which periodically sync the sources from Keycloak and sends the pull request 
   itself.
