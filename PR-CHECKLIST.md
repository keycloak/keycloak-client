# Checklist for merging PRs

See the [PR Checklist of the main Keycloak server repository](https://github.com/keycloak/keycloak/blob/main/PR-CHECKLIST.md) 
for the info.

The Keycloak client currently does not have a bot, so after merging a PR, it is also good to double-check that the related GH issue 
has a correct label set to the upcoming version of Keycloak client. For example if next version of the Keycloak client release 
would be `26.0.5`, make sure that the issue has label like `release/26.0.5` added to it. It should be added manually for now.
