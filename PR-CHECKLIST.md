# Checklist for merging PRs

See the [PR Checklist of the main Keycloak server repository](https://github.com/keycloak/keycloak/blob/main/PR-CHECKLIST.md) 
for the info.

The keycloak-client currently does not have bot, so after merging PR, it is also good to doublecheck that related GH issue 
has correct label set to the upcoming version of keycloak client. For example if next version of keycloak-client release 
would be `26.0.5`, make sure that the issue has label like `release/26.0.5` added to it. It should be added manually for now.
