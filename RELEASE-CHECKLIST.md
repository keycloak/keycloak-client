# Release checklist

* Before release, doublecheck that all issues planned for the current release are either closed or postponed to next 
  milestone (New milestone may need to be eventually created).
  * Keycloak-client release is usually done shortly after Keycloak server major/minor release. In this case, before releasing keycloak-client (but after Keycloak server release was already finished),
    it can be good to run [Sync workflow](.github/workflows/sync-and-send-pr.yml) and merge the sent PR to doublecheck server sources are synced to keycloak-client. Some more about syncing in the [README.md](README.md). 
  * Can be also good to doublecheck in the [run-tests.yml](.github/workflows/run-tests.yml) if the tested server versions matches with the supported Keycloak server streams and update the versions if not matches. Update is
    usually needed in the case of keycloak-client release after keycloak server major/minor release as there is usually new minor server stream being added and possibly some other minor stream unsupported.
    For example after the release of Keycloak server 26.4.0, the stream `26.4` is going to be added and stream `26.3` may not be supported anymore.
    But after the release of `26.5`, the stream `26.4` might be still supported for some time. So removing may not always happen.
* Release can be done by trigger GH workflow [release.yml](.github/workflows/release.yml) (Permissions required)
* After release, it can be good to [close the corresponding milestone](https://github.com/keycloak/keycloak-client/milestones) (permissions required)
* There is a need to run [Announce workflow in keycloak-rel](https://github.com/keycloak-rel/keycloak-rel/blob/main/.github/workflows/announce.yml) (permissions required), which will update the client version in
  keycloak-quickstarts and keycloak-web and will send the blog-post to the Keycloak page.
