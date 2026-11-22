# Windows publication rules

- Create project commits, tags, builds and GitHub Releases under Stepan-Gribov. Check the authenticated GitHub login and the destination before publishing.
- Push Windows source changes only to Stepan-Gribov/vpn-windows. Keep any KindlyVPN upstream fetch-only. The checkout's origin push URL and default push remote must point to the personal Windows repository.
- Enable the tracked checkout guard with git config core.hooksPath .githooks. Keep publication by any root workflow restricted to the same personal account. A vendored workflow in a dependency subdirectory has no publication authority for this repository.
- Review the exact source diff and new history for real service parameters, signing secrets, tokens and user data. Public source and public assets may contain only public settings or examples. Keep production ZIPs with local service configuration in the verified private Stepan-Gribov/vpn-builds Releases.
- Build Windows releases from an identified source revision. Check the packaged version and SHA-256, then download the uploaded asset using authorized access and compare the bytes.
- Consult Graphify before code investigation and refresh the applicable Windows graph after a release build. Separate synthetic Windows results from production acceptance.
