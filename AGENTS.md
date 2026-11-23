# Windows publication rules

- Create project commits, tags, builds and GitHub Releases under Stepan-Gribov. Check the authenticated GitHub login and the destination before publishing.
- Push Windows source changes only to Stepan-Gribov/vpn-windows. Keep any KindlyVPN upstream fetch-only. The checkout's origin push URL and default push remote must point to the personal Windows repository.
- Enable the tracked checkout guard with git config core.hooksPath .githooks. Keep publication by any root workflow restricted to the same personal account. A vendored workflow in a dependency subdirectory has no publication authority for this repository.
- Review each source diff, new commit and release archive (including the binaries) for credentials and user data. The public subscription API and verification keys may be bundled. Keep production secrets, private profiles and locally configured builds out of the public repository and release assets.
- Publish each verified Windows x64 ZIP and its checksum directly in Stepan-Gribov/vpn-windows Releases. Tag the build commit and include version notes and build instructions.
- Build Windows releases from an identified source revision. Check the packaged version and SHA-256, then download the published ZIP without GitHub authentication and compare the bytes.
- Consult Graphify before code investigation and refresh the applicable Windows graph after a release build. Separate synthetic Windows results from production acceptance.
