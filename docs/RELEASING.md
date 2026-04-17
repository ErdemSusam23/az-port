# Releasing az-port

This repository is set up to publish binaries through GitHub Releases.

## Release Flow

1. Make sure `main` contains the changes you want to ship.
2. Run the local verification commands:

```bash
go test ./...
go build ./...
```

3. Create an annotated version tag:

```bash
git tag -a v0.1.0 -m "v0.1.0"
```

4. Push the branch and the tag:

```bash
git push origin main
git push origin v0.1.0
```

5. GitHub Actions will run `.github/workflows/release.yml` and publish the release automatically.

## Published Artifacts

The release workflow currently publishes:

- `az-port_Windows_x86_64.zip`
- `az-port_Linux_x86_64.tar.gz`
- `az-port_macOS_x86_64.tar.gz`
- `az-port_macOS_arm64.tar.gz`
- `checksums.txt`

Each archive includes:

- the `az-port` binary for that platform
- `README.md`
- `LICENSE`

## Manual Release Trigger

You can also run the workflow manually from GitHub Actions with `workflow_dispatch` to validate packaging without cutting a release tag.

Note: the manual run uploads workflow artifacts, but the GitHub Release publish step only runs for tag builds.
