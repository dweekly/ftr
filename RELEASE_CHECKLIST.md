# Release Checklist for ftr

This checklist should be followed when preparing a new release.

## Pre-release Steps

- [ ] **Update version number** in `Cargo.toml`
- [ ] **Update CHANGELOG.md**
  - [ ] Move items from "Unreleased" to the new version section
  - [ ] Add the release date
  - [ ] Update version comparison links at the bottom
  - [ ] Ensure all significant changes are documented
- [ ] **Run tests** - `cargo test`
- [ ] **Run lints** - `cargo clippy`
- [ ] **Build locally** - `cargo build --release`
- [ ] **Test the binary** - Run a few manual tests
- [ ] **Commit all changes** with message like "Prepare for v0.x.x release"

## Creating the Release

1. **Create and push the tag**:
   ```bash
   git tag -a v0.x.x -m "Release v0.x.x"
   git push origin v0.x.x
   ```

2. **Wait for CI** - The GitHub Actions workflow will:
   - Build binaries for multiple platforms
   - Create .deb packages for amd64 and arm64
   - Create a draft GitHub release with assets

3. **Edit the GitHub release**:
   - Copy the relevant section from CHANGELOG.md
   - Add any additional notes or highlights
   - Publish the release

## Post-release Steps

- [ ] **Verify release assets** - Check that .deb files are attached
- [ ] **Test installation methods**:
  - [ ] Homebrew: `brew update && brew upgrade ftr`
  - [ ] Cargo: `cargo install ftr`
  - [ ] Debian package: Download and test .deb installation
- [ ] **Update README** if needed (e.g., new installation instructions)
- [ ] **Announce the release** (if applicable)

## Automation Ideas

Consider adding these GitHub Actions checks:
- Workflow that fails if CHANGELOG.md doesn't contain the new version
- Pre-commit hook to remind about CHANGELOG updates
- Release workflow that extracts notes from CHANGELOG.md automatically