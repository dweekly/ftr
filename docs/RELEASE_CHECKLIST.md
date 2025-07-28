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

1. **Ensure crates.io access** (first time only):
   - Make sure you have a crates.io account
   - Create an API token at https://crates.io/settings/tokens
   - Add it as `CARGO_REGISTRY_TOKEN` secret in GitHub repository settings

2. **Create and push the tag**:
   ```bash
   git tag -a v0.x.x -m "Release v0.x.x"
   git push origin v0.x.x
   ```

3. **Wait for CI to create draft release** - The workflow will:
   - Build .deb packages for amd64 and arm64
   - Create a DRAFT GitHub release with assets
   - NOT publish to crates.io yet (waits for release publication)

4. **Edit the draft release on GitHub**:
   - Go to the releases page and find the draft
   - Replace the placeholder text with actual release notes
   - Copy the relevant section from CHANGELOG.md
   - Add any additional highlights or breaking changes
   - Review everything carefully (this will be shown on crates.io!)
   
5. **Publish the release**:
   - Click "Publish release" on GitHub
   - This will trigger the crates.io publication
   - The same release notes will be used for crates.io

## Post-release Steps

- [ ] **Verify release assets** - Check that .deb files are attached
- [ ] **Verify crates.io publication**:
  - [ ] Check https://crates.io/crates/ftr
  - [ ] Verify the README is displayed correctly
  - [ ] Note: crates.io uses README.md from the git tag, not release notes
- [ ] **Update Homebrew tap**:
  - [ ] Check https://github.com/dweekly/homebrew-ftr/blob/main/ftr.rb
  - [ ] Update version, URL, and SHA256 in ftr.rb
  - [ ] URL format: `https://github.com/dweekly/ftr/archive/refs/tags/vX.Y.Z.tar.gz`
  - [ ] Get SHA256: `curl -sL https://github.com/dweekly/ftr/archive/refs/tags/vX.Y.Z.tar.gz | shasum -a 256`
  - [ ] Commit and push to homebrew-ftr repository
- [ ] **Test installation methods**:
  - [ ] Homebrew: `brew update && brew upgrade ftr`
  - [ ] Cargo: `cargo install ftr` (wait ~5 minutes for crates.io to update)
  - [ ] Debian package: Download and test .deb installation
- [ ] **Update README** if needed (e.g., new installation instructions)
- [ ] **Announce the release** (if applicable)

## Automation Ideas

Consider adding these GitHub Actions checks:
- Workflow that fails if CHANGELOG.md doesn't contain the new version
- Pre-commit hook to remind about CHANGELOG updates
- Release workflow that extracts notes from CHANGELOG.md automatically