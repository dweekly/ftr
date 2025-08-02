# Release Process

This document describes the secure release process for ftr. This process ensures that all releases are thoroughly tested and validated before artifacts are published.

## Overview

The release process has been designed with the following security principles:
- No release can be created from untested code
- All releases must go through the full CI pipeline
- Release artifacts are only built from validated commits on the main branch
- The process is auditable through PR history

## Prerequisites

Before starting a release:
1. Ensure all planned features and fixes are merged to main
2. Update CHANGELOG.md with all changes for the release
3. Ensure the version in Cargo.toml is updated
4. Run `cargo test` locally to verify tests pass
5. Run `cargo clippy -- -D warnings` to ensure no linting issues

## Release Steps

### 1. Create a Release Branch

```bash
# Create a release branch from main
git checkout main
git pull origin main
git checkout -b release-v0.x.y
```

### 2. Update Version and Changelog

1. Update version in `Cargo.toml`
2. Update `CHANGELOG.md`:
   - Move items from `[Unreleased]` to a new version section
   - Add the release date
   - Update the comparison links at the bottom

3. Commit the changes:
```bash
git add Cargo.toml CHANGELOG.md
git commit -m "Prepare for v0.x.y release"
```

### 3. Create a Pull Request

1. Push the release branch:
```bash
git push -u origin release-v0.x.y
```

2. Create a PR from `release-v0.x.y` to `main`
3. Ensure all CI checks pass:
   - Tests on all platforms (Linux, macOS, Windows, FreeBSD)
   - Clippy and formatting checks
   - Security audit
   - Documentation builds

4. Get the PR reviewed and approved by maintainers

### 4. Merge and Tag

1. Merge the PR to main
2. Pull the latest main locally:
```bash
git checkout main
git pull origin main
```

3. Create and push the release tag:
```bash
git tag -a v0.x.y -m "Release v0.x.y

Brief description of major changes

See CHANGELOG.md for full details"

git push origin v0.x.y
```

### 5. Monitor the Release Pipeline

When you push the tag, the following automated processes will run:

1. **Release Validation** (`validate-release.yml`):
   - Verifies the tag points to a commit on main
   - Checks that Cargo.toml version matches the tag
   - Runs the full CI suite again
   - Validates that all checks pass

2. **Artifact Building** (only if validation passes):
   - Debian packages built for amd64 and arm64
   - Windows binaries built for x64 and ARM64
   - Draft GitHub release created with artifacts

3. **Monitor the Actions tab** in GitHub to ensure all workflows succeed

### 6. Publish the Release

1. Go to the GitHub Releases page
2. Find the draft release created by the workflow
3. Edit the release notes:
   - Add a summary of key changes
   - Include installation instructions
   - Link to the full CHANGELOG
   - Credit contributors

4. **Publish the release** (this triggers the crates.io publish)

### 7. Verify the Release

After publishing:
1. Check that the release appears on crates.io
2. Test installation methods:
   - `cargo install ftr`
   - Debian package installation
   - Windows binary execution
3. Update any documentation that references the version

## Security Considerations

### What the Validation Prevents

1. **Direct tag pushing**: Tags must point to commits that exist on main
2. **Untested releases**: Full CI must run and pass before artifacts are built
3. **Version mismatches**: Tag version must match Cargo.toml version
4. **Bypassing PR process**: Commits should go through PR review

### Branch Protection Rules

Ensure these GitHub branch protection rules are configured for `main`:
- Require pull request reviews before merging
- Require status checks to pass before merging
- Require branches to be up to date before merging
- Include administrators in restrictions
- Require conversation resolution before merging

## Troubleshooting

### Release validation fails

If the validation workflow fails:
1. Check that the tag points to a commit on main
2. Verify Cargo.toml version matches the tag
3. Ensure the commit has passed CI (was part of a merged PR)

### CI fails on release tag

If CI fails when running on the release tag:
1. Fix the issue on a new branch
2. Create a PR to main
3. After merging, delete the failed tag: `git push --delete origin v0.x.y`
4. Start the release process again

### Crates.io publish fails

If the crates.io publish fails:
1. Check the error message in the GitHub Actions log
2. Common issues:
   - Version already exists on crates.io
   - Missing or invalid API token
   - Cargo.toml metadata issues

## Emergency Release Process

In case of critical security fixes:
1. Follow the same process but use `hotfix-v0.x.y` as the branch name
2. Ensure the fix is minimal and focused
3. Fast-track the PR review with multiple maintainers
4. Document the emergency release in CHANGELOG.md