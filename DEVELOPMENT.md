# GlobiGuard Java SDK - Development Guide

## CI/CD Pipeline Overview

This repository uses GitHub Actions for automated testing, building, and publishing.

### Workflows

#### 1. **Test & Lint** (`test.yml`)
- **Triggers:** Every push to `main`/`develop`, and on all pull requests
- **What it does:**
  - Tests across Java 17 and 21
  - Runs Maven verify
  - Generates Jacoco coverage reports
- **Status check:** ✅ Must pass before merging to `main`

#### 2. **Build & Package** (`build.yml`)
- **Triggers:** Every push to `main`/`develop`, and on all pull requests
- **What it does:**
  - Builds JAR file
  - Verifies JAR integrity
  - Uploads to GitHub Artifacts
- **Purpose:** Verify package creation before publish

#### 3. **Publish** (`publish.yml`)
- **Triggers:** When a git tag matching `v*.*.*` is pushed
- **What it does:**
  - Builds and signs JAR
  - Publishes to Maven Central
  - Creates GitHub Release
- **Requirements:** Maven Central credentials and GPG key
- **Usage:**
  ```bash
  git tag v0.1.0
  git push origin v0.1.0
  ```

#### 4. **Security Scan** (`security.yml`)
- **Triggers:** Every push to `main`/`develop`, weekly on Sunday
- **What it does:**
  - Runs OWASP Dependency-Check
  - Checks for known vulnerabilities
- **Purpose:** Continuous security monitoring

### Branch Protection

The `main` branch is protected with:
- ✅ Require 1 pull request review before merging
- ✅ Require all status checks to pass
- ✅ Require branches to be up to date before merging
- ✅ Dismiss stale pull request approvals on new commits
- ✅ Require code owner reviews
- ❌ Force pushes disabled
- ❌ Deletions disabled

### Versioning Strategy

We use **Semantic Versioning** (major.minor.patch):

- **0.1.0** → Initial release
- **0.1.1** → Patch fix
- **0.2.0** → Minor feature
- **1.0.0** → Major release (breaking changes)

Update version in `pom.xml`:
```xml
<version>0.1.0</version>
```

### Publishing Workflow

```bash
# 1. Make changes on a feature branch
git checkout -b feat/new-feature
git commit -m "feat: new feature"

# 2. Update version if needed
# Edit pom.xml: <version>0.2.0</version>
git commit -m "bump: version to 0.2.0"

# 3. Push and create PR
git push origin feat/new-feature

# 4. Review, merge to main

# 5. Tag release
git tag v0.1.0
git push origin v0.1.0

# 6. Watch CI/CD publish to Maven Central
# <dependency>
#     <groupId>com.globiguard</groupId>
#     <artifactId>globiguard</artifactId>
#     <version>0.1.0</version>
# </dependency>
```

### Development Cycle

1. **Create feature branch:** `git checkout -b feature/name main`
2. **Make changes:** Edit code, test locally
3. **Run tests locally:** `mvn test`
4. **Commit:** `git commit -m "feat: description"`
5. **Push:** `git push origin feature/name`
6. **Create PR:** Open GitHub pull request to `main`
7. **Review:** Automated tests and code review
8. **Merge:** Merge PR to `main`
9. **Publish (optional):** Update version and tag

### Local Testing

```bash
# Run tests
mvn test

# Run full verification
mvn clean verify

# Build JAR
mvn clean package

# Generate coverage report
mvn clean verify jacoco:report

# View coverage: target/site/jacoco/index.html
```

### Code Owners

Code ownership is defined in `.github/CODEOWNERS`:
- All files: `@globi-explore/maintainers`
- PRs require approval from code owners before merge

### Repository Configuration

- **Default branch:** `main`
- **Discussions:** Enabled (for Q&A)
- **Releases:** Auto-generated from tags
- **Topics:** `globiguard`, `sdk`, `governance`, `java`, `maven`
- **Visibility:** Public
- **Java version:** 17+
- **Build tool:** Maven

## Troubleshooting

**Maven build fails?**
- Clear cache: `mvn clean`
- Update Maven: `mvn -v`
- Check Java: `java -version`

**Tests fail?**
- Run specific test: `mvn test -Dtest=TestClassName`
- Check logs: `mvn test -X`

**Maven Central publish fails?**
- Verify GPG key configuration
- Check Maven Central account credentials
- Ensure version format is correct

## Questions?

See main repository README or GitHub Discussions for Q&A.
