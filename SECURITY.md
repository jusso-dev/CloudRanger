# Security policy

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability. Use GitHub's private vulnerability reporting for this repository and include affected versions, impact, reproduction steps, and any suggested mitigation. Avoid including real cloud credentials, account data, or unredacted evidence.

## Automated checks

Every change is covered by frozen-lockfile builds, production dependency auditing, CodeQL analysis, and pull-request dependency review. GitHub secret scanning and push protection are enabled. Dependabot opens grouped production and development updates. Tagged release archives are built in GitHub Actions and receive a GitHub build-provenance attestation before publication.

## Triage and remediation

- Maintainers acknowledge private reports and critical/high Dependabot or CodeQL alerts within two business days.
- Confirmed critical issues are targeted for remediation or a documented containment within 72 hours; high-severity issues within seven days.
- Affected releases are identified, regression tests are added where practical, and fixes receive normal CI and security checks.
- If an immediate fix is unsafe, maintainers document compensating controls and a target date in the private advisory.
- Release attestations should be verified against this repository and the expected tag before deployment.

CloudRanger is a posture assessment tool, not a substitute for cloud-provider authorization controls or independent compliance certification.
