# Security Policy

## Scope
ThreatTrail is an educational SOC investigation training MVP designed for local or classroom lab environments. It is **not** intended to be exposed directly to the public internet without additional production hardening.

## Reporting a Vulnerability
If you discover a security vulnerability in ThreatTrail:
1. **Do not open a public GitHub issue.**
2. Email the maintainer directly or submit a private security advisory through the repository's **Security > Advisories** tab.
3. Include steps to reproduce, affected endpoint/component, and potential impact.

## Security Controls Implemented in This MVP
* Passwords hashed using `bcrypt` / `argon2`.
* Server-side answer grading (`correct_answer` excluded from question fetch payloads).
* Rate limiting on `/api/auth/login` and `/api/scenarios/{id}/submit`.
* Size and path-traversal checks on Admin `.zip`/`.json` log uploads.
* Strict CORS allowlist and HTTP security headers (`CSP`, `X-Frame-Options`, `X-Content-Type-Options`).
