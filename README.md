# IQ-kbteams

A self-hosted Microsoft Teams knowledge assistant. Go owns business logic and source access. Teams protocol handling and delegated token acquisition live in a small TypeScript gateway; office-document extraction runs in an isolated Python worker.

## Status

Phase A-C local implementation checks pass; live Microsoft 365 compatibility and tenant authorization have not been verified. The implementation includes tenant-bound API authentication, Teams tab SSO, delegated OneDrive, administrator-configured SharePoint, per-user Outlook mail, and Teams chat plus associated-team channel retrieval (including incoming shared channels where the user is a member), bounded offline extraction, an admin setup UI, operator-managed provider API keys, provider connectivity checks, and a private per-user answer endpoint with citations, daily quotas, shared request concurrency controls, a monthly provider-attempt cap, and content-free audit events retained 30 days by default. The bot requests sign-in and forwards personal-chat questions to the same authenticated per-user answer endpoint; group and channel messages receive a private-tab handoff. Optional PostgreSQL supports legacy fixed queries and admin-reviewed entity, text-search, and related-list profiles. Each mapped user connects with their existing PostgreSQL LOGIN over verified TLS in bounded read-only transactions. The profiles passed a disposable PostgreSQL 18 integration fixture; validation against an organization's actual PostgreSQL service and permissions remains required. Azure Entra database OAuth is unsupported. Do not treat local builds as proof of live Microsoft or production database behavior.

## Prerequisites for a live pilot

- A Microsoft 365 tenant and operator-supplied Entra tenant ID, administrator object ID, one-time setup secret, app registrations, credentials, and consent for enabled delegated scopes.
- A DNS name with publicly reachable HTTPS for Teams callbacks and tab hosting.
- Provider credentials and an administrator-selected model endpoint.
- Optional PostgreSQL endpoint, DBA-reviewed fixed SELECT catalog, and two real mapped database LOGIN identities for permission tests.
- Docker Engine access for Compose, parser isolation checks, and whole-stack resource measurements.

Teams bot SSO is documented for personal and group chat, not channel scope. Channel sign-in therefore uses a private authenticated tab handoff. Messages already posted to Teams cannot be retroactively revoked if membership or source permissions later change.

## Local development

For a single container managed by Dokploy, deploy the GitHub repository's `master` branch in Docker Compose mode with `./docker-compose.yml` and follow `docs/DOKPLOY.md`. Configuration is injected from Dokploy's `.env`; the original `compose.yaml` keeps the separate-container deployment with file-mounted secrets.

See `docs/SETUP.md` and `docs/PHASE-C-VALIDATION.md` for configuration, implementation evidence, and remaining release gates. Compose exposes only Caddy. Secrets and encryption keys are mounted as files outside persistent data volumes.
