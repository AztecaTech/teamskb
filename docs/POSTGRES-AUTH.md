# PostgreSQL authorization adapters

## Choosing search sources

The question form offers **Database only**, **Microsoft only**, and **Database
and Microsoft**. The server filters retrieval to the selected, administrator-enabled
sources. Existing bot/API callers that omit `scope` retain combined search behavior.
Database-only requests avoid Microsoft content retrieval; Microsoft-only requests
avoid database catalog checks, query selection, and database identity email lookup.

Independent Microsoft source searches run concurrently. Fixed-query permission
checks return zero rows, and a single approved fixed database query skips the
selector model call. Actual query execution still resolves current user permissions.
Business profiles retain schema and two-user validation.

Results label Database versus Microsoft citations and show per-source result
counts, unavailable sources, missing approved queries, and partial-result warnings.
Deployment logs include content-free request IDs, scope, source status/counts, and
timings for catalog checks, selection, retrieval, and answer generation. The startup
logs alone cannot diagnose search latency. No production speedup is claimed by the
local fixture; model/provider and Microsoft latency still affect real requests.

The shared connection in Dokploy supplies database credentials, not a user's
permissions. IQ Knowledge resolves the signed-in Teams member's directory email,
looks up one database identity, and applies its restricted PostgreSQL role inside
each read-only transaction. Results reach the model only after database access
rules have filtered them.

## Deployment and setup

1. Grant delegated Microsoft Graph `User.Read` to the Entra app and provide the
   required tenant consent. The app obtains `/me` through its existing OBO gateway.
   The returned object ID must match the verified Teams object ID. Guest accounts,
   missing directory `mail`, and failed directory lookups cannot use this adapter.
   The app does not accept a browser-supplied email or fall back to a username.
2. Set `POSTGRES_DSN` to a dedicated service login and password with verified TLS,
   for example `postgres://iqkb_service:URL_ENCODED_PASSWORD@db.example.com:5432/company?sslmode=verify-full`.
   Administrator-only mapping discovery inspects catalog metadata using the injected URI, including when that URI uses an administrator login. It scans likely email-bearing relations in pages of 25 and reports detected fields without granting search access. Actual user authorization and searches still reject superuser or BYPASSRLS service logins.

   The service must not be a superuser or have BYPASSRLS. Use NOINHERIT, grant
   direct SELECT access only to the authorization view, and grant permission to
   SET ROLE to the restricted execution roles. Do not use a database owner login.
3. Provide the authorization view described below. Existing users and permissions
   are authoritative; the app neither creates users nor grants database privileges.
4. In **Workspace settings → Sources → PostgreSQL**, choose the permission
   system and select **Detect user mapping and prefill**. This administrator-only
   step reads metadata through the shared service connection before an adapter
   or user email mapping exists. One complete candidate prefills an empty draft;
   multiple candidates require selection. Complete pagination before accepting
   automatic selection. Ordinary user tables missing adapter fields are listed
   as incomplete rather than being treated as permission mappings. Review the
   detected schema/name and enter the DBA review reference, then select
   **Save and check my access**. No user password is needed in shared mode.
5. Review the query catalog or business profiles, test each profile with two
   distinct database users, and activate PostgreSQL search.

Without service credentials the previous individual PostgreSQL-login mode remains
available. Adding service credentials requires an adapter; it never enables
unrestricted service-account searches automatically.

After authorization, **Discover accessible schema** supplies content relations to
the approved-query form. Selecting a compatible relation prefills its query ID,
description and parameterized SQL, provided all four contract columns are present.
Existing drafts are preserved. Detection never invents approval records or saves
queries automatically; use the normal review and save actions.

## Authorization view contract

Create a DBA-maintained view which adapts your existing identity/permission tables
to these columns. Use schema-qualified joins and review all role translations.

| Column | Required meaning |
| --- | --- |
| `tenant_id` | Entra tenant UUID as text, or UUID castable to text |
| `email` | Organization email matching the member's directory `mail` |
| `user_id` | Stable application user ID, castable to text |
| `database_role` | Actual restricted PostgreSQL execution role, not merely an application role label |
| `active` | Boolean indicating whether the user can access this integration |
| `permission_version` | Nonempty revision which changes when this user's effective permissions change |

The lookup is parameterized by authenticated tenant and normalized email. It must
produce exactly one row, including inactive rows; absent, inactive, NULL, duplicate,
unsafe-role, and cross-tenant matches fail closed. A missing or unreadable view also
denies access. The selected role must differ from the service login and be granted
to it. Both LOGIN and NOLOGIN execution roles are supported.

One database user may have several application roles. Resolve those into one
approved database execution role or into policies keyed by the stable user ID;
do not return multiple lookup rows. Keep email ownership and tenant associations
correct in your directory and auth system. Matching an email alone is not a grant.

## Permission modes

**PostgreSQL roles:** each transaction uses `SET LOCAL ROLE` to the role returned
by the adapter. PostgreSQL grants and RLS policies apply as that `current_user`.
Policies depending on `session_user` need adaptation: it remains the service login.
Use individual-login mode if those policies cannot be changed.

**Application auth with database policies:** uses the returned restricted role and
adds `request.jwt.claims` with `sub` (database user ID), `email`, `role`, `tenant_id`,
and `teams_object_id`. This supports database policies reading these claims. These
are server-established transaction claims, not a JWT issued by the external auth
provider. The execution role cannot own data tables or bypass RLS.

Both modes also provide transaction-local settings `iqkb.user_id`, `iqkb.email`,
`iqkb.tenant_id`, and `iqkb.teams_object_id`. Example policy expression for your
own schema:

```sql
tenant_id::text = current_setting('iqkb.tenant_id', true)
AND owner_user_id::text = current_setting('iqkb.user_id', true)
```

A DBA must implement and review policies or approved views/queries for the actual
auth system. Merely supplying an application role such as `manager` does not
restrict rows. Backend-only permission code in an external application is not
automatically executed by a direct PostgreSQL connection. This adapter supports
systems whose permissions are enforced in the database; additional server-side
authorization adapters are needed for systems with exclusively API-based rules.

Role and user context are LOCAL to the read-only transaction and are rolled back
before closing its connection. Schema discovery and profile validation inspect
the effective role's privileges rather than the service login's privileges.

## Revocation and verification

User lookup, role safety and membership checks run for every database operation.
Update `permission_version` whenever effective permissions change. Profile test
evidence records the resolved user, role, permission revision, profile fingerprint,
and adapter fingerprint. Activation and profile searches reject outdated evidence;
saving an adapter clears its evidence. Two emails resolving to the same database
user count as one user for profile validation.

Run `scripts/validate-postgres-auth.ps1` for a disposable TLS-enabled PostgreSQL 15
fixture. It tests both permission modes, user isolation, discovery, profiles,
read-only transactions, state cleanup, missing/inactive/duplicate users,
cross-tenant lookup, unsafe roles, account/role revocation, API setup, two-user
evidence, query retrieval, permission revision changes, and evidence invalidation.
It does not connect to the production database or verify live Teams consent.

See the official [Graph user endpoint](https://learn.microsoft.com/en-us/graph/api/user-get?view=graph-rest-1.0)
and [PostgreSQL SET ROLE documentation](https://www.postgresql.org/docs/current/sql-set-role.html).
