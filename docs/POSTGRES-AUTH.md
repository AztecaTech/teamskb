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

For a PostgreSQL service without TLS on the same private Dokploy network, explicitly set `POSTGRES_CONNECTION_MODE=private_network` and use `POSTGRES_DSN=postgresql://USER:PASSWORD@INTERNAL_DATABASE_HOST:5432/DATABASE?sslmode=disable`. Attach the app and database to the same private Docker network. Use Dokploy's internal database hostname and internal port, not the externally published endpoint. This mode sends database traffic without TLS and rejects public and link-local destination IPs at connection time. User mapping, role checks, read-only transactions, and row policies remain enforced. The default `POSTGRES_CONNECTION_MODE=verify_full` continues to require verified TLS. Changing only `sslmode=disable` while keeping the default mode is rejected during startup.

For an externally published PostgreSQL endpoint without TLS, explicitly set `POSTGRES_CONNECTION_MODE=external_plaintext` and use `POSTGRES_DSN=postgresql://USER:PASSWORD@EXTERNAL_HOST:PUBLISHED_PORT/DATABASE?sslmode=disable`. This accepts external hostnames and public IP addresses using the configured published port. Database credentials and traffic are sent without encryption. It does not automatically downgrade a TLS connection. The same email mapping, execution role, and row-policy checks apply in all three modes.

Mapping discovery uses metadata column names and types, rather than a fixed table name. A unique candidate with recognizable email, user ID, role, and boolean account-status columns prefills an editable column mapping. Common aliases such as `id`, `role`, and `enabled` are supported; multiple matching candidates require administrator selection. Business tables with only an email column do not qualify automatically. Existing mapping drafts are preserved.

An explicit column mapping can use the source relation directly instead of creating the canonical six-column authorization view. If no tenant column exists, saving binds the mapping to the signed-in administrator's Microsoft tenant on the server; other tenants are rejected. If no permission-version column exists, a hash of the mapped user record provides change detection for profile evidence. The role value must still name an allowed PostgreSQL execution role granted to the service login; application role labels alone do not establish database permissions. Custom column names remain editable. A review note or ticket is optional: when omitted, the server records the signed-in administrator and UTC save time automatically.

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

   Dokploy HTTPS for the application does not enable PostgreSQL TLS. The database endpoint must support TLS itself, and its certificate must match the URI hostname and be trusted by the app container. Mapping discovery reports `database_tls_unavailable` if the endpoint refuses PostgreSQL SSL negotiation, `database_tls_handshake_failed` for an invalid TLS response, and `database_connection_closed` if the endpoint closes the connection during setup. These failures happen before table metadata or email mappings can be inspected.
   Administrator-only mapping discovery inspects catalog metadata using the injected URI, including when that URI uses an administrator login. It scans likely email-bearing relations in pages of 25 and reports detected fields without granting search access. Shared-adapter authorization may use privileged URI credentials only to resolve the mapped user. Before returning a search transaction, a superuser connection changes its session authorization and execution role to the mapped restricted role.

   Prefer a restricted service login without superuser or BYPASSRLS. Use NOINHERIT, grant
   direct SELECT access only to the authorization view, and grant permission to
   SET ROLE to the restricted execution roles. Do not use a database owner login.
3. Provide the authorization view or column mapping described below. Existing
   users are authoritative; the app does not create users. Existing database
   permissions can be reused, or an administrator can explicitly install new,
   reviewed integration rules through the permission-draft workflow below.
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

## User email confirmation

## Permission drafts for detected labels

Selecting Enable PostgreSQL search persists the source choice and immediately runs an administrator readiness check. The UI displays Selected — setup incomplete until the current user's email/permissions, nonempty query catalog, required profile evidence, and query checks pass. The selection flag alone never means queries are authorized. Readiness feedback appears beside the toggle and links to the next required setup section; it is refreshed after identity confirmation and when loading administrator settings. Draft rules are not database deployment. Ready for activation refers to this source's checks; workspace/provider activation remains separate.

A recognized email with unresolved permissions reports `database_permission_mapping_required`, rather than asking the user to repeat email confirmation. Each label can generate its own SQL preview independently. After its reviewed SQL is applied, a completed execution-role translation can be saved while other labels remain unmapped and denied; empty translation choices are omitted from the saved adapter. A pending label cannot obtain access through a completed label's rules.

Use Prepare mapping drafts automatically to load up to four catalog pages, propose resource/field rules for empty detected-label drafts, and save them in one action. Existing edited resources and execution-role names are preserved. Identity and credential-named resources are excluded; field suggestions exclude credential names and are bounded to 32 fields. An unambiguous single-column foreign key to the mapped user ID can suggest a user row scope, but creator/updater/audit references are excluded and no relationship is considered permission proof. Other scopes remain pending. Suggestions are always unreviewed, and role names never imply all-row access. Up to 25 resource suggestions per empty label and 100 rules overall are generated. Bulk scope and review controls are explicit administrator decisions; they do not run automatically. Applying database changes still requires review of the SQL artifact.

The draft editor loads a separate administrator-only resource catalog through the shared connection. It lists readable base tables and columns in pages of 25, including business tables with no email, role, or permission columns. This catalog does not require user-email permission confirmation, does not read table rows, and does not grant access. Credential/token/secret column names are omitted. Use Load more resources for additional pages; the permission-evidence list is not the complete resource catalog.

Role discovery now seeds a configurable draft for each detected label, without assigning read access from its name. Saved drafts are restored on rediscovery. Select discovered resources, explicit readable fields (up to 32 per resource), and either all rows in that reviewed resource or rows whose reviewed user-ID column equals the matched database user ID. A user-ID scope requires that column to be among the selected fields. Creator/updater links are not automatically treated as ownership rules. Unknown labels, unresolved scope, and empty resource selections remain without access. Membership joins and JSON field-level native rules are not implemented by this initial editor and must not be represented as equivalent to its simple scopes.

Drafts are saved separately from the active authorization adapter and do not authorize queries. The SQL preview endpoint requires reviewed rules, new non-owning execution-role names, readable existing base tables, and no PUBLIC SELECT grants that could override field restrictions. It rejects credential/token/secret fields and does not execute SQL. Generated SQL creates restricted NOLOGIN roles, explicit column grants, and restrictive SELECT policies; an accompanying permissive policy makes the selected rows readable while the restrictive rule continues to constrain existing broader policies. Role names are generated from detected labels and remain editable; existing roles are not overwritten. Applying SQL enables RLS on selected tables and must be reviewed for native-application compatibility before execution.

After generating the preview, review the SQL and acknowledge its effect on your native application. Select **Apply reviewed mapping and check my access** to install it through the shared URI. This separate administrator-only action revalidates metadata under table locks, verifies a 15-minute signature bound to the exact drafts, SQL, adapter and administrator, and applies all new roles/grants/policies in one PostgreSQL transaction. The URI login needs database setup privileges; read access alone is insufficient. Statement and lock timeouts bound installation, and failure before commit rolls back all installation changes. A lost commit acknowledgement reports an unknown outcome and requires role discovery before retrying.

After installation the server automatically saves label translations and clears profile evidence. An already entered, matched email is retained only after resolving the same active database user under the new restricted role; installation never skips initial email confirmation. The UI refreshes the adapter, detected execution roles and readiness, and brings feedback into view. Queries still run under the restricted user role. Enabling the source, discovery, saving drafts and generating previews never install permissions by themselves. Labels and business resources remain configurable; label names do not imply access.

Alternatively, a DBA can apply the reviewed SQL externally. Rediscover roles, select their label translations and save the adapter, then verify the user's email. If PostgreSQL installs the rules but the application's settings cannot be saved, the response reports the installation and instructs you to save the detected translations; it does not repeat or overwrite existing roles. Database installation and the application's SQLite settings are separate commits. Approved queries and profile tests remain required. Integration tests exercise in-app installation, retained email confirmation, denied pending labels, row isolation, unselected-field rejection and rollback after a DDL failure in a disposable fixture.

User recognition and search authorization are separate. After the entered database email matches the verified Microsoft email, a bounded lookup identifies exactly one active user and its application role label. If the label lacks an execution-role translation, the UI reports `matched_permissions_required` with the matched user and label. This recognition is retained for the signed-in tenant/object and adapter fingerprint, rechecked against the current active user on refresh, and never satisfies the database-search confirmation gate. It does not enable business metadata access, profile tests, or searches. Those require successful permission enforcement. Role labels alone cannot reproduce permissions implemented by a native application's code.

Permission structure discovery is available in the role-mapping section. It inspects readable relation/column metadata for authorization-related signals and foreign keys to the selected user relation, reports foreign-key relationships around those candidates, and lists readable row-policy definitions with their target roles and RLS enabled/forced status. Candidate selection uses structural and column-name signals rather than specific application table names. A candidate is not proof of authorization semantics. This inventory reads catalog metadata, not business or permission-table rows; the separate role-value query reads bounded distinct role labels. Discovery limits tables, columns, links, policies, and response size and explicitly flags incomplete results. Permissions enforced solely by external application code cannot be inferred from this inventory. No roles, policies, or grants are created by discovery, and execution-role and email confirmation checks remain required.

Role translation is part of the authorization mapping. After selecting a user relation, role discovery reads up to 100 distinct values from its role column and lists eligible PostgreSQL execution roles with existing row-policy counts. It excludes superuser, BYPASSRLS, connection-account, and table-owning roles. Exact existing role-name matches can prefill; unmatched application labels require an explicit reviewed selection. Policy counts do not establish that database policies reproduce an application's authorization model. No roles, grants, or policies are created automatically. If translations are saved, an unknown application role is denied without fallback. In application-auth mode, `request.jwt.claims.role` retains the application role and `request.jwt.claims.database_role` contains the execution role, alongside the matched user and tenant claims. Both user identity and role switching are validated on every request. Saving translations invalidates existing email confirmation and profile evidence through the adapter fingerprint.

In shared-adapter mode, each user enters their database account email under Database access. The server compares it to their verified Microsoft directory email, resolves exactly one active database user, and validates the execution role before saving confirmation for that tenant and Microsoft object ID. No database password is requested. Confirmation is required for database searches, metadata access, and profile tests; adapter changes invalidate it. Runtime queries still recheck the account and permissions. Administrator adapter diagnostics can run before user confirmation. The mapped execution role must be separate from the connection account, non-superuser, non-BYPASSRLS, and must not own tables. Shared privileged credentials are limited to identity lookup; user searches begin only after dropping to the restricted user identity. Legacy direct-user logins still reject superuser and BYPASSRLS accounts.
