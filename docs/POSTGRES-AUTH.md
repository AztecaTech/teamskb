# PostgreSQL authorization adapters

## Automatic permitted fields and row access

Application-permission mode can select each matched user's permitted resources,
fields and row scope automatically from the native application's permission
service. Configure `POSTGRES_PERMISSION_SOURCE_URL` and
`POSTGRES_PERMISSION_SOURCE_TOKEN` (or `POSTGRES_PERMISSION_SOURCE_TOKEN_FILE`)
once in the deployment. The endpoint must implement the contract below using the
native application's actual authorization decisions. IQ Knowledge includes the
client and enforcement; it does not install an endpoint in the owning application
or infer permissions implemented by arbitrary backend code from a database URI.

After the identity mapping is saved, the permission editor loads this source
automatically. The allowed fields and scope are selected without resource, field,
scope or review-checkbox input. One permitted resource is also selected for the
first search-profile draft; with several resources the administrator chooses
which one to make searchable first. The editor shows a read-only permission
summary and **Refresh my permissions**. Saving the mapping and initial email
confirmation remain explicit; an already confirmed email is rechecked after a
save. Profile preview, saving and two-user verification remain required.

The source is configured only on the server. HTTPS certificate verification,
server bearer authentication, a five-second timeout, no followed redirects and
bounded strict JSON replies apply. The token is forwarded only to the configured
endpoint and is never sent to the browser or model. The Dokploy single-container
launcher passes these settings only to the Go application.

IQ Knowledge sends a `POST` to the configured endpoint:

```json
{
  "operation": "read",
  "subject": {
    "userId": "7",
    "email": "person@example.com",
    "tenantId": "verified-microsoft-tenant",
    "objectId": "verified-microsoft-object",
    "label": "native-label"
  }
}
```

The subject comes from the verified Microsoft identity and the unique active
database account. The service must resolve that account with its current native
permissions, including native denials or additional account restrictions. It must
return exactly the same subject and a revision that changes with its policy:

```json
{
  "subject": {
    "userId": "7",
    "email": "person@example.com",
    "tenantId": "verified-microsoft-tenant",
    "objectId": "verified-microsoft-object",
    "label": "native-label"
  },
  "allowed": true,
  "revision": "native-policy-revision-1",
  "resources": [
    {
      "schema": "custom",
      "relation": "records",
      "fields": ["record_key", "caption", "content"],
      "scope": { "kind": "user", "column": "owner_key" }
    }
  ]
}
```

This is a protocol example, not a default permission grant. Resource/field names,
labels and scopes are supplied by the native permission service. The scope kinds
are the same supported `all`, `user`, `email`, `claim` and `membership` rules
described below. A claim rule also supplies `claimColumns`, mapping the attribute
name to an existing scalar column in the identity relation. Attribute values are
read from the matched database user; they are not accepted from the remote reply.
No SQL, business rows or search question is sent to the permission service.

Every authorized database operation re-resolves the native decision and validates
its fields, resource types and scope against PostgreSQL. Its source fingerprint,
revision, full rules and attribute mapping join the account revision in profile
evidence, so changes invalidate old two-user tests. A denial, unavailable source,
identity mismatch, unsupported rule or invalid metadata blocks access; saved
manual rules cannot override a configured source. The preview API returns only
the user's allowed fields/scopes and claim column mappings, never claim values
or business rows. Saving with a configured native source retains the identity
mapping, but does not persist its per-user rules or claims as manual grants;
disconnecting that source therefore cannot turn the snapshot into fallback access.
Without a configured source, the editor explains this missing
connection and retains the existing reviewed manual mapping flow. No external
database tables, roles, grants, policies or records are changed.

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

For an externally published PostgreSQL endpoint without TLS, explicitly set `POSTGRES_CONNECTION_MODE=external_plaintext` and use `POSTGRES_DSN=postgresql://USER:PASSWORD@EXTERNAL_HOST:PUBLISHED_PORT/DATABASE?sslmode=disable`. This accepts external hostnames and public IP addresses using the configured published port. Database credentials and traffic are sent without encryption. It does not automatically downgrade a TLS connection. The selected authorization adapter and email checks apply in all three transport modes.

Mapping discovery uses metadata column names and types, rather than a fixed table name. A unique candidate with recognizable email, user ID, role, and boolean account-status columns prefills an editable column mapping. Common aliases such as `id`, `role`, and `enabled` are supported; multiple matching candidates require administrator selection. Business tables with only an email column do not qualify automatically. Existing mapping drafts are preserved.

An explicit column mapping can use the source relation directly instead of creating the canonical six-column authorization view. If no tenant column exists, saving binds the mapping to the signed-in administrator's Microsoft tenant on the server; other tenants are rejected. If no permission-version column exists, a hash of the mapped user record provides change detection for profile evidence. In database-policy modes, the role value must resolve to an allowed PostgreSQL execution role. Application-rules mode matches the label to reviewed resource permissions instead. Labels alone never grant access. Custom column names remain editable. A review note or ticket is optional: when omitted, the server records the signed-in administrator and UTC save time automatically.

The shared connection in Dokploy supplies database credentials, not a user's
permissions. IQ Knowledge resolves the signed-in Teams member's directory email,
looks up one database identity, and enforces the selected authorization adapter inside
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
   Administrator-only mapping discovery inspects catalog metadata using the injected URI, including when that URI uses an administrator login. It scans likely email-bearing relations in pages of 25 and reports detected fields without granting search access. In database-policy modes, a superuser connection changes its session authorization and execution role to the mapped restricted role. Application-rules mode keeps the service connection and permits only generated profile queries with enforced field projections and row predicates.

   Prefer a restricted service login without superuser or BYPASSRLS. In database-policy modes, use NOINHERIT, grant
   direct SELECT access only to the authorization view, and grant permission to
   SET ROLE to the restricted execution roles. Application-rules mode instead needs SELECT
   on the identity, membership and reviewed business columns.
3. Select an existing authorization relation or use an explicit column mapping.
   Users and permissions remain authoritative in their existing system. The app
   does not create or alter PostgreSQL tables, columns, users, roles, grants, row
   policies or business records. Mapping configuration is stored in the app.
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

Use an existing authorization view with these columns, or configure the editable
column mapping against an existing user relation. The app does not create views
or add missing columns. Review translations to existing execution roles.

| Column | Required meaning |
| --- | --- |
| `tenant_id` | Entra tenant UUID as text, or UUID castable to text |
| `email` | Organization email matching the member's directory `mail` |
| `user_id` | Stable application user ID, castable to text |
| `database_role` | Restricted PostgreSQL execution role in database-policy modes; application label in application-rules mode |
| `active` | Boolean indicating whether the user can access this integration |
| `permission_version` | Nonempty revision which changes when this user's effective permissions change |

The lookup is parameterized by authenticated tenant and normalized email. It must
produce exactly one row, including inactive rows; absent, inactive, NULL, duplicate,
unsafe-role, and cross-tenant matches fail closed. A missing or unreadable view also
denies access. In database-policy modes the selected execution role must differ from the service login and be granted
to it. Both LOGIN and NOLOGIN execution roles are supported. Application-rules mode does not translate labels to SQL roles.

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

These two database-policy modes also provide transaction-local settings `iqkb.user_id`, `iqkb.email`,
`iqkb.tenant_id`, and `iqkb.teams_object_id`. Example policy expression for your
own schema:

```sql
tenant_id::text = current_setting('iqkb.tenant_id', true)
AND owner_user_id::text = current_setting('iqkb.user_id', true)
```

Existing policies or approved read-only views/queries must enforce the actual
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
fixture. It tests database-policy and application-rule modes, user isolation, discovery, profiles,
read-only transactions, state cleanup, missing/inactive/duplicate users,
cross-tenant lookup, unsafe roles, account/role revocation, API setup, two-user
evidence, query retrieval, permission revision changes, and evidence invalidation.
It does not connect to the production database or verify live Teams consent.

See the official [Graph user endpoint](https://learn.microsoft.com/en-us/graph/api/user-get?view=graph-rest-1.0)
and [PostgreSQL SET ROLE documentation](https://www.postgresql.org/docs/current/sql-set-role.html).

## Read-only PostgreSQL and application-side mapping

All external PostgreSQL operations use read-only transactions, including metadata discovery and email recognition through privileged shared URI credentials. The connector contains no permission installation or DDL generator. It never creates or changes external tables, columns, views, users, roles, grants, policies or business records. Switching to an existing execution role and setting user context are transaction-local and are rolled back when the connection closes. Adapter settings, approved SELECT queries and profile evidence are saved in IQ Knowledge's own SQLite store.

The former permission-draft editor and SQL installation controls have been removed. Former draft/preview/apply routes return HTTP 410 `postgres_read_only` before opening a database connection, including requests from cached clients. Existing local drafts are left unused; they never become permission grants. The app does not undo any externally applied changes, since doing so would also change the database.

Selecting Enable PostgreSQL search persists the source choice and runs an administrator readiness check. Selected — setup incomplete remains until identity, existing permission enforcement, a nonempty query catalog and required profile tests pass. Readiness feedback appears beside the toggle and points to the next required setup section. Ready for activation refers to this source's checks; workspace/provider activation remains separate.

A recognized email with unresolved permissions reports `database_permission_mapping_required`, rather than asking the user to repeat email confirmation. In database-policy modes, application labels map only to existing, eligible restricted PostgreSQL execution roles. Application-rules mode instead uses reviewed resource, field and row mappings saved in the app. A completed label mapping can be saved while other labels remain unmapped and denied. Saving the identity mapping itself remains possible before role translation so the user can confirm an email and see the matched application label.

If permissions are implemented only in the native application's code, database metadata cannot infer or enforce them. The application-rules adapter can reproduce reviewed scalar resource and row rules. Rules involving custom API logic, JSON visibility or computed permissions need a dedicated provider; the automatic native permission source imports supported declarative rules. Native API data retrieval and arbitrary backend calculations remain unsupported. The app explicitly reports the missing mapping and keeps that label's database search unavailable; it never grants access merely from labels such as admin or user or falls back to unrestricted service-account searches. No business tables or role labels are hardcoded.

The administrator-only resource catalog still lists readable base tables and columns in pages of 25. It does not require user-email permission confirmation, reads metadata rather than sample rows, excludes credential/token/secret fields and never authorizes search by itself. Query previews for business profiles remain fixed SELECT statements and do not create database resources.

Tests cover rejection of obsolete installation routes without a database connection, PostgreSQL's rejection of table/column/role/grant/policy and record changes even under privileged URI metadata credentials, normal read-only discovery, identity recognition, scoped searches and per-user isolation in a disposable fixture. They do not modify or validate the production database.

## User email confirmation

User recognition and search authorization are separate. After the entered database email matches the verified Microsoft email, a bounded lookup identifies exactly one active user and its application role label. If the label lacks an execution-role translation or reviewed application rules, the UI reports `matched_permissions_required` with the matched user and label. This recognition is retained for the signed-in tenant/object and adapter fingerprint, rechecked against the current active user on refresh, and never satisfies the database-search confirmation gate. It does not enable business metadata access, profile tests, or searches. Those require successful permission enforcement. Role labels alone cannot reproduce permissions implemented by a native application's code.

Permission structure discovery is available in the role-mapping section. It inspects readable relation/column metadata for authorization-related signals and foreign keys to the selected user relation, reports foreign-key relationships around those candidates, and lists readable row-policy definitions with their target roles and RLS enabled/forced status. Candidate selection uses structural and column-name signals rather than specific application table names. A candidate is not proof of authorization semantics. This inventory reads catalog metadata, not business or permission-table rows; the separate role-value query reads bounded distinct role labels. Discovery limits tables, columns, links, policies, and response size and explicitly flags incomplete results. Permissions enforced solely by external application code cannot be inferred from this inventory. No roles, policies, or grants are created by discovery, and execution-role and email confirmation checks remain required.

Role translation is part of the authorization mapping. After selecting a user relation, role discovery reads up to 100 distinct values from its role column and lists eligible PostgreSQL execution roles with existing row-policy counts. It excludes superuser, BYPASSRLS, connection-account, and table-owning roles. Exact existing role-name matches can prefill; unmatched application labels require an explicit reviewed selection. Policy counts do not establish that database policies reproduce an application's authorization model. No roles, grants, or policies are created automatically. If translations are saved, an unknown application role is denied without fallback. In application-auth mode, `request.jwt.claims.role` retains the application role and `request.jwt.claims.database_role` contains the execution role, alongside the matched user and tenant claims. Both user identity and role switching are validated on every request. Saving translations invalidates existing email confirmation and profile evidence through the adapter fingerprint.

In shared-adapter mode, each user enters their database account email under Database access. The server compares it to their verified Microsoft directory email, resolves exactly one active database user, and validates the selected permission adapter before saving confirmation for that tenant and Microsoft object ID. No database password is requested. Confirmation is required for database searches, metadata access, and profile tests; adapter changes invalidate it. Runtime queries still recheck the account and permissions. Administrator adapter diagnostics can run before user confirmation. In database-policy modes, the mapped execution role must be separate from the connection account, non-superuser, non-BYPASSRLS, and must not own tables. In database-policy modes, privileged credentials are used for identity lookup and then dropped to a restricted execution role. In application-rules mode, shared credentials execute only server-compiled profile queries with explicit application authorization. Legacy direct-user logins still reject superuser and BYPASSRLS accounts.


## Application permissions without PostgreSQL changes

Select **Application permissions enforced by IQ Knowledge (read-only)** when the
native application's labels do not correspond to existing PostgreSQL roles. Detect
the identity relation and its labels, then use the resource metadata catalog to
configure permissions for each label. Metadata identifies existing columns and
relationships; it cannot establish the meaning of native backend authorization.
An administrator must review each resource against the existing application's
read permissions. Unreviewed, unmapped or unsupported rules deny retrieval. There
are no special privileges associated with a label named admin, user or manager.

Each reviewed resource chooses readable scalar fields and one row scope:

| Scope | Enforced condition |
| --- | --- |
| All rows | Explicitly reviewed access to every row in this resource |
| User ID | Existing resource column equals the matched stable database user ID |
| Email | Existing resource column equals the verified organizational email |
| User attribute | Resource column equals a configured scalar attribute read from the matched user record |
| Team/group membership | An existing membership table links the matched user ID to the resource group, with optional active and Microsoft-tenant conditions |

Attribute values and labels come from the unique active database account. Browser
requests and model output cannot override them. Membership predicates query the
existing table on every read, so revocation takes effect on the next query. If
memberships use a different native key, tenant values differ from Microsoft tenant
IDs, or authorization involves an OR/deny precedence not supported here, a custom
provider is required; do not approximate the native rule with a broader scope.

This mode supports ordinary and partitioned base tables with builtin scalar
columns. JSON, arrays, custom types, views and computed backend permissions remain
unavailable. Only generated business profiles are executable: fixed SQL catalog
queries are rejected. Both related-list parent resolution and child retrieval are
scoped before matching, ranking, ambiguity checks and limits. Key/foreign-key
metadata is returned only for reviewed resources and fields. Metadata pages are
bounded and paginated. The model receives the approved profile descriptions and
parameters; it never receives SQL, identity attributes or unfiltered business rows.

The URI is still the service connection. PostgreSQL is not impersonating an
application label in this mode. IQ Knowledge applies reviewed field projections
and SQL row predicates to each generated profile, in a read-only transaction with
a locked builtin search path and statement limits. Prefer a least-privileged
service login with SELECT access to the identity, membership and reviewed business
columns. No PostgreSQL tables, roles, policies, grants or records are changed.
Profile tests from two different database users remain required for activation.
Adapter changes invalidate email confirmations and previous profile evidence.

### Adapting another application

Trace each native read path from authenticated identity to its permission decision:
label and user attributes, allowed resource and fields, row conditions, team
membership, explicit denials, and derived data. Record supported rules using the
configuration above. For rules enforced through native API services or custom
visibility calculations, implement a reviewed provider behind
`internal/authorization.Adapter` rather than putting application-specific table
names or label meanings in the search engine. The registry currently provides
`database_policy` and `application_rules`; it rejects unknown providers. Registration
is server code, not browser- or model-supplied executable configuration.

Validate equivalent allowed and denied outcomes for at least two distinct users
before activation. A passing configuration test proves the configured isolation;
it does not prove parity with arbitrary native application code. Live source
permissions must be traced and reviewed separately. The disposable fixture covers
user/email/attribute scopes, team revocation and tenant restrictions, hidden-field
and structured-value rejection, parent/child isolation, email confirmation,
two-user evidence, catalog restrictions and model-prompt isolation.


## Completing application-permission setup

The matched database label is shown first in the resource editor. Identity mapping
can be saved as a draft before any resource permissions exist. Readiness identifies
whether the current label has no resource rule or an unfinished review, and links
to that resource editor. Saving an identity-only draft does not report a failed
connection or enable searches.

Choose one table, its readable fields (including an existing single-column unique
key and at least one text display/search field), and the row access already allowed
by the native application. New rules open immediately. Review is unavailable until
fields, scope columns and any attribute/membership mapping are complete. Resource
metadata loads up to four pages automatically, with filtering and further paging
for larger catalogs. Permissions are never inferred from the label's name.

After **Save permissions and continue**, an email previously confirmed for the same
signed-in account is rechecked automatically against Microsoft and the current
database mapping. An unconfirmed account still needs its first explicit email
verification. Existing server confirmation and adapter-fingerprint checks remain
in force. Accessible metadata supplies a search-profile draft using an actual key,
text columns and supported output types. Missing/ambiguous keys or missing text
fields produce instructions rather than invented mappings. Saved profile IDs are
preserved; new drafts use an unused ID.

Review the draft and select **Preview search profile**, then **Save versioned
profile**. A review note is optional; the server records the administrator and
review time when it is blank. Saving runs the current user's access test and shows
the remaining readiness step. The existing two-distinct-user requirement remains:
a second database user verifies their email and tests the saved profile under
Database access. Other labels need their own reviewed resource rules.

`frontend/test/postgres-setup.browser.mjs` exercises this flow with an isolated
Teams/API fixture and a locally installed Playwright module/browser. Run it with
`node test/postgres-setup.browser.mjs [PLAYWRIGHT_MODULE_PATH] [BROWSER_EXECUTABLE]`
from `frontend`. It checks paginated resource selection, complete review gating,
email recheck, profile prefill, optional review notes, the current user's test and
second-user guidance. Add `--unconfirmed` to check first-time email confirmation, or `--automatic` to check native field/scope selection without manual inputs and revocation without manual fallback. The PostgreSQL integration fixture separately checks the
real server and database enforcement. Neither test is live Teams/Dokploy validation.
