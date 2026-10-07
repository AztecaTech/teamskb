import React, { useEffect, useState } from 'react';
import { createRoot } from 'react-dom/client';
import { app, authentication } from '@microsoft/teams-js';
import { decodeRelationChoice, encodeRelationChoice } from './relation-choice.mjs';
import { authorizationPrefill, candidateColumnMapping, queryPrefill } from './mapping-prefill.mjs';
import './style.css';
import PermissionRuleEditor from './PermissionRuleEditor';

type Session = { tenantId: string; objectId: string; role: 'Admin' | 'User'; active: boolean };
type SetupStatus = { active: boolean; wizardReady: boolean };
type ProviderStatus = { configured: boolean; apiKeyConfigured?: boolean; provider?: string; model?: string; baseUrl?: string };
type SourceStatus = { id: string; kind: string; boundary: string; enabled: boolean; siteUrls?: string[] };
type PostgresIdentity = { objectId: string; verifiedEmail: string; databaseIdentity: string; reviewedBy: string; reviewedAt: string };
type PostgresDiscovery = { relations: Array<{ schema: string; name: string; kind: string; supported: boolean; reason?: string; comment?: string }>; columns: Array<{ schema: string; relation: string; name: string; dataType: string; nullable: boolean; comment?: string }>; keys: Array<{ schema: string; relation: string; kind: string; columns: string[] }>; relationships: Array<{ name: string; sourceSchema: string; sourceRelation: string; sourceColumns: string[]; targetSchema: string; targetRelation: string; targetColumns: string[] }>; nextSchema?: string; nextName?: string };
type PostgresQuery = { id: string; version: number; description: string; sql: string; parameters: Array<{ name: string; type: string }>; outputColumns: string[]; approvalRecord: string };
type PostgresCredentialStatus = { available: boolean; mapped: boolean; configured: boolean; verifiedEmail: string; mode?: string; status?: string; userId?: string; databaseRole?: string; applicationRole?: string; emailStatus?: string };
type PostgresReadiness = { enabled: boolean; ready: boolean; state: string; message: string; next?: string; queries: number };
type PostgresAuthAdapter = { mode: string; schema: string; relation: string; approvalRecord: string; columns?: { email: string; userId: string; role: string; active: string; tenantId?: string; permissionVersion?: string }; tenantScope?: string; roleMappings?: Record<string, string> };
type AuthorizationCandidate = { schema: string; relation: string; ready: boolean; missingColumns: string[]; columns?: { name: string; dataType: string }[] };
type AuthorizationDiscovery = { candidates: AuthorizationCandidate[]; nextSchema?: string; nextName?: string };
type PostgresProfileSummary = { id: string; version: number; label: string; capability: string };
type PostgresProfileTest = { profileId: string; version: number; objectId: string; databaseIdentity: string; testedAt: string; status: string; category: string };
type PostgresProfilePreview = { version: number; sql: string; parameters: Array<{ name: string; type: string }>; outputColumns: string[]; parentSQL?: string; parentParameters?: Array<{ name: string; type: string }>; approvalRecord: string; permissionExplanation: string };
type SearchDetails = { scope: string; database: string; warning?: string; sources?: Array<{ source: string; status: string; results: number }> };
type AskResult = { answer?: string; sources: Array<{ id: string; name: string; url: string; kind?: string }>; search?: SearchDetails; clarification?: { kind: string; question: string; candidates: Array<{ id: string; displayName: string }> } };

function directoryEmailHelp(status?: string) {
  if (status === 'directory_mail_missing') return 'Your Microsoft directory profile has no usable email address. Ask your administrator to populate its mail field; a manually entered database email cannot replace it.';
  if (status === 'directory_member_required') return 'The current database integration requires a member account in your organization; guest accounts are not supported.';
  if (status === 'directory_identity_mismatch') return 'The directory profile did not match your Teams account. Sign in again; access remains blocked until the identities match.';
  if (status === 'directory_unavailable') return 'Microsoft directory lookup failed. Check the deployment’s Graph connectivity and retry.';
  return 'Check delegated Microsoft Graph User.Read consent on the Entra app identified by APP_CLIENT_ID, verify its client secret, then reopen the Teams app and refresh database access.';
}

function App() {
  const [message, setMessage] = useState('Connecting to Microsoft Teams…');
  const [session, setSession] = useState<Session | null>(null);
  const [setup, setSetup] = useState<SetupStatus | null>(null);
  const [setupStep, setSetupStep] = useState(0);
  const [failedSource, setFailedSource] = useState('');
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [provider, setProvider] = useState('openai');
  const [model, setModel] = useState('');
  const [baseUrl, setBaseUrl] = useState('');
  const [providerKeyConfigured, setProviderKeyConfigured] = useState(false);
  const [sourceEnabled, setSourceEnabled] = useState(false);
  const [sharePointEnabled, setSharePointEnabled] = useState(false);
  const [sharePointSiteUrls, setSharePointSiteUrls] = useState('');
  const [outlookEnabled, setOutlookEnabled] = useState(false);
  const [teamsChatsEnabled, setTeamsChatsEnabled] = useState(false);
  const [teamsChannelsEnabled, setTeamsChannelsEnabled] = useState(false);
  const [postgresConfigured, setPostgresConfigured] = useState(false);
  const [sharedDatabaseCredentials, setSharedDatabaseCredentials] = useState(false);
  const [postgresAuth, setPostgresAuth] = useState<PostgresAuthAdapter>({ mode: 'postgres_role', schema: '', relation: '', approvalRecord: '' });
  const [postgresAuthSaved, setPostgresAuthSaved] = useState(false);
  const [mappingMessage, setMappingMessage] = useState('');
  const [roleDiscovery, setRoleDiscovery] = useState<{ applicationRoles: string[]; executionRoles: { name: string; policies: number }[]; truncated: boolean; permissions?: { relations: { schema: string; relation: string; columns: string[]; rlsEnabled: boolean; rlsForced: boolean; evidence: string }[]; relationships: { name: string; sourceSchema: string; sourceRelation: string; sourceColumns: string[]; targetSchema: string; targetRelation: string; targetColumns: string[] }[]; policies: { schema: string; relation: string; name: string; roles: string[]; using: string; check: string; rlsEnabled: boolean }[]; truncated: boolean } } | null>(null);
  const [roleMappingMessage, setRoleMappingMessage] = useState('');
  const [authorizationDiscovery, setAuthorizationDiscovery] = useState<AuthorizationDiscovery | null>(null);
  const [postgresEnabled, setPostgresEnabled] = useState(false);
  const [postgresReadiness, setPostgresReadiness] = useState<PostgresReadiness | null>(null);
  const [postgresSourceMessage, setPostgresSourceMessage] = useState('');
  const [postgresObjectId, setPostgresObjectId] = useState('');
  const [postgresVerifiedEmail, setPostgresVerifiedEmail] = useState('');
  const [postgresDatabaseIdentity, setPostgresDatabaseIdentity] = useState('');
  const [postgresIdentities, setPostgresIdentities] = useState<PostgresIdentity[]>([]);
  const [postgresQueries, setPostgresQueries] = useState<PostgresQuery[]>([]);
  const [postgresDiscovery, setPostgresDiscovery] = useState<PostgresDiscovery | null>(null);
  const [postgresProfiles, setPostgresProfiles] = useState<PostgresProfileSummary[]>([]);
  const [postgresProfileTests, setPostgresProfileTests] = useState<PostgresProfileTest[]>([]);
  const [profileId, setProfileId] = useState('');
  const [profileLabel, setProfileLabel] = useState('');
  const [profileSynonyms, setProfileSynonyms] = useState('');
  const [profileCapability, setProfileCapability] = useState('entity_lookup');
  const [profileSearchStrategy, setProfileSearchStrategy] = useState('keyword');
  const [profileLanguage, setProfileLanguage] = useState('english');
  const [profileRelation, setProfileRelation] = useState('');
  const [profileKey, setProfileKey] = useState('');
  const [profileDisplay, setProfileDisplay] = useState('');
  const [profileSearchColumns, setProfileSearchColumns] = useState('');
  const [profileForeignKey, setProfileForeignKey] = useState('');
  const [profileParentProfileId, setProfileParentProfileId] = useState('');
  const [profileFiltersJSON, setProfileFiltersJSON] = useState('[]');
  const [profileReturnTypes, setProfileReturnTypes] = useState<Record<string, string>>({});
  const [profileSourceURL, setProfileSourceURL] = useState('');
  const [profileApproval, setProfileApproval] = useState('');
  const [profilePreview, setProfilePreview] = useState<PostgresProfilePreview | null>(null);
  const [profilePreviewInput, setProfilePreviewInput] = useState('');
  const [postgresToolId, setPostgresToolId] = useState('');
  const [postgresToolDescription, setPostgresToolDescription] = useState('');
  const [postgresToolSQL, setPostgresToolSQL] = useState('');
  const [postgresToolApproval, setPostgresToolApproval] = useState('');
  const [postgresCredentialStatus, setPostgresCredentialStatus] = useState<PostgresCredentialStatus | null>(null);
  const [postgresPassword, setPostgresPassword] = useState('');
  const [databaseEmail, setDatabaseEmail] = useState('');
  const [postgresCredentialMessage, setPostgresCredentialMessage] = useState('');
  const [adminMessage, setAdminMessage] = useState('');
  const [adminBusy, setAdminBusy] = useState(false);
  const [bootstrapSecret, setBootstrapSecret] = useState('');
  const [question, setQuestion] = useState('');
  const [searchLocation, setSearchLocation] = useState('all');
  const [searchDetails, setSearchDetails] = useState<SearchDetails | null>(null);
  const [answer, setAnswer] = useState<AskResult | null>(null);
  const [askMessage, setAskMessage] = useState('');
  const [asking, setAsking] = useState(false);

  async function api(path: string, init: RequestInit = {}) {
    const token = await authentication.getAuthToken();
    const headers = new Headers(init.headers);
    headers.set('Authorization', `Bearer ${token}`);
    if (init.body && !headers.has('Content-Type')) headers.set('Content-Type', 'application/json');
    return fetch(path, { ...init, headers, cache: 'no-store' });
  }

  useEffect(() => {
    let disposed = false;
    async function start() {
      let signedIn = false;
      try {
        await app.initialize();
        const response = await api('/api/session');
        if (!response.ok) throw new Error('Sign-in was not accepted.');
        const current = await response.json() as Session;
        if (disposed) return;
        setSession(current);
        signedIn = true;
        if (current.active) setSetup({ active: true, wizardReady: true });
        setMessage('Signed in securely with your organization account.');
        const credentialResponse = await api('/api/postgres/credentials');
        if (credentialResponse.ok) setPostgresCredentialStatus(await credentialResponse.json() as PostgresCredentialStatus);
        const profileResponse = await api('/api/postgres/profiles');
        if (profileResponse.ok) setPostgresProfiles((await profileResponse.json() as { profiles: PostgresProfileSummary[] }).profiles);
        if (current.role !== 'Admin') return;

        const [setupResponse, providerResponse, sourcesResponse, postgresResponse, identityResponse, queryResponse] = await Promise.all([
          api('/api/setup/status'), api('/api/admin/provider'), api('/api/admin/sources'),
          api('/api/admin/postgres/status'), api('/api/admin/postgres/identities'), api('/api/admin/postgres/queries'),
        ]);
        if (disposed) return;
        if (!setupResponse.ok || !providerResponse.ok || !sourcesResponse.ok) throw new Error('Workspace settings could not be loaded.');
        if (setupResponse.ok) {
          const status = await setupResponse.json() as SetupStatus;
          setSetup(status);
          if (!status.active && status.wizardReady) setSetupStep(2);
        }
        if (providerResponse.ok) {
          const saved = await providerResponse.json() as ProviderStatus;
          setProviderKeyConfigured(saved.apiKeyConfigured ?? false);
          if (saved.provider) setProvider(saved.provider);
          if (saved.model) setModel(saved.model);
          if (saved.baseUrl) setBaseUrl(saved.baseUrl);
        }
        if (sourcesResponse.ok) {
          const data = await sourcesResponse.json() as { sources: SourceStatus[] };
          setSourceEnabled(data.sources.some((source) => source.id === 'user-onedrive' && source.enabled));
          const sharePoint = data.sources.find((source) => source.id === 'user-sharepoint');
          setSharePointEnabled(sharePoint?.enabled ?? false);
          setSharePointSiteUrls(sharePoint?.siteUrls?.join('\n') ?? '');
          setOutlookEnabled(data.sources.find((source) => source.id === 'user-outlook')?.enabled ?? false);
          setTeamsChatsEnabled(data.sources.find((source) => source.id === 'user-teams-chats')?.enabled ?? false);
          setTeamsChannelsEnabled(data.sources.find((source) => source.id === 'user-teams-channels')?.enabled ?? false);
          setPostgresEnabled(data.sources.find((source) => source.id === 'user-postgres')?.enabled ?? false);
        }
        if (postgresResponse.ok) setPostgresConfigured((await postgresResponse.json() as { configured: boolean }).configured);
        const authResponse = await api('/api/admin/postgres/auth');
        if (authResponse.ok) {
          const auth = await authResponse.json() as { adapter: PostgresAuthAdapter | null; sharedCredentialsConfigured: boolean };
          setSharedDatabaseCredentials(auth.sharedCredentialsConfigured);
          if (auth.adapter) { setPostgresAuth(auth.adapter); setPostgresAuthSaved(true); }
        }
        if (identityResponse.ok) setPostgresIdentities((await identityResponse.json() as { identities: PostgresIdentity[] }).identities);
        if (queryResponse.ok) setPostgresQueries((await queryResponse.json() as { queries: PostgresQuery[] }).queries);
        const profileTestsResponse = await api('/api/admin/postgres/profile-tests');
        if (profileTestsResponse.ok) setPostgresProfileTests((await profileTestsResponse.json() as { tests: PostgresProfileTest[] }).tests);
        if (current.role === 'Admin') { try { await refreshPostgresReadiness(); } catch { setPostgresSourceMessage('PostgreSQL readiness could not be loaded. Use Check readiness to retry.'); } }
      } catch {
        if (!disposed) setMessage(signedIn ? 'Your account is connected, but some workspace settings could not load. Reload the app to retry; contact your administrator if this continues.' : 'Open this app inside Microsoft Teams and confirm your organization has configured single sign-on.');
      }
    }
    void start();
    return () => { disposed = true; };
  }, []);

  async function saveProvider(event: React.FormEvent) {
    event.preventDefault();
    setAdminBusy(true);
    setAdminMessage('');
    try {
      const response = await api('/api/admin/provider', {
        method: 'PUT', body: JSON.stringify({ provider, model, ...(provider === 'openai_compatible' ? { baseUrl } : {}) }),
      });
      if (!response.ok) throw new Error(response.status === 400 ? 'Check the provider, model, and URL.' : 'Provider could not be saved.');
      setSetup((current) => current ? { ...current, wizardReady: false } : current);
      setAdminMessage('Settings saved. Checking the provider…');
      const checkResponse = await api('/api/admin/provider/check', { method: 'POST' });
      if (!checkResponse.ok) throw new Error('Settings saved, but the provider could not connect. Check the model name, endpoint, and operator-managed API key, then retry.');
      const statusResponse = await api('/api/setup/status');
      if (!statusResponse.ok) throw new Error('Provider connected, but setup status could not be refreshed. Retry to continue.');
      setSetup(await statusResponse.json() as SetupStatus);
      setSetupStep(1);
      setAdminMessage('Provider connected. Choose at least one source.');
    } catch (error) {
      setAdminMessage(error instanceof Error ? error.message : 'Provider could not be saved.');
    } finally {
      setAdminBusy(false);
    }
  }

  async function toggleOneDrive(enabled: boolean) {
    setAdminBusy(true);
    setAdminMessage('');
    try {
      const response = await api('/api/admin/sources/onedrive', { method: 'PUT', body: JSON.stringify({ enabled }) });
      if (!response.ok) throw new Error('OneDrive source setting could not be saved.');
      setSourceEnabled(enabled);
      const statusResponse = await api('/api/setup/status');
      if (statusResponse.ok) setSetup(await statusResponse.json() as SetupStatus);
      setAdminMessage(enabled ? 'Per-user OneDrive search enabled.' : 'Per-user OneDrive search disabled.');
    } catch (error) {
      setAdminMessage(error instanceof Error ? error.message : 'OneDrive source setting could not be saved.');
    } finally {
      setAdminBusy(false);
    }
  }

  async function saveSharePoint(enabled: boolean) {
    setAdminBusy(true);
    setAdminMessage('');
    try {
      const siteUrls = sharePointSiteUrls.split(/\r?\n/).map((site) => site.trim()).filter(Boolean);
      const response = await api('/api/admin/sources/sharepoint', {
        method: 'PUT', body: JSON.stringify({ enabled, siteUrls }),
      });
      if (!response.ok) throw new Error(response.status === 400 ? 'Enter up to five valid SharePoint Online site URLs, one per line.' : 'SharePoint source setting could not be saved.');
      setSharePointEnabled(enabled);
      const statusResponse = await api('/api/setup/status');
      if (statusResponse.ok) setSetup(await statusResponse.json() as SetupStatus);
      setAdminMessage(enabled ? 'Configured SharePoint sites enabled for per-user search.' : 'SharePoint search disabled.');
    } catch (error) {
      setAdminMessage(error instanceof Error ? error.message : 'SharePoint source setting could not be saved.');
    } finally {
      setAdminBusy(false);
    }
  }

  async function checkSharePoint() {
    setAdminBusy(true);
    setAdminMessage('');
    try {
      const response = await api('/api/admin/checks/sharepoint', { method: 'POST' });
      if (!response.ok) throw new Error(response.status === 424 ? 'Grant delegated Sites.Read.All consent, then check again.' : 'One or more configured SharePoint sites could not be accessed.');
      const result = await response.json() as { siteCount: number };
      setAdminMessage(`Connected to ${result.siteCount} SharePoint site${result.siteCount === 1 ? '' : 's'}.`);
    } catch (error) {
      setAdminMessage(error instanceof Error ? error.message : 'SharePoint access check failed.');
    } finally {
      setAdminBusy(false);
    }
  }

  async function toggleOutlook(enabled: boolean) {
    setAdminBusy(true);
    setAdminMessage('');
    try {
      const response = await api('/api/admin/sources/outlook', { method: 'PUT', body: JSON.stringify({ enabled }) });
      if (!response.ok) throw new Error('Outlook source setting could not be saved.');
      setOutlookEnabled(enabled);
      const statusResponse = await api('/api/setup/status');
      if (statusResponse.ok) setSetup(await statusResponse.json() as SetupStatus);
      setAdminMessage(enabled ? 'Per-user Outlook mail search enabled.' : 'Outlook mail search disabled.');
    } catch (error) {
      setAdminMessage(error instanceof Error ? error.message : 'Outlook source setting could not be saved.');
    } finally {
      setAdminBusy(false);
    }
  }

  async function checkOutlook() {
    setAdminBusy(true);
    setAdminMessage('');
    try {
      const response = await api('/api/admin/checks/outlook', { method: 'POST' });
      if (!response.ok) throw new Error(response.status === 424 ? 'Grant delegated Mail.Read consent, then check again.' : 'The administrator mailbox could not be accessed.');
      setAdminMessage('Connected to the administrator’s own mailbox.');
    } catch (error) {
      setAdminMessage(error instanceof Error ? error.message : 'Outlook access check failed.');
    } finally {
      setAdminBusy(false);
    }
  }

  async function toggleTeamsChats(enabled: boolean) {
    setAdminBusy(true);
    setAdminMessage('');
    try {
      const response = await api('/api/admin/sources/teams-chats', { method: 'PUT', body: JSON.stringify({ enabled }) });
      if (!response.ok) throw new Error('Teams chats source setting could not be saved.');
      setTeamsChatsEnabled(enabled);
      const statusResponse = await api('/api/setup/status');
      if (statusResponse.ok) setSetup(await statusResponse.json() as SetupStatus);
      setAdminMessage(enabled ? 'Per-user Teams chat search enabled.' : 'Teams chat search disabled.');
    } catch (error) {
      setAdminMessage(error instanceof Error ? error.message : 'Teams chat source setting could not be saved.');
    } finally {
      setAdminBusy(false);
    }
  }

  async function checkTeamsChats() {
    setAdminBusy(true);
    setAdminMessage('');
    try {
      const response = await api('/api/admin/checks/teams-chats', { method: 'POST' });
      if (!response.ok) throw new Error(response.status === 424 ? 'Grant delegated Chat.Read consent, then check again.' : 'The administrator’s Teams chats could not be accessed.');
      setAdminMessage('Connected to the administrator’s own Teams chats.');
    } catch (error) {
      setAdminMessage(error instanceof Error ? error.message : 'Teams chat access check failed.');
    } finally {
      setAdminBusy(false);
    }
  }

  async function toggleTeamsChannels(enabled: boolean) {
    setAdminBusy(true);
    setAdminMessage('');
    try {
      const response = await api('/api/admin/sources/teams-channels', { method: 'PUT', body: JSON.stringify({ enabled }) });
      if (!response.ok) throw new Error('Teams channels source setting could not be saved.');
      setTeamsChannelsEnabled(enabled);
      const statusResponse = await api('/api/setup/status');
      if (statusResponse.ok) setSetup(await statusResponse.json() as SetupStatus);
      setAdminMessage(enabled ? 'Per-user Teams channel search enabled.' : 'Teams channel search disabled.');
    } catch (error) {
      setAdminMessage(error instanceof Error ? error.message : 'Teams channels source setting could not be saved.');
    } finally {
      setAdminBusy(false);
    }
  }

  async function checkTeamsChannels() {
    setAdminBusy(true);
    setAdminMessage('');
    try {
      const response = await api('/api/admin/checks/teams-channels', { method: 'POST' });
      const result = await response.json() as { status?: string; stage?: string; upstreamStatus?: number };
      if (!response.ok) {
        const stages: Record<string, string> = { token_exchange: 'sign-in token exchange', list_teams: 'listing your teams', list_channels: 'listing channels', read_messages: 'reading channel messages' };
        const stage = result.stage ? stages[result.stage] || 'channel access' : 'channel access';
        const advice = result.status === 'consent_required' ? 'Grant delegated Team.ReadBasic.All, Channel.ReadBasic.All, and ChannelMessage.Read.All consent, then sign in again.' : result.status === 'permission_denied' ? 'Confirm your account belongs to an accessible channel and the app has delegated channel permissions. Administrator status alone does not grant private-channel membership.' : result.status === 'invalid_request' ? 'Microsoft rejected the API request. Redeploy the updated app and retry.' : result.status === 'throttled' ? 'Microsoft is throttling requests. Wait briefly and retry.' : result.status === 'timeout' ? 'The request timed out. Retry and check the deployment’s Microsoft Graph connectivity.' : 'Check Microsoft Graph connectivity and the deployment logs, then retry.';
        throw new Error(`Teams channels failed while ${stage} (${result.status || 'unavailable'}${result.upstreamStatus ? `; Graph HTTP ${result.upstreamStatus}` : ''}). ${advice}`);
      }
      setAdminMessage('Connected to the administrator’s joined Teams channels.');
    } catch (error) {
      setAdminMessage(error instanceof Error ? error.message : 'Teams channel access check failed.');
    } finally {
      setAdminBusy(false);
    }
  }

  async function refreshPostgresReadiness() {
    setPostgresReadiness(null); setPostgresSourceMessage('Checking PostgreSQL identity, permissions, and queries…');
    const response = await api('/api/admin/postgres/readiness');
    if (!response.ok) throw new Error('The source selection is saved, but the PostgreSQL readiness check could not be completed.');
    const result = await response.json() as PostgresReadiness;
    setPostgresReadiness(result); setPostgresSourceMessage(result.message); return result;
  }

  async function goToPostgresSetupStep() {
    const target = postgresReadiness?.next;
    if (!target) return;
    if (target === 'postgres-permission-drafts' && !roleDiscovery && postgresAuth.schema && postgresAuth.relation) await detectRoleMappings();
    requestAnimationFrame(() => document.getElementById(target)?.scrollIntoView({ behavior: 'smooth', block: 'start' }));
  }

  async function togglePostgres(enabled: boolean) {
    setAdminBusy(true);
    setAdminMessage(''); setPostgresReadiness(null); setPostgresSourceMessage('Saving PostgreSQL source selection…');
    try {
      const response = await api('/api/admin/sources/postgres', { method: 'PUT', body: JSON.stringify({ enabled }) });
      if (!response.ok) throw new Error('The PostgreSQL source setting could not be saved.');
      setPostgresEnabled(enabled);
      const statusResponse = await api('/api/setup/status');
      if (statusResponse.ok) setSetup(await statusResponse.json() as SetupStatus);
      if (enabled) await refreshPostgresReadiness();
      else setPostgresSourceMessage('PostgreSQL search is disabled.');
    } catch (error) {
      setPostgresSourceMessage(error instanceof Error ? error.message : 'The PostgreSQL source setting could not be saved.');
    } finally {
      setAdminBusy(false);
    }
  }

  async function discoverPostgres(afterSchema = '', afterName = '', append = false) {
    setAdminBusy(true); setAdminMessage('');
    try {
      const query = afterSchema ? `?afterSchema=${encodeURIComponent(afterSchema)}&afterName=${encodeURIComponent(afterName)}` : '';
      const response = await api(`/api/admin/postgres/discovery${query}`);
      if (!response.ok) {
        const failure = await response.json() as { error?: string };
        if (failure.error === 'database_permission_mapping_required') {
          throw new Error('Your email is already matched. Review the prepared permission rules, apply their reviewed SQL, then map the execution role and recheck your access. Re-entering the email does not resolve pending permissions.');
        }
        if (failure.error === 'database_email_confirmation_required') {
          await refreshDatabaseIdentity();
          throw new Error('Verify your database email in Database access first. Enter the same email shown for your Microsoft account and click “Verify my database email,” then retry business metadata discovery. Saving or changing the adapter requires email confirmation again.');
        }
        throw new Error(`Business metadata discovery failed (${failure.error || 'unknown'}). Check the saved authorization mapping and your database access.`);
      }
      const page = await response.json() as PostgresDiscovery;
      setPostgresDiscovery((current) => append && current ? { ...page, relations: [...current.relations, ...page.relations], columns: [...current.columns, ...page.columns], keys: [...(current.keys ?? []), ...(page.keys ?? [])], relationships: [...(current.relationships ?? []), ...(page.relationships ?? [])] } : page);
      setAdminMessage(`Loaded ${page.relations.length} accessible relations and ${page.columns.length} readable columns. No table rows were read.`);
    } catch (error) { setAdminMessage(error instanceof Error ? error.message : 'Metadata discovery failed.'); }
    finally { setAdminBusy(false); }
  }

  function profileFormSignature() {
    return JSON.stringify([profileId, profileLabel, profileSynonyms, profileCapability, profileSearchStrategy, profileLanguage, profileRelation, profileKey, profileDisplay, profileSearchColumns, profileForeignKey, profileParentProfileId, profileFiltersJSON, profileReturnTypes, profileSourceURL, profileApproval]);
  }

  function businessProfileDraft() {
    const decodedRelation = decodeRelationChoice(profileRelation);
    if (!decodedRelation) throw new Error('Choose a valid table before previewing.');
    const returnColumns = Object.entries(profileReturnTypes).filter(([, type]) => type).map(([name, type]) => ({ name, type }));
    if (!returnColumns.length) throw new Error('Select at least one return column.');
    if (profileSourceURL && !returnColumns.some((column) => column.name === profileSourceURL && column.type === 'text')) throw new Error('Choose a selected text return column for the source URL.');
    const draft: Record<string, unknown> = { id: profileId, version: 1, label: profileLabel, synonyms: profileSynonyms.split(',').map((item) => item.trim()).filter(Boolean), capability: profileCapability, searchStrategy: profileCapability === 'text_search' ? profileSearchStrategy : '', language: profileCapability === 'text_search' && profileSearchStrategy === 'full_text' ? profileLanguage : '', schema: decodedRelation[0], relation: decodedRelation[1], keyColumn: profileKey, labelColumn: profileDisplay, searchColumns: profileSearchColumns.split(',').map((item) => item.trim()).filter(Boolean), returnColumns, sourceURLColumn: profileSourceURL, approval: profileApproval };
    if (profileCapability === 'related_list') {
      const parentProfile = postgresProfiles.find((item) => item.id === profileParentProfileId && item.capability === 'entity_lookup');
      if (!parentProfile || profileId === parentProfile.id) throw new Error('Choose a saved entity lookup profile as the parent.');
      const fk = postgresDiscovery?.relationships.find((item) => JSON.stringify([item.sourceSchema,item.sourceRelation,item.name]) === profileForeignKey);
      if (!fk || fk.sourceSchema !== decodedRelation[0] || fk.sourceRelation !== decodedRelation[1] || fk.sourceColumns.length !== 1 || fk.targetColumns.length !== 1) throw new Error('Choose one discovered single-column foreign key for this child table.');
      let filters: unknown;
      try { filters = JSON.parse(profileFiltersJSON); } catch { throw new Error('Filters must be valid JSON.'); }
      draft.relationship = { parentProfileId: parentProfile.id, childForeignKey: fk.sourceColumns[0], filters };
    }
    return draft;
  }

  async function previewBusinessProfile() {
    setAdminBusy(true); setAdminMessage('');
    try {
      const draft = businessProfileDraft();
      const response = await api('/api/admin/postgres/profiles/preview', { method: 'POST', body: JSON.stringify(draft) });
      if (!response.ok) throw new Error('Preview failed. Check the selected columns, types, unique key, and your database permissions.');
      setProfilePreview(await response.json() as PostgresProfilePreview);
      setProfilePreviewInput(profileFormSignature());
      setAdminMessage('Generated SQL preview is ready. Review the query and permission explanation before saving.');
    } catch (error) { setAdminMessage(error instanceof Error ? error.message : 'Profile preview failed.'); }
    finally { setAdminBusy(false); }
  }

  async function saveBusinessProfile(event: React.FormEvent) {
    event.preventDefault(); setAdminBusy(true); setAdminMessage('');
    try {
      const draft = businessProfileDraft();
      if (!profilePreview || profilePreviewInput !== profileFormSignature()) throw new Error('Preview the current profile draft before saving.');
      const response = await api('/api/admin/postgres/profiles', { method: 'PUT', body: JSON.stringify(draft) });
      if (!response.ok) throw new Error('Profile was not saved. Confirm its identifiers, text field types, unique key, and DBA approval.');
      const catalog = await api('/api/admin/postgres/queries');
      if (catalog.ok) setPostgresQueries((await catalog.json() as { queries: PostgresQuery[] }).queries);
      const profiles=await api('/api/postgres/profiles');
      if(profiles.ok)setPostgresProfiles((await profiles.json() as {profiles:PostgresProfileSummary[]}).profiles);
      setProfilePreview(null); setProfilePreviewInput('');
      setAdminMessage('Business profile saved as a canonical, parameterized query. It still needs user-login tests before activation.');
    } catch (error) { setAdminMessage(error instanceof Error ? error.message : 'Profile could not be saved.'); }
    finally { setAdminBusy(false); }
  }

  async function checkOneDrive() {
    setAdminBusy(true); setAdminMessage('');
    try {
      const response = await api('/api/admin/checks/onedrive', { method: 'POST' });
      const result = await response.json() as { status?: string };
      if (!response.ok) throw new Error(`OneDrive check failed (${result.status || 'unavailable'}). Check Microsoft consent, your OneDrive provisioning, and service connectivity.`);
      setAdminMessage('OneDrive access passed.');
    } catch (error) { setAdminMessage(error instanceof Error ? error.message : 'OneDrive check failed.'); }
    finally { setAdminBusy(false); }
  }

  async function checkPostgres() {
    setAdminBusy(true);
    try { const result = await refreshPostgresReadiness(); setAdminMessage(result.message); }
    catch (error) { setPostgresSourceMessage(error instanceof Error ? error.message : 'PostgreSQL readiness check failed.'); }
    finally { setAdminBusy(false); }
  }

  async function confirmDatabaseEmail(event: React.FormEvent) {
    event.preventDefault(); setAdminBusy(true); setPostgresCredentialMessage('');
    try {
      const response = await api('/api/postgres/email', { method: 'PUT', body: JSON.stringify({ email: databaseEmail }) });
      const result = await response.json() as { error?: string; userId?: string; databaseRole?: string; applicationRole?: string; status?: string };
      if (!response.ok) {
        if (result.error === 'execution_role_not_found' || result.error === 'application_role_mapping_required') {
          throw new Error(`Your email matched an active database user. Its application role${result.applicationRole ? ` “${result.applicationRole}”` : ''} has no valid database execution-role mapping. Review Detected permission structure and Role translation, then save the adapter. If no eligible execution roles exist, the permission adapter must be configured before access can be granted.`);
        }
        if (result.error === 'database_email_mismatch') throw new Error('Your entered database email does not match your verified Microsoft email.');
        if (result.error === 'user_email_not_found') throw new Error('The entered email matches Microsoft, but no database user was found in the configured mapping.');
        if (result.error === 'user_inactive') throw new Error('Your email matched a disabled database user.');
        throw new Error(`Database access verification failed (${result.error || 'unknown'}). Check the mapped account and its execution-role permissions.`);
      }
      setPostgresCredentialMessage(result.status === 'matched_permissions_required' ? `Email verified. Matched database user ${result.userId} with application role “${result.applicationRole}”. Permissions are pending; database search is not enabled by this label alone.` : `Email verified. Connected as ${result.userId} with database role ${result.databaseRole}.`);
      await refreshDatabaseIdentity();
    } catch (error) { setPostgresCredentialMessage(error instanceof Error ? error.message : 'Database email confirmation failed.'); }
    finally { setAdminBusy(false); }
  }

  async function refreshDatabaseIdentity() {
    const response = await api('/api/postgres/credentials');
    if (!response.ok) throw new Error('Database identity status could not be refreshed.');
    setPostgresCredentialStatus(await response.json() as PostgresCredentialStatus);
    if (session?.role === 'Admin') { try { await refreshPostgresReadiness(); } catch { setPostgresSourceMessage('Database identity updated. Recheck PostgreSQL readiness.'); } }
  }

  async function detectRoleMappings(adapter = postgresAuth) {
    setRoleMappingMessage('Discovering role values and database execution roles…');
    try {
      const query = new URLSearchParams({ schema: adapter.schema, relation: adapter.relation, column: adapter.columns?.role || 'database_role' });
      const response = await api(`/api/admin/postgres/auth/roles?${query}`);
      const result = await response.json();
      if (!response.ok) throw new Error(`Role discovery failed (${result.error || 'unknown'}).`);
      setRoleDiscovery(result);
      const roles = new Set(result.executionRoles.map((role: { name: string }) => role.name));
      const mappings: Record<string, string> = {};
      for (const role of result.applicationRoles as string[]) mappings[role] = adapter.roleMappings?.[role] || (roles.has(role) ? role : '');
      setPostgresAuth((current) => current.schema === adapter.schema && current.relation === adapter.relation ? { ...current, roleMappings: mappings } : current);
      setPostgresAuthSaved(false);
      setRoleMappingMessage(result.executionRoles.length === 0 ? 'Application roles were found, but no eligible PostgreSQL execution roles were found. Review the detected permission tables, relationships, and row policies below. Application code permissions are not visible in database metadata. Role names alone cannot establish equivalent database permissions.' : 'Exact database-role matches are prefilled. Select a reviewed execution role for application labels that have no exact match. Policy counts show existing role policies, not proof that they implement your application permissions.');
    } catch (error) { setRoleMappingMessage(error instanceof Error ? error.message : 'Role discovery failed.'); }
  }

  async function detectDatabaseMapping(append = false) {
    setAdminBusy(true); setMappingMessage('Inspecting database metadata…');
    try {
      const after = append && authorizationDiscovery?.nextSchema ? `?afterSchema=${encodeURIComponent(authorizationDiscovery.nextSchema)}&afterName=${encodeURIComponent(authorizationDiscovery.nextName || '')}` : '';
      const response = await api(`/api/admin/postgres/auth/discovery${after}`);
      if (!response.ok) {
        const failure = await response.json() as { error?: string; stage?: string };
        const guidance: Record<string, string> = {
          shared_database_credentials_required: 'POSTGRES_DSN must contain the service username and password. Update Dokploy environment and redeploy.',
          unsafe_database_login: 'The URI login is a PostgreSQL superuser or has BYPASSRLS. Use a dedicated non-superuser service login without BYPASSRLS so user permissions can be enforced.',
          database_authentication_failed: 'PostgreSQL rejected the URI credentials or authentication rules. Check the username/password and connection access rules; URL-encode special characters in the password.',
          database_not_found: 'The database named in POSTGRES_DSN does not exist on that server.',
          database_private_endpoint_required: 'Private-network mode cannot connect to a public address. Use the internal Dokploy hostname for private_network mode, or explicitly configure external_plaintext with sslmode=disable for your external non-TLS endpoint.',
          database_tls_unavailable: 'The PostgreSQL endpoint refused TLS. Enable TLS on the database or connect through its TLS-enabled endpoint. A full URI alone does not enable TLS on the server.',
          database_tls_handshake_failed: 'The endpoint did not complete a valid TLS handshake. Check the PostgreSQL hostname/port and TLS configuration.',
          database_connection_closed: 'The server or proxy closed the connection before setup completed. Check the PostgreSQL endpoint and proxy connection settings.',
          database_tls_verification_failed: 'The database certificate or hostname could not be verified. Configure the trusted CA and matching hostname for sslmode=verify-full.',
          database_dns_failed: 'The database hostname could not be resolved from the app container. Check the Dokploy network and URI hostname.',
          database_unreachable: 'The database host/port could not be reached from the app container. Check the Dokploy network, firewall, and database listener.',
          database_timeout: 'Database discovery timed out. Check connectivity and retry.',
          metadata_permission_denied: 'The URI login connected but was denied metadata access. Check its database/schema permissions.',
          metadata_identity_mismatch: 'The connection starts with a different execution role. Remove an automatic role override from the URI or connection proxy for metadata discovery.',
          database_request_failed: 'PostgreSQL rejected a connection-setup or metadata command. The stage identifies which part failed.',
        };
        throw new Error(`Mapping discovery failed (${failure.error || 'unknown'}${failure.stage ? `; stage: ${failure.stage}` : ''}). ${guidance[failure.error || ''] || 'Check the shared database connection and metadata privileges.'}`);
      }
      const page = await response.json() as AuthorizationDiscovery;
      const candidates = append && authorizationDiscovery ? [...authorizationDiscovery.candidates, ...page.candidates] : page.candidates;
      const discovery = { ...page, candidates };
      setAuthorizationDiscovery(discovery);
      const prefilled = authorizationPrefill(postgresAuth, candidates, !page.nextSchema);
      if (prefilled !== postgresAuth) { setPostgresAuth(prefilled); setPostgresAuthSaved(false); await detectRoleMappings(prefilled); } else if (postgresAuth.schema && postgresAuth.relation) { await detectRoleMappings(postgresAuth); }
      setMappingMessage(prefilled !== postgresAuth ? 'User mapping prefilled from detected fields. Review the column mapping below, then save and check your access. The role must resolve to an allowed PostgreSQL execution role.' : page.nextSchema ? 'More metadata is available. Load the next page before choosing an automatic mapping.' : candidates.some((candidate) => candidate.ready || candidateColumnMapping(candidate)) ? 'Choose a compatible mapping below. Your existing entries have been preserved.' : 'No complete authorization mapping was found. Detected user tables are listed below with missing fields; their permission mapping still needs configuration.');
    } catch (error) { setMappingMessage(error instanceof Error ? error.message : 'Mapping discovery failed.'); }
    finally { setAdminBusy(false); }
  }

  function prefillQueryFromRelation(schema: string, name: string) {
    const relation = postgresDiscovery?.relations.find((item) => item.schema === schema && item.name === name);
    if (!relation || !postgresDiscovery) return;
    const draft = queryPrefill(relation, postgresDiscovery.columns);
    if (!draft) { setAdminMessage('This relation does not have the four required query output fields. Use the business-profile mapper or enter a reviewed query.'); return; }
    if (postgresToolSQL || postgresToolId || postgresToolDescription) { setAdminMessage('Your existing query draft was preserved. Clear its fields before prefilling from another relation.'); return; }
    let id = draft.id;
    for (let suffix = 2; postgresQueries.some((query) => query.id === id); suffix++) id = `${draft.id.slice(0, 54)}_${suffix}`;
    setPostgresToolId(id); setPostgresToolDescription(draft.description); setPostgresToolSQL(draft.sql);
    setAdminMessage('Query ID, description, and SQL prefilled from the selected relation. Review the query and enter its approval reference before saving.');
  }

  async function savePostgresAuth(event: React.FormEvent) {
    event.preventDefault();
    setAdminBusy(true); setAdminMessage('');
    try {
      const response = await api('/api/admin/postgres/auth', { method: 'PUT', body: JSON.stringify({ ...postgresAuth, roleMappings: Object.fromEntries(Object.entries(postgresAuth.roleMappings || {}).filter(([, role]) => role.trim() !== '')) }) });
      if (!response.ok) throw new Error('Check the adapter view, approval reference, and shared username/password in Dokploy POSTGRES_DSN.');
      setPostgresAuthSaved(true);
      setPostgresProfileTests([]);
      setAdminMessage('Adapter saved. Checking your database identity…');
      const check = await api('/api/admin/postgres/auth/check', { method: 'POST' });
      await refreshDatabaseIdentity();
      if (!check.ok) {
        const failure = await check.json() as { error?: string };
        const advice: Record<string, string> = {
          unsafe_service_login: 'The URI login is a superuser or has BYPASSRLS. Use a non-superuser service login with the required execution-role grants.',
          postgres_verified_email_required: 'Microsoft has not supplied a verified organizational email. Check User.Read consent and your account profile.',
          user_email_not_found: 'No database user matches your signed-in Microsoft email within this tenant mapping.',
          user_email_ambiguous: 'More than one database user matches your email. Resolve the duplicate mapping.',
          user_inactive: 'Your matched database account is disabled.',
          user_mapping_query_failed: 'The mapped relation or columns cannot be queried. Check the saved column mapping and service SELECT permissions.',
          user_mapping_values_invalid: 'The matched record has missing or incompatible values. Check user ID, role, and the boolean active column.',
          execution_role_invalid: 'The mapped role is invalid or matches the service login. Map to a separate PostgreSQL execution role.',
          application_role_mapping_required: 'This application role has no saved translation. Use Detect role values and permissions in the authorization mapping.',
          execution_role_not_found: 'The user row matched, but its role value is not a PostgreSQL role. Application roles need an authorization adapter that translates them to a database execution role.',
          execution_role_owns_tables: 'The mapped execution role owns tables and could bypass row policies. Use a non-owning execution role with explicit access grants.',
          execution_role_switch_failed: 'The connection could not switch to the mapped restricted identity. Database search access was denied.',
          service_identity_mismatch: 'The connection starts with an unexpected session role. Check database proxy or URI role overrides.',
          execution_role_unsafe: 'The mapped role is a superuser or has BYPASSRLS and cannot enforce per-user access.',
          execution_role_not_granted: 'The matched PostgreSQL execution role is not granted to the URI service login.',
        };
        throw new Error(`Adapter saved; access check failed (${failure.error || 'unknown'}). ${advice[failure.error || ''] || 'Check the database connection and authorization mapping.'}`);
      }
      const result = await check.json() as { userId: string; databaseRole: string };
      setAdminMessage(`Connected as database user ${result.userId}, role ${result.databaseRole}. Profile tests must be rerun after adapter changes.`);
    } catch (error) { setAdminMessage(error instanceof Error ? error.message : 'Database adapter could not be checked.'); }
    finally { setAdminBusy(false); }
  }

  async function checkDatabaseIdentity() {
    setAdminBusy(true); setPostgresCredentialMessage('');
    try { await refreshDatabaseIdentity(); }
    catch (error) { setPostgresCredentialMessage(error instanceof Error ? error.message : 'Database identity check failed.'); }
    finally { setAdminBusy(false); }
  }

  async function savePostgresIdentity(event: React.FormEvent) {
    event.preventDefault();
    setAdminBusy(true);
    setAdminMessage('');
    try {
      const response = await api('/api/admin/postgres/identities', {
        method: 'PUT', body: JSON.stringify({ objectId: postgresObjectId, verifiedEmail: postgresVerifiedEmail, databaseIdentity: postgresDatabaseIdentity }),
      });
      if (!response.ok) throw new Error(response.status === 409 ? 'This database login is already mapped to another account, or the mapping conflicts with an existing binding. Use a separate database login for each user.' : 'Check the verified email, object ID, and existing database login name.');
      const saved = await response.json() as PostgresIdentity;
      setPostgresIdentities((items) => [...items.filter((item) => item.objectId !== saved.objectId), saved].sort((a, b) => a.objectId.localeCompare(b.objectId)));
      setPostgresObjectId('');
      setPostgresVerifiedEmail('');
      setPostgresDatabaseIdentity('');
      setAdminMessage('Existing database identity binding saved and reviewed. The user must save their own database password again.');
      const statusResponse = await api('/api/postgres/credentials');
      if (!statusResponse.ok) throw new Error('Mapping saved, but sign-in status could not refresh. Reload the app before entering your database password.');
      setPostgresCredentialStatus(await statusResponse.json() as PostgresCredentialStatus);
      setPostgresProfileTests((items) => items.filter((item) => item.objectId !== saved.objectId));
    } catch (error) {
      setAdminMessage(error instanceof Error ? error.message : 'The PostgreSQL identity mapping could not be saved.');
    } finally {
      setAdminBusy(false);
    }
  }

  async function deletePostgresIdentity(objectId: string) {
    setAdminBusy(true);
    setAdminMessage('');
    try {
      const response = await api(`/api/admin/postgres/identities/${encodeURIComponent(objectId)}`, { method: 'DELETE' });
      if (!response.ok) throw new Error('The PostgreSQL identity mapping could not be removed.');
      setPostgresIdentities((items) => items.filter((item) => item.objectId !== objectId));
      setAdminMessage('PostgreSQL identity mapping removed.');
      const statusResponse = await api('/api/postgres/credentials');
      if (!statusResponse.ok) throw new Error('Mapping removed, but sign-in status could not refresh. Reload the app.');
      setPostgresCredentialStatus(await statusResponse.json() as PostgresCredentialStatus);
      setPostgresProfileTests((items) => items.filter((item) => item.objectId !== objectId));
    } catch (error) {
      setAdminMessage(error instanceof Error ? error.message : 'The PostgreSQL identity mapping could not be removed.');
    } finally {
      setAdminBusy(false);
    }
  }

  async function savePostgresQuery(event: React.FormEvent) {
    event.preventDefault();
    setAdminBusy(true);
    setAdminMessage('');
    try {
      const previous = postgresQueries.find((query) => query.id === postgresToolId);
      const response = await api('/api/admin/postgres/queries', {
        method: 'PUT',
        body: JSON.stringify({
          id: postgresToolId, version: (previous?.version ?? 0) + 1, description: postgresToolDescription, sql: postgresToolSQL,
          parameters: [{ name: 'question', type: 'text' }, { name: 'limit', type: 'integer[1,5]' }],
          outputColumns: ['id:text', 'title:text', 'content:text', 'source_url:text'], approvalRecord: postgresToolApproval,
        }),
      });
      if (!response.ok) throw new Error(response.status === 409 ? 'Refresh the query list and try a new version.' : 'The query must be one fixed SELECT with the approved parameters and output columns.');
      const saved = await response.json() as PostgresQuery;
      setPostgresQueries((items) => [...items.filter((query) => query.id !== saved.id), saved].sort((a, b) => a.id.localeCompare(b.id)));
      setAdminMessage(`Approved query ${saved.id} version ${saved.version} saved.`);
    } catch (error) {
      setAdminMessage(error instanceof Error ? error.message : 'The approved query could not be saved.');
    } finally {
      setAdminBusy(false);
    }
  }

  function editPostgresQuery(query: PostgresQuery) {
    setPostgresToolId(query.id);
    setPostgresToolDescription(query.description);
    setPostgresToolSQL(query.sql);
    setPostgresToolApproval(query.approvalRecord.split('; reviewed-by=')[0]);
  }

  async function deletePostgresQuery(toolId: string) {
    setAdminBusy(true);
    setAdminMessage('');
    try {
      const response = await api(`/api/admin/postgres/queries/${encodeURIComponent(toolId)}`, { method: 'DELETE' });
      if (!response.ok) throw new Error('The approved query could not be removed.');
      setPostgresQueries((items) => items.filter((query) => query.id !== toolId));
      setAdminMessage(`Approved query ${toolId} removed.`);
    } catch (error) {
      setAdminMessage(error instanceof Error ? error.message : 'The approved query could not be removed.');
    } finally {
      setAdminBusy(false);
    }
  }

  async function savePostgresPassword(event: React.FormEvent) {
    event.preventDefault();
    setAdminBusy(true);
    setPostgresCredentialMessage('');
    try {
      const response = await api('/api/postgres/credentials', { method: 'PUT', body: JSON.stringify({ password: postgresPassword }) });
      if (!response.ok) throw new Error(response.status === 424 ? 'The password did not authenticate as your administrator-reviewed database identity.' : 'Your PostgreSQL password could not be saved.');
      setPostgresPassword('');
      const statusResponse = await api('/api/postgres/credentials');
      if (statusResponse.ok) setPostgresCredentialStatus(await statusResponse.json() as PostgresCredentialStatus);
      setPostgresCredentialMessage('Your password was verified and stored encrypted for your account.');
    } catch (error) {
      setPostgresCredentialMessage(error instanceof Error ? error.message : 'Your PostgreSQL password could not be saved.');
    } finally {
      setAdminBusy(false);
    }
  }

  async function testPostgresProfile(id: string) {
    setAdminBusy(true); setPostgresCredentialMessage('');
    try {
      const response=await api(`/api/postgres/profiles/${encodeURIComponent(id)}/test`,{method:'POST'});
      const result=await response.json() as {status?:string};
      if(!response.ok) throw new Error('This profile did not pass with your database permissions. Contact an administrator to review permissions or schema status.');
      setPostgresCredentialMessage(`Profile test ${result.status}. Only pass/fail metadata was saved; no sample rows were retained.`);
      if(session?.role==='Admin'){const tests=await api('/api/admin/postgres/profile-tests');if(tests.ok)setPostgresProfileTests((await tests.json() as {tests:PostgresProfileTest[]}).tests);}
    } catch(error){setPostgresCredentialMessage(error instanceof Error?error.message:'Profile test failed.');}
    finally{setAdminBusy(false);}
  }

  async function deletePostgresPassword() {
    setAdminBusy(true);
    setPostgresCredentialMessage('');
    try {
      const response = await api('/api/postgres/credentials', { method: 'DELETE' });
      if (!response.ok) throw new Error('Your PostgreSQL password could not be removed.');
      setPostgresCredentialStatus((status) => status ? { ...status, configured: false } : status);
      setPostgresCredentialMessage('Your saved database password was removed.');
    } catch (error) {
      setPostgresCredentialMessage(error instanceof Error ? error.message : 'Your PostgreSQL password could not be removed.');
    } finally {
      setAdminBusy(false);
    }
  }

  async function activateSetup(event: React.FormEvent) {
    event.preventDefault();
    setAdminBusy(true);
    setAdminMessage('');
    setFailedSource('');
    try {
      const response = await api('/api/setup/activate', {
        method: 'POST', headers: { 'X-Setup-Secret': bootstrapSecret },
      });
      if (!response.ok) {
        const failure = await response.json() as { error?: string; status?: string; source?: string; emailStatus?: string };
        if (failure.error === 'source_check_failed') {
          const sourceNames: Record<string, string> = { onedrive: 'OneDrive', sharepoint: 'SharePoint', outlook: 'Outlook', 'teams-chats': 'Teams chats', 'teams-channels': 'Teams channels', postgres: 'PostgreSQL' };
          const source = failure.source ? sourceNames[failure.source] || 'A source' : 'A source';
          const guidance = failure.status === 'postgres_adapter_required' ? 'Configure and save the database authorization adapter below before activating.' : failure.status === 'postgres_verified_email_required' ? directoryEmailHelp(failure.emailStatus) : failure.status === 'consent_required' ? 'Check Microsoft delegated consent and sign in again.' : failure.status === 'permission_denied' ? 'Check the signed-in account’s permissions.' : failure.status === 'not_provisioned' || failure.status === 'not_found' ? 'This source is not provisioned or could not be found for your account.' : failure.source === 'postgres' ? 'Check the database authorization adapter, your access, and the approved queries.' : 'The source could not be reached or its service rejected the request. Check it below and retry.';
          setFailedSource(failure.source || '');
          setSetupStep(1);
          throw new Error(`${source} blocked activation (${failure.status || 'unavailable'}). ${guidance} You can disable a source you do not need and activate with the remaining sources.`);
        }
        throw new Error(response.status === 409 ? 'Save and check your provider and enable at least one source before activating.' : 'Activation failed. Check the one-time setup secret and your administrator access, then retry.');
      }
      setBootstrapSecret('');
      setSetup({ active: true, wizardReady: true });
      setSetupStep(1);
      setSettingsOpen(false);
      setAdminMessage('Workspace activated. The bootstrap secret cannot activate it again.');
    } catch (error) {
      setAdminMessage(error instanceof Error ? error.message : 'Workspace activation failed.');
    } finally {
      setAdminBusy(false);
    }
  }

  async function ask(event: React.FormEvent) {
    event.preventDefault();
    setAsking(true);
    setAskMessage('');
    setAnswer(null);
    setSearchDetails(null);
    try {
      const response = await api('/api/ask', { method: 'POST', body: JSON.stringify({ question, scope: searchLocation }) });
      const result = await response.json() as AskResult & { error?: string };
      if (result.search) setSearchDetails(result.search);
      if (!response.ok) throw new Error(result.error === 'source_unavailable' ? 'A connected source could not be searched. Sign in again or ask your administrator to check permissions.' : 'The assistant could not answer this question.');
      setAnswer(result);
    } catch (error) {
      setAskMessage(error instanceof Error ? error.message : 'The assistant could not answer this question.');
    } finally {
      setAsking(false);
    }
  }

  const selectedRelation = decodeRelationChoice(profileRelation);
  const selectedProfileColumns = selectedRelation ? postgresDiscovery?.columns.filter((column) => column.schema === selectedRelation[0] && column.relation === selectedRelation[1]) ?? [] : [];
  return <main>
    <div className="brand-mark" aria-hidden="true">IQ</div>
    <p className="eyebrow">ORGANIZATIONAL KNOWLEDGE</p>
    <h1>IQ Knowledge</h1>
    <p className="intro">Find clear answers from the sources your organization has approved.</p>
    <div className="status-card" role="status" aria-live="polite">
      <span className={session ? 'status-dot ready' : 'status-dot'} aria-hidden="true" />
      <div><strong>{session ? 'Account connected' : 'Sign-in required'}</strong><p>{message}</p></div>
    </div>
    {session && <section className="account" aria-label="Signed-in account"><span>Access level</span><strong>{session.role}</strong></section>}
    {session?.role === 'User' && !setup?.active && <section className="setup-card"><h2>Your workspace is being set up</h2><p>Your administrator needs to connect a provider and source before you can ask questions.</p></section>}

    {session && postgresCredentialStatus?.available && <section id="database-access" className="setup-card">
      <h2>Your PostgreSQL sign-in</h2>
      {postgresCredentialStatus.mode === 'shared-adapter' ? <>
        <p role="status">{postgresCredentialStatus.status === 'connected' ? `Connected as ${postgresCredentialStatus.userId} with database role ${postgresCredentialStatus.databaseRole}.` : postgresCredentialStatus.status === 'matched_permissions_required' ? `Email matched database user ${postgresCredentialStatus.userId} with application role “${postgresCredentialStatus.applicationRole}”. Permission rules still need an enforceable mapping before database search can run.` : postgresCredentialStatus.status === 'adapter_required' ? 'Your administrator needs to configure the database authorization adapter.' : postgresCredentialStatus.status === 'email_confirmation_required' ? 'Enter your database email below to verify the match before searching.' : postgresCredentialStatus.status === 'email_required' ? directoryEmailHelp(postgresCredentialStatus.emailStatus) : 'Your database user could not be authorized. Check the email match, account status, adapter view, and database role grants with your administrator.'}</p>
        <p className="muted">Your Teams account is matched automatically. The connection is supplied by your organization.</p>
        <form onSubmit={confirmDatabaseEmail}>
          <p className="muted">Your verified Microsoft email: {postgresCredentialStatus.verifiedEmail || 'unavailable'}. Your database account email must match it.</p>
          <label>Database account email<input type="email" value={databaseEmail} onChange={(event) => setDatabaseEmail(event.target.value)} maxLength={254} required autoComplete="email" /></label>
          <button type="submit" disabled={adminBusy || !postgresCredentialStatus.verifiedEmail || !databaseEmail}>Verify my database email</button>
        </form>
        <button type="button" disabled={adminBusy} onClick={() => void checkDatabaseIdentity()}>Refresh database access</button>
        {postgresCredentialMessage && <p role="status">{postgresCredentialMessage}</p>}
        {postgresCredentialStatus.configured && postgresProfiles.length > 0 && <div><h3>Business profile tests</h3><p className="muted">Run tests with your resolved permissions. Each profile requires passing tests from two different database users.</p>{postgresProfiles.map((profile) => <div className="button-row" key={profile.id}><span>{profile.label} v{profile.version}</span><button type="button" disabled={adminBusy} onClick={() => void testPostgresProfile(profile.id)}>Test with my permissions</button></div>)}</div>}
      </> : <>
      {!postgresCredentialStatus.verifiedEmail ? <p role="status">Your Teams sign-in did not provide the verified email required by the current database integration. An email entered in the mapping form cannot supply this claim. Ask your administrator to check the identity configuration.</p> : !postgresCredentialStatus.mapped ? <p role="status">Your signed-in email is {postgresCredentialStatus.verifiedEmail}. An administrator must map this exact email and your Entra object ID ({session.objectId}) to your existing PostgreSQL login.</p> : <>
      <p className="muted">Your verified account {postgresCredentialStatus.verifiedEmail} is bound to an existing database login. Enter your own database password; it is encrypted for your account and used only for your searches.</p>
      <form className="admin-form" onSubmit={(event) => void savePostgresPassword(event)}>
        <label>Your database password<input type="password" autoComplete="current-password" value={postgresPassword} onChange={(event) => setPostgresPassword(event.target.value)} maxLength={4096} required /></label>
        <div className="button-row"><button type="submit" disabled={adminBusy || !postgresPassword}>Verify and save password</button>{postgresCredentialStatus.configured && <button type="button" disabled={adminBusy} onClick={() => void deletePostgresPassword()}>Remove saved password</button>}</div>
      </form>
      {postgresCredentialMessage && <p role="status">{postgresCredentialMessage}</p>}
      {postgresCredentialStatus.configured && postgresProfiles.length>0 && <div><h3>Business profile tests</h3><p className="muted">Tests run as your own mapped login and discard returned rows. Administrators require passing evidence from two different users before activating profiles.</p>{postgresProfiles.map((profile)=><div className="button-row" key={profile.id}><span>{profile.label} v{profile.version}</span><button type="button" disabled={adminBusy} onClick={()=>void testPostgresProfile(profile.id)}>Test as my login</button></div>)}</div>}
      </>}
      </>}
    </section>}

    {session?.role === 'Admin' && <section className="setup-card">
      <div className="setup-heading"><h2>{setup?.active ? 'Workspace settings' : 'Set up your workspace'}</h2>{setup?.active && <button type="button" aria-expanded={settingsOpen} onClick={() => setSettingsOpen(!settingsOpen)}>{settingsOpen ? 'Close settings' : 'Manage settings'}</button>}</div>
      <p>{setup?.active ? 'Workspace is active. You can ask questions below.' : 'Connect a provider, choose one source, and activate. You can add more sources later.'}</p>
      {(!setup?.active || settingsOpen) && <>
      <nav className="setup-steps" aria-label="Setup steps">
        {(setup?.active ? ['AI provider', 'Sources'] : ['AI provider', 'Sources', 'Activate']).map((label, index) => <button type="button" key={label} disabled={adminBusy} aria-current={setupStep === index ? 'step' : undefined} onClick={() => { setSetupStep(index); setAdminMessage(''); }}><span>{index + 1}</span>{label}</button>)}
      </nav>
      <div hidden={setupStep !== 0}>
      <h3>Connect your AI provider</h3>
      <p className="muted">Use the model approved by your organization.</p>
      <form className="admin-form" onSubmit={(event) => void saveProvider(event)}>
        <label>Model provider<select value={provider} onChange={(event) => setProvider(event.target.value)}>
          <option value="openai">OpenAI</option><option value="openai_compatible">OpenAI-compatible endpoint</option><option value="anthropic">Anthropic</option>
        </select></label>
        <label>Model name<input value={model} onChange={(event) => setModel(event.target.value)} maxLength={128} required /></label>
        {provider === 'openai_compatible' && <label>HTTPS base URL<input type="url" value={baseUrl} onChange={(event) => setBaseUrl(event.target.value)} placeholder="https://provider.example/v1" required /></label>}
        <p className="muted">Each answer sends the question and selected source excerpts to this provider. Before activation, review retention, training use, and region for the exact account, endpoint, and model; the synthetic connection check does not verify those settings.</p>
        <p className="muted" role="status">{providerKeyConfigured ? 'API key configured by your operator.' : 'An operator must configure the API key before you can connect.'}</p>
        <details className="setup-details"><summary>Where does the API key go?</summary><p className="muted">Set MODEL_API_KEY in local development or the model_api_key mounted secret in Docker. Keys are never sent from this page or stored in SQLite.</p></details>
        <button type="submit" disabled={adminBusy || !providerKeyConfigured}>{adminBusy ? 'Connecting…' : 'Save and connect'}</button>
      </form>
      </div>
      <div hidden={setupStep !== 1}>
      <h3>Choose where to search</h3>
      <p className="muted">One source is enough to get started. Only enable sources your organization has approved.</p>
      <label className="source-toggle"><input type="checkbox" checked={sourceEnabled} disabled={adminBusy} onChange={(event) => void toggleOneDrive(event.target.checked)} /> Enable search in each user’s own OneDrive</label>
      <p className="muted">Start with personal documents. Microsoft consent and access are checked during activation.</p>
      <button type="button" disabled={adminBusy || !sourceEnabled} onClick={() => void checkOneDrive()}>Check OneDrive</button>
      <details className="source-setup" open={failedSource === 'sharepoint' || undefined}><summary>SharePoint documents {sharePointEnabled ? '· Enabled' : '· Optional'}</summary>
        <label>SharePoint site URLs<textarea value={sharePointSiteUrls} onChange={(event) => setSharePointSiteUrls(event.target.value)} rows={3} placeholder="https://contoso.sharepoint.com/sites/Research" disabled={adminBusy} /></label>
        <p className="muted">One site per line, up to five. Searches each site’s default document library. Delegated Sites.Read.All consent is required; each user’s access is checked when searching and downloading.</p>
        <div className="button-row">
          <button type="button" disabled={adminBusy || !sharePointSiteUrls.trim()} onClick={() => void saveSharePoint(true)}>Save and enable</button>
          <button type="button" disabled={adminBusy || !sharePointEnabled} onClick={() => void checkSharePoint()}>Check SharePoint</button>
          <button type="button" disabled={adminBusy || !sharePointEnabled} onClick={() => void saveSharePoint(false)}>Disable</button>
        </div>
      </details>
      <details className="source-setup" open={failedSource === 'teams-chats' || undefined}><summary>Teams chats {teamsChatsEnabled ? '· Enabled' : '· Optional'}</summary>
        <label className="source-toggle"><input type="checkbox" checked={teamsChatsEnabled} disabled={adminBusy} onChange={(event) => void toggleTeamsChats(event.target.checked)} /> Enable search in each user’s Teams chats</label>
        <p className="muted">Searches recent messages in the user’s private and group chats (up to ten chats and twenty messages per chat). Delegated Chat.Read consent is required. Channel messages are not included.</p>
        <button type="button" disabled={adminBusy || !teamsChatsEnabled} onClick={() => void checkTeamsChats()}>Check Teams chats</button>
      </details>
      <details className="source-setup" open={failedSource === 'teams-channels' || undefined}><summary>Teams channels {teamsChannelsEnabled ? '· Enabled' : '· Optional'}</summary>
        <label className="source-toggle"><input type="checkbox" checked={teamsChannelsEnabled} disabled={adminBusy} onChange={(event) => void toggleTeamsChannels(event.target.checked)} /> Enable search in each user’s joined Teams channels</label>
        <p className="muted">Searches up to five joined teams, five channels per team, and twenty recent root messages per channel. Delegated Team.ReadBasic.All, Channel.ReadBasic.All, and ChannelMessage.Read.All consent is required. Users’ channel membership is checked by Graph.</p>
        <button type="button" disabled={adminBusy || !teamsChannelsEnabled} onClick={() => void checkTeamsChannels()}>Check Teams channels</button>
      </details>
      <details className="source-setup" open={failedSource === 'outlook' || undefined}><summary>Outlook email {outlookEnabled ? '· Enabled' : '· Optional'}</summary>
        <label className="source-toggle"><input type="checkbox" checked={outlookEnabled} disabled={adminBusy} onChange={(event) => void toggleOutlook(event.target.checked)} /> Enable search in each user’s own Outlook mailbox</label>
        <p className="muted">Searches a few matching message subjects and text bodies. Delegated Mail.Read consent is required; messages are read as the signed-in user. Attachments and shared mailboxes are not searched.</p>
        <button type="button" disabled={adminBusy || !outlookEnabled} onClick={() => void checkOutlook()}>Check Outlook</button>
      </details>
      {postgresConfigured && <details className="source-setup" open={failedSource === 'postgres' || undefined}><summary>PostgreSQL · Advanced {postgresEnabled ? (postgresReadiness?.ready ? '· Ready for activation' : '· Selected · Setup pending') : '· Optional'}</summary>
        <h3 id="postgres-authorization">Database authorization</h3>
        <p className="muted">Connect using Dokploy credentials, match each Teams email to a database user, and apply that user's permissions. An administrator configures the adapter once.</p>
        <p className="muted">{sharedDatabaseCredentials ? 'Shared database credentials are configured.' : 'Add the service username and password to POSTGRES_DSN in Dokploy and redeploy to use automatic matching. The legacy per-user login flow remains available below.'}</p>
        <button type="button" disabled={adminBusy || !sharedDatabaseCredentials} onClick={() => void detectDatabaseMapping()}>Detect user mapping and prefill</button>
        {mappingMessage && <p role="status">{mappingMessage}</p>}
        {authorizationDiscovery && <div className="query-entry"><h4>Detected user mappings</h4>{authorizationDiscovery.candidates.map((candidate) => <div key={`${candidate.schema}.${candidate.relation}`}><strong>{candidate.schema}.{candidate.relation}</strong>{candidate.columns && <p className="muted">Detected fields: {candidate.columns.map((column) => column.name).join(', ')}.</p>}{(candidate.ready || candidateColumnMapping(candidate)) ? <button type="button" disabled={adminBusy} onClick={() => { const selected = { ...postgresAuth, schema: candidate.schema, relation: candidate.relation, columns: candidate.ready ? undefined : candidateColumnMapping(candidate) ?? undefined, roleMappings: undefined }; setPostgresAuth(selected); setPostgresAuthSaved(false); void detectRoleMappings(selected); setAdminMessage('Mapping fields filled from the selected relation. Review and save to check your access.'); }}>Use this mapping</button> : <p className="muted">Incomplete mapping: missing {candidate.missingColumns.join(', ') || 'supported schema or relation name'}.</p>}</div>)}{authorizationDiscovery.candidates.length === 0 && <p className="muted">No user mapping candidates on this metadata page.</p>}{authorizationDiscovery.nextSchema && <button type="button" disabled={adminBusy} onClick={() => void detectDatabaseMapping(true)}>Load next metadata page</button>}</div>}
        <form className="admin-form" onSubmit={(event) => void savePostgresAuth(event)}>
          <label>Permission system<select value={postgresAuth.mode} onChange={(event) => { setPostgresAuth({ ...postgresAuth, mode: event.target.value }); setPostgresAuthSaved(false); }}><option value="postgres_role">PostgreSQL roles and row policies</option><option value="session_context">Application auth with database row policies</option></select></label>
          <label>Authorization view schema<input value={postgresAuth.schema} onChange={(event) => { setPostgresAuth({ ...postgresAuth, schema: event.target.value }); setPostgresAuthSaved(false); }} maxLength={63} required placeholder="iqkb_auth" /></label>
          <label>Authorization view name<input value={postgresAuth.relation} onChange={(event) => { setPostgresAuth({ ...postgresAuth, relation: event.target.value }); setPostgresAuthSaved(false); }} maxLength={63} required placeholder="users" /></label>
          <details className="setup-details"><summary>Adapter view requirements</summary><p className="muted">The DBA-defined view translates your auth system into these columns: tenant_id, email, user_id, database_role, active (boolean), and permission_version. It must return exactly one user per tenant and email. The service login needs SELECT on this view and permission to switch to the returned restricted role. Application auth policies can read the transaction's iqkb user context and request.jwt.claims. Each permission change must update permission_version. Policies must enforce access in PostgreSQL; an application role label alone cannot restrict records.</p></details>
          {postgresAuth.columns && <div className="query-entry"><h4>Detected column mapping</h4>{(['email', 'userId', 'role', 'active', 'tenantId', 'permissionVersion'] as const).map((key) => <label key={key}>{({ email: 'Email column', userId: 'User ID column', role: 'Database execution role column', active: 'Active account column', tenantId: 'Tenant column (optional)', permissionVersion: 'Permission version column (optional)' })[key]}<input value={postgresAuth.columns?.[key] || ''} maxLength={63} required={['email', 'userId', 'role', 'active'].includes(key)} onChange={(event) => { setPostgresAuth({ ...postgresAuth, columns: { ...postgresAuth.columns!, [key]: event.target.value } }); setPostgresAuthSaved(false); }} /></label>)}<p className="muted">Without a tenant column, this mapping is restricted to your Microsoft tenant. Without a permission version column, changes to the user record invalidate prior profile tests. The role is checked against PostgreSQL before search access is granted.</p></div>}
          <div className="query-entry"><h4>Role translation</h4><p className="muted">Map each reviewed application label to a restricted execution role. You can save a completed label while leaving others unmapped; unmapped labels remain denied.</p><button type="button" disabled={adminBusy || !postgresAuth.schema || !postgresAuth.relation} onClick={() => void detectRoleMappings()}>Detect role values and permissions</button>{roleMappingMessage && <p role="status">{roleMappingMessage}</p>}{roleDiscovery && roleDiscovery.executionRoles.length > 0 && roleDiscovery.applicationRoles.map((role) => <label key={role}>{role}<select value={postgresAuth.roleMappings?.[role] || ''} onChange={(event) => { setPostgresAuth({ ...postgresAuth, roleMappings: { ...postgresAuth.roleMappings, [role]: event.target.value } }); setPostgresAuthSaved(false); }}><option value="">Select execution role</option>{roleDiscovery.executionRoles.map((execution) => <option key={execution.name} value={execution.name}>{execution.name} ({execution.policies} row policies)</option>)}</select></label>)}{roleDiscovery && roleDiscovery.executionRoles.length === 0 && <p role="status">Detected application roles: {roleDiscovery.applicationRoles.join(', ') || 'none'}. Saving is blocked until their actual permissions can be mapped to a restricted database execution role. Superuser, BYPASSRLS, table-owning, and ungranted roles are excluded.</p>}{roleDiscovery?.permissions && <div><h4>Detected permission structure</h4><p className="muted">These are discovered tables, relationships, and policies. Metadata candidates require review; no permissions are invented or granted.</p>{roleDiscovery.permissions.relations.map((item) => <details key={`${item.schema}.${item.relation}`}><summary>{item.schema}.{item.relation} — {item.evidence}</summary><p>Readable columns: {item.columns.join(', ')}.</p><p>Row security: {item.rlsEnabled ? 'enabled' : 'disabled'}{item.rlsForced ? ', forced' : ''}.</p></details>)}{roleDiscovery.permissions.relationships.map((link) => <p key={`${link.sourceSchema}.${link.sourceRelation}.${link.name}`}>{link.sourceSchema}.{link.sourceRelation} ({link.sourceColumns.join(', ')}) → {link.targetSchema}.{link.targetRelation} ({link.targetColumns.join(', ')})</p>)}{roleDiscovery.permissions.policies.map((policy) => <details key={`${policy.schema}.${policy.relation}.${policy.name}`}><summary>{policy.schema}.{policy.relation}: {policy.name} — {policy.rlsEnabled ? 'RLS enabled' : 'RLS disabled'}</summary><p>Applies to: {policy.roles.join(', ')}.</p>{policy.using && <pre>{policy.using}</pre>}{policy.check && <pre>{policy.check}</pre>}</details>)}{roleDiscovery.permissions.policies.length === 0 && <p>No readable database row policies were found. Application code permissions are not visible through database metadata.</p>}{roleDiscovery.permissions.truncated && <p role="status">Permission discovery reached its metadata limit; the displayed structure is incomplete.</p>}</div>}{roleDiscovery?.truncated && <p role="status">Role discovery was limited to 100 values. Review the complete permission mapping before saving.</p>}</div>
          {roleDiscovery && <PermissionRuleEditor identity={{ schema: postgresAuth.schema, relation: postgresAuth.relation, userId: postgresAuth.columns?.userId || 'user_id' }} relationships={roleDiscovery.permissions?.relationships || []} labels={roleDiscovery.applicationRoles} resources={roleDiscovery.permissions?.relations || []} api={api} />}
          <label>Review note (optional)<input value={postgresAuth.approvalRecord} onChange={(event) => { setPostgresAuth({ ...postgresAuth, approvalRecord: event.target.value }); setPostgresAuthSaved(false); }} maxLength={200} placeholder="Optional ticket or note" /></label>
          <p className="muted">Saving records your administrator identity and the review time automatically.</p>
          <button type="submit" disabled={adminBusy || !sharedDatabaseCredentials || (roleDiscovery !== null && (roleDiscovery.executionRoles.length === 0 || !roleDiscovery.applicationRoles.some((role) => !!postgresAuth.roleMappings?.[role])))}>{adminBusy ? 'Checking…' : postgresAuthSaved ? 'Save and recheck my access' : 'Save and check my access'}</button>
        </form>
        <label className="source-toggle"><input type="checkbox" checked={postgresEnabled} disabled={adminBusy} onChange={(event) => void togglePostgres(event.target.checked)} /> Enable PostgreSQL search</label>
        <div className="query-entry" aria-live="polite"><strong>{postgresEnabled ? postgresReadiness?.ready ? 'Ready for activation' : 'Selected — setup incomplete' : 'PostgreSQL search disabled'}</strong><p>{postgresSourceMessage || (postgresEnabled ? 'Check readiness to see what remains before PostgreSQL queries can run.' : 'Select this source to configure database search.')}</p>{postgresReadiness && !postgresReadiness.ready && postgresReadiness.next && <button type="button" disabled={adminBusy} onClick={() => void goToPostgresSetupStep()}>{({ 'postgres-permission-drafts': 'Review permission rules', 'postgres-authorization': 'Complete authorization mapping', 'database-access': 'Open database access', 'postgres-query-catalog': 'Configure searchable queries' } as Record<string, string>)[postgresReadiness.next] || 'Open required setup step'}</button>}</div>
        <p className="muted">Searches your organization's data using reviewed queries and the database connection configured by your administrator. Each query applies your resolved database role and authorization context. PostgreSQL OAuth is unsupported.</p>
        <button type="button" disabled={adminBusy || !postgresEnabled} onClick={() => void checkPostgres()}>Check readiness</button>
        <div className="button-row"><button type="button" disabled={adminBusy || !postgresEnabled} onClick={() => void discoverPostgres()}>Discover accessible schema</button></div>
        {postgresCredentialStatus?.status === 'email_confirmation_required' && <p role="status">Your database email must be verified before business metadata discovery. <a href="#database-access">Go to Verify my database email</a>.</p>}
        <p className="muted">Discovery lists only metadata visible to your resolved database role. It never reads sample rows. Only invoker-secure views with safe dependencies can be mapped; each profile access checks that the selected view key is non-null and unique, which may scan the view and time out on large views. Comments are untrusted database metadata; review them before using any description in a mapping.</p>
        {postgresDiscovery && <div className="query-entry"><h3>Accessible relations</h3>{postgresDiscovery.relations.map((relation) => { const keys = (postgresDiscovery.keys ?? []).filter((key) => key.schema === relation.schema && key.relation === relation.name); const relationships = (postgresDiscovery.relationships ?? []).filter((item) => item.sourceSchema === relation.schema && item.sourceRelation === relation.name); return <article key={`${relation.schema}.${relation.name}`}><strong>{relation.schema}.{relation.name}</strong> <span className="muted">{relation.kind}</span>{relation.reason && <p className="muted">{relation.reason}</p>}{relation.comment && <p>{relation.comment}</p>}{keys.length > 0 && <p>Keys: {keys.map((key) => `${key.kind} (${key.columns.join(', ')})`).join('; ')}</p>}{relationships.map((item) => <p key={item.name}>Relationship: {item.sourceColumns.join(', ')} → {item.targetSchema}.{item.targetRelation} ({item.targetColumns.join(', ')})</p>)}<ul>{postgresDiscovery.columns.filter((column) => column.schema === relation.schema && column.relation === relation.name).map((column) => <li key={column.name}><code>{column.name}</code> · {column.dataType}{column.nullable ? ' · nullable' : ''}{column.comment ? ` · ${column.comment}` : ''}</li>)}</ul></article>;})}{postgresDiscovery.nextSchema && <button type="button" disabled={adminBusy} onClick={() => void discoverPostgres(postgresDiscovery.nextSchema!, postgresDiscovery.nextName!, true)}>Load next metadata page</button>}
	          <h3>Map a business capability</h3><p className="muted">Choose metadata and business meanings you reviewed. No entities, aliases, relationships, or filter values are inferred.</p>
          <form className="admin-form" onSubmit={(event) => void saveBusinessProfile(event)}>
            <label>Profile ID<input value={profileId} onChange={(event) => setProfileId(event.target.value)} maxLength={63} required placeholder="asset_lookup" /></label>
            <label>Business label<input value={profileLabel} onChange={(event) => setProfileLabel(event.target.value)} maxLength={128} required /></label>
            <label>Confirmed aliases, comma separated<input value={profileSynonyms} onChange={(event) => setProfileSynonyms(event.target.value)} maxLength={512} placeholder="only terms confirmed by your team" /></label>
	            <label>Search capability<select value={profileCapability} onChange={(event) => setProfileCapability(event.target.value)}><option value="entity_lookup">Entity lookup</option><option value="text_search">Text search</option><option value="related_list">Related records with filters</option></select></label>
            {profileCapability === 'text_search' && <><label>Text search strategy<select value={profileSearchStrategy} onChange={(event) => setProfileSearchStrategy(event.target.value)}><option value="keyword">Keyword matching</option><option value="full_text">PostgreSQL full text</option></select></label>{profileSearchStrategy === 'full_text' && <label>PostgreSQL text-search language<select value={profileLanguage} onChange={(event) => setProfileLanguage(event.target.value)}>{['simple','danish','dutch','english','finnish','french','german','hungarian','italian','norwegian','portuguese','romanian','russian','spanish','swedish','turkish'].map((language) => <option key={language} value={language}>{language}</option>)}</select></label>}</>}
            <label>Accessible relation<select value={profileRelation} onChange={(event) => { setProfileRelation(event.target.value); setProfileReturnTypes({}); setProfileSourceURL(''); }} required><option value="">Choose a table or reviewed invoker view</option>{postgresDiscovery.relations.filter((item) => item.supported).map((item) => <option key={encodeRelationChoice(item.schema, item.name)} value={encodeRelationChoice(item.schema, item.name)}>{item.schema}.{item.name}</option>)}</select></label>
            <label>Unique key column<input value={profileKey} onChange={(event) => setProfileKey(event.target.value)} maxLength={63} required /></label>
            <label>Display column<input value={profileDisplay} onChange={(event) => setProfileDisplay(event.target.value)} maxLength={63} required /></label>
	            {profileCapability !== 'related_list' && <label>Text search columns<input value={profileSearchColumns} onChange={(event) => setProfileSearchColumns(event.target.value)} maxLength={512} required placeholder="display_name, reference" /></label>}
	            {profileCapability === 'related_list' && <fieldset><legend>Reviewed parent relationship and filters</legend>
	              <label>Discovered foreign key<select value={profileForeignKey} onChange={(event) => setProfileForeignKey(event.target.value)} required><option value="">Choose the child-to-parent relationship</option>{postgresDiscovery.relationships.filter((item) => item.sourceSchema === decodeRelationChoice(profileRelation)?.[0] && item.sourceRelation === decodeRelationChoice(profileRelation)?.[1] && item.sourceColumns.length === 1 && item.targetColumns.length === 1).map((item) => <option key={JSON.stringify([item.sourceSchema,item.sourceRelation,item.name])} value={JSON.stringify([item.sourceSchema,item.sourceRelation,item.name])}>{item.sourceColumns[0]} → {item.targetSchema}.{item.targetRelation}.{item.targetColumns[0]}</option>)}</select></label>
	              <label>Approved parent entity profile<select value={profileParentProfileId} onChange={(event) => setProfileParentProfileId(event.target.value)} required><option value="">Choose a saved entity lookup profile</option>{postgresProfiles.filter((item) => item.capability === 'entity_lookup' && item.id !== profileId).map((item) => <option key={item.id} value={item.id}>{item.label} · {item.id} v{item.version}</option>)}</select></label>
	              <label>Typed filters as reviewed JSON<textarea value={profileFiltersJSON} onChange={(event) => setProfileFiltersJSON(event.target.value)} rows={5} required aria-describedby="related-filter-help" /></label>
	              <p id="related-filter-help" className="muted">Example: <code>{'[{"name":"status","column":"status","type":"text","required":true,"values":[{"label":"Unpaid","value":"open"},{"label":"Paid","value":"closed"}]}]'}</code>. Required filters must be selected. Optional filters can be omitted and must use text values. Labels map to exact database values.</p>
	            </fieldset>}
            <fieldset><legend>Typed return columns</legend><p className="muted">Choose output fields and the value type to preserve. The preview checks selected types against PostgreSQL metadata.</p>{selectedProfileColumns.map((column) => <div className="button-row" key={column.name}><label><input type="checkbox" checked={Boolean(profileReturnTypes[column.name])} onChange={(event) => setProfileReturnTypes((current) => { const next = { ...current }; if (event.target.checked) next[column.name] = current[column.name] || 'text'; else delete next[column.name]; return next; })} /><code>{column.name}</code> · {column.dataType}</label><select aria-label={`Type for ${column.name}`} value={profileReturnTypes[column.name] || 'text'} disabled={!profileReturnTypes[column.name]} onChange={(event) => setProfileReturnTypes((current) => ({ ...current, [column.name]: event.target.value }))}><option value="text">Text</option><option value="integer">Integer</option><option value="number">Number</option><option value="boolean">Boolean</option><option value="date">Date</option><option value="timestamp">Timestamp</option></select></div>)}</fieldset>
            <label>Source URL column (optional)<select value={profileSourceURL} onChange={(event) => setProfileSourceURL(event.target.value)}><option value="">No source link</option>{selectedProfileColumns.filter((column) => profileReturnTypes[column.name] === 'text').map((column) => <option key={column.name} value={column.name}>{column.name}</option>)}</select></label>
            <p className="muted">Choose a selected text field containing HTTPS links. Unsafe or non-HTTPS values are omitted from citations.</p>
            <label>DBA approval record<input value={profileApproval} onChange={(event) => setProfileApproval(event.target.value)} maxLength={200} required placeholder="ticket or sign-off reference" /></label>
            <button type="button" disabled={adminBusy} onClick={() => void previewBusinessProfile()}>Preview generated SQL</button>
            {profilePreview && <div className="query-entry"><h4>Profile v{profilePreview.version} SQL preview{profilePreviewInput !== profileFormSignature() ? ' (stale)' : ''}</h4><p>{profilePreview.permissionExplanation}</p>{profilePreview.parentSQL && <><h5>Parent entity resolution</h5><p>Parameters: {profilePreview.parentParameters?.map((parameter) => `${parameter.name}:${parameter.type}`).join(', ')}</p><pre>{profilePreview.parentSQL}</pre></>}<h5>{profilePreview.parentSQL ? 'Related record query' : 'Generated query'}</h5><p>Parameters: {profilePreview.parameters.map((parameter) => `${parameter.name}:${parameter.type}`).join(', ')}</p><p>Output: {profilePreview.outputColumns.join(', ')}</p><pre>{profilePreview.sql}</pre>{profilePreviewInput !== profileFormSignature() && <p className="muted">The draft changed after preview. Generate a new preview before saving.</p>}</div>}
            <button type="submit" disabled={adminBusy || !profilePreview || profilePreviewInput !== profileFormSignature()}>Save versioned profile</button>
          </form>
        </div>}
        {!sharedDatabaseCredentials && <><h3>Legacy per-user database logins</h3><form className="admin-form" onSubmit={(event) => void savePostgresIdentity(event)}>
          <label>User Entra object ID<input value={postgresObjectId} onChange={(event) => setPostgresObjectId(event.target.value)} maxLength={36} required placeholder="GUID" /></label>
          <label>User verified organizational email<input type="email" value={postgresVerifiedEmail} onChange={(event) => setPostgresVerifiedEmail(event.target.value)} maxLength={254} required /></label>
          <label>Existing database login name<input value={postgresDatabaseIdentity} onChange={(event) => setPostgresDatabaseIdentity(event.target.value)} maxLength={63} required /></label>
          <button type="submit" disabled={adminBusy}>Review and save identity binding</button>
        </form>
        {postgresIdentities.length > 0 && <ul>{postgresIdentities.map((item) => <li key={item.objectId}>{item.verifiedEmail} → {item.databaseIdentity} <button type="button" disabled={adminBusy} onClick={() => void deletePostgresIdentity(item.objectId)}>Remove</button></li>)}</ul>}
        </>}
        <h3 id="postgres-query-catalog">Approved query catalog</h3>
        <p className="muted">The model sees only query IDs, descriptions, and parameter types. It cannot see or generate SQL. The application binds the user's question as <code>question:text</code> and validates <code>limit:integer[1,5]</code>. Every query must return <code>id</code>, <code>title</code>, <code>content</code>, and <code>source_url</code> as text.</p>
        {postgresQueries.map((query) => <article className="query-entry" key={query.id}>
          <strong>{query.id} v{query.version}</strong><p className="muted">{query.description} · {query.approvalRecord}</p><pre>{query.sql}</pre>
          <div className="button-row"><button type="button" disabled={adminBusy} onClick={() => editPostgresQuery(query)}>Edit next version</button><button type="button" disabled={adminBusy} onClick={() => void deletePostgresQuery(query.id)}>Remove</button></div>
        </article>)}
        {postgresProfileTests.length>0 && <div><h3>Profile test evidence</h3><ul>{postgresProfileTests.map((item)=><li key={`${item.profileId}:${item.objectId}`}>{item.profileId} v{item.version} · {item.databaseIdentity} · {item.status} · {item.testedAt}{item.category?` · ${item.category}`:''}</li>)}</ul></div>}
        <form className="admin-form" onSubmit={(event) => void savePostgresQuery(event)}>
          {postgresDiscovery && <label>Prefill from a discovered content relation<select value="" disabled={adminBusy} onChange={(event) => { const relation = decodeRelationChoice(event.target.value); if (relation) prefillQueryFromRelation(relation[0], relation[1]); }}><option value="">Choose a compatible relation to prefill the query</option>{postgresDiscovery.relations.filter((relation) => queryPrefill(relation, postgresDiscovery.columns)).map((relation) => <option key={encodeRelationChoice(relation.schema, relation.name)} value={encodeRelationChoice(relation.schema, relation.name)}>{relation.schema}.{relation.name}</option>)}</select></label>}
          <label>Query ID<input value={postgresToolId} onChange={(event) => setPostgresToolId(event.target.value)} maxLength={63} required placeholder="policy_search" /></label>
          <label>Description for the model (optional)<input value={postgresToolDescription} onChange={(event) => setPostgresToolDescription(event.target.value)} maxLength={512} placeholder="Generated automatically if left blank" /></label>
          <label>Fixed SELECT SQL<textarea value={postgresToolSQL} onChange={(event) => setPostgresToolSQL(event.target.value)} rows={7} required /></label>
          <label>Review note (optional)<input value={postgresToolApproval} onChange={(event) => setPostgresToolApproval(event.target.value)} maxLength={180} placeholder="Optional ticket or note" /></label>
          <button type="submit" disabled={adminBusy}>Save approved query version</button>
        </form>
      </details>}
      {!setup?.active && <><button type="button" disabled={adminBusy || !setup?.wizardReady} onClick={() => { setSetupStep(2); setAdminMessage(''); }}>Continue to activation</button>{!setup?.wizardReady && <p className="muted">Connect your provider and enable at least one source to continue.</p>}</>}
      </div>
      {!setup?.active && <div hidden={setupStep !== 2}>
        <h3>Ready to start asking questions</h3>
        <p className="muted">Enabled sources: {[sourceEnabled && 'OneDrive', sharePointEnabled && 'SharePoint', teamsChatsEnabled && 'Teams chats', teamsChannelsEnabled && 'Teams channels', outlookEnabled && 'Outlook', postgresEnabled && 'PostgreSQL'].filter(Boolean).join(', ') || 'None yet'}. Activation checks access to every enabled source.</p>
        {!setup?.wizardReady && <p role="status">Complete the provider connection and source selection first.</p>}
        <form className="admin-form" onSubmit={(event) => void activateSetup(event)}>
          <label>One-time setup secret<input id="bootstrap-secret" type="password" autoComplete="new-password" value={bootstrapSecret} onChange={(event) => setBootstrapSecret(event.target.value)} required /></label>
          <p className="muted">Use the bootstrap secret supplied by your deployment operator. This activates the workspace for your organization.</p>
          <button type="submit" disabled={adminBusy || !setup?.wizardReady}>{adminBusy ? 'Checking source access…' : 'Activate workspace'}</button>
        </form>
      </div>}
      {adminMessage && <p role="status">{adminMessage}</p>}
      <p className="muted">Answers are private to the signed-in user. Source text and questions are processed for each request and are not saved by IQ Knowledge.</p>
      </>}
    </section>}

    {setup?.active && <section className="ask-card">
      <h2>Ask connected sources</h2>
      <p className="muted">Choose Database, Microsoft, or both. Searches use enabled sources and your permissions; the question and matching excerpts are sent to your administrator’s model provider. IQ Knowledge does not save them. Microsoft and the provider apply their own data policies.</p>
      <form onSubmit={(event) => void ask(event)}>
        <label htmlFor="search-location">Where to search<select id="search-location" value={searchLocation} disabled={asking} onChange={(event) => setSearchLocation(event.target.value)}><option value="all">Database and Microsoft</option><option value="database">Database only</option><option value="microsoft">Microsoft only</option></select></label>
        <label htmlFor="question">Question</label>
        <textarea id="question" value={question} onChange={(event) => setQuestion(event.target.value)} maxLength={500} rows={3} required placeholder="Ask about a policy or document…" />
        <button type="submit" disabled={asking || !question.trim()}>{asking ? searchLocation === 'database' ? 'Searching database…' : searchLocation === 'microsoft' ? 'Searching Microsoft…' : 'Searching selected sources…' : 'Ask privately'}</button>
      </form>
      {askMessage && <p role="status">{askMessage}</p>}
      {searchDetails && <div className="query-entry" role="status">{searchDetails.scope !== 'microsoft' && <p>Database: {({ not_selected: 'not selected', disabled: 'not enabled', not_configured: 'connection not configured', no_authorized_queries: 'no usable approved queries; check your mapping, permissions, and query catalog', no_matching_query: 'no approved query matched this question', query_selection_failed: 'query selection failed', searched: 'query selected' } as Record<string, string>)[searchDetails.database] || searchDetails.database}.</p>}{searchDetails.sources?.map((source) => <p key={source.source}>{source.source === 'database' ? 'Database' : source.source}: {source.status.replaceAll('_', ' ')} · {source.results} results</p>)}{searchDetails.warning && <p>{searchDetails.warning}</p>}</div>}
      {answer && <div className="answer" aria-live="polite">
        {answer.clarification ? <><h3>Clarification needed</h3><p>{answer.clarification.question}</p><ul>{answer.clarification.candidates.map((candidate) => <li key={candidate.id}>{candidate.displayName} <span className="muted">({candidate.id})</span></li>)}</ul></> : <><h3>Answer</h3><p className="answer-text">{answer.answer}</p></>}
        {answer.sources.length > 0 && <><h3>Sources</h3><ul>{answer.sources.map((source) => <li key={source.id}>{source.kind && <strong>{source.kind === 'database' ? 'Database' : 'Microsoft'} · </strong>}{source.url ? <a href={source.url} target="_blank" rel="noreferrer">{source.name}</a> : source.name} <span>[{source.id}]</span></li>)}</ul></>}
      </div>}
    </section>}
    <footer>Answers use only connected sources and your organization’s access rules. Each answer is private to the signed-in account.</footer>
  </main>;
}

createRoot(document.getElementById('root')!).render(<React.StrictMode><App /></React.StrictMode>);
