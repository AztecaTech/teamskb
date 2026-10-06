import React, { useEffect, useState } from 'react';
import { createRoot } from 'react-dom/client';
import { app, authentication } from '@microsoft/teams-js';
import { decodeRelationChoice, encodeRelationChoice } from './relation-choice.mjs';
import './style.css';

type Session = { tenantId: string; objectId: string; role: 'Admin' | 'User'; active: boolean };
type SetupStatus = { active: boolean; wizardReady: boolean };
type ProviderStatus = { configured: boolean; apiKeyConfigured?: boolean; provider?: string; model?: string; baseUrl?: string };
type SourceStatus = { id: string; kind: string; boundary: string; enabled: boolean; siteUrls?: string[] };
type PostgresIdentity = { objectId: string; verifiedEmail: string; databaseIdentity: string; reviewedBy: string; reviewedAt: string };
type PostgresDiscovery = { relations: Array<{ schema: string; name: string; kind: string; supported: boolean; reason?: string; comment?: string }>; columns: Array<{ schema: string; relation: string; name: string; dataType: string; nullable: boolean; comment?: string }>; keys: Array<{ schema: string; relation: string; kind: string; columns: string[] }>; relationships: Array<{ name: string; sourceSchema: string; sourceRelation: string; sourceColumns: string[]; targetSchema: string; targetRelation: string; targetColumns: string[] }>; nextSchema?: string; nextName?: string };
type PostgresQuery = { id: string; version: number; description: string; sql: string; parameters: Array<{ name: string; type: string }>; outputColumns: string[]; approvalRecord: string };
type PostgresCredentialStatus = { available: boolean; mapped: boolean; configured: boolean; verifiedEmail: string };
type PostgresProfileSummary = { id: string; version: number; label: string; capability: string };
type PostgresProfileTest = { profileId: string; version: number; objectId: string; databaseIdentity: string; testedAt: string; status: string; category: string };
type PostgresProfilePreview = { version: number; sql: string; parameters: Array<{ name: string; type: string }>; outputColumns: string[]; parentSQL?: string; parentParameters?: Array<{ name: string; type: string }>; approvalRecord: string; permissionExplanation: string };
type AskResult = { answer?: string; sources: Array<{ id: string; name: string; url: string }>; clarification?: { kind: string; question: string; candidates: Array<{ id: string; displayName: string }> } };

function App() {
  const [message, setMessage] = useState('Connecting to Microsoft Teams…');
  const [session, setSession] = useState<Session | null>(null);
  const [setup, setSetup] = useState<SetupStatus | null>(null);
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
  const [postgresEnabled, setPostgresEnabled] = useState(false);
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
  const [postgresCredentialMessage, setPostgresCredentialMessage] = useState('');
  const [adminMessage, setAdminMessage] = useState('');
  const [adminBusy, setAdminBusy] = useState(false);
  const [bootstrapSecret, setBootstrapSecret] = useState('');
  const [question, setQuestion] = useState('');
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
      try {
        await app.initialize();
        const response = await api('/api/session');
        if (!response.ok) throw new Error('Sign-in was not accepted.');
        const current = await response.json() as Session;
        if (disposed) return;
        setSession(current);
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
        if (setupResponse.ok) setSetup(await setupResponse.json() as SetupStatus);
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
        if (identityResponse.ok) setPostgresIdentities((await identityResponse.json() as { identities: PostgresIdentity[] }).identities);
        if (queryResponse.ok) setPostgresQueries((await queryResponse.json() as { queries: PostgresQuery[] }).queries);
        const profileTestsResponse = await api('/api/admin/postgres/profile-tests');
        if (profileTestsResponse.ok) setPostgresProfileTests((await profileTestsResponse.json() as { tests: PostgresProfileTest[] }).tests);
      } catch {
        if (!disposed) setMessage('Open this app inside Microsoft Teams and confirm your organization has configured single sign-on.');
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
      setAdminMessage(`Provider settings saved. Set the provider key in operator configuration, then test the connection before ${setup?.active ? 'asking questions' : 'activating setup'}.`);
      setSetup((current) => current ? { ...current, wizardReady: false } : current);
    } catch (error) {
      setAdminMessage(error instanceof Error ? error.message : 'Provider could not be saved.');
    } finally {
      setAdminBusy(false);
    }
  }

  async function testProvider() {
    setAdminBusy(true);
    setAdminMessage('');
    try {
      const response = await api('/api/admin/provider/check', { method: 'POST' });
      if (!response.ok) throw new Error('The model provider check failed. Verify its settings and the operator-managed provider key.');
      setAdminMessage('Model provider connected.');
      const statusResponse = await api('/api/setup/status');
      if (statusResponse.ok) setSetup(await statusResponse.json() as SetupStatus);
    } catch (error) {
      setAdminMessage(error instanceof Error ? error.message : 'The model provider check failed.');
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
      if (!response.ok) throw new Error(response.status === 424 ? 'Grant delegated Team.ReadBasic.All, Channel.ReadBasic.All, and ChannelMessage.Read.All consent, then check again.' : 'The administrator’s joined Teams channels could not be accessed.');
      setAdminMessage('Connected to the administrator’s joined Teams channels.');
    } catch (error) {
      setAdminMessage(error instanceof Error ? error.message : 'Teams channel access check failed.');
    } finally {
      setAdminBusy(false);
    }
  }

  async function togglePostgres(enabled: boolean) {
    setAdminBusy(true);
    setAdminMessage('');
    try {
      const response = await api('/api/admin/sources/postgres', { method: 'PUT', body: JSON.stringify({ enabled }) });
      if (!response.ok) throw new Error('The PostgreSQL source setting could not be saved.');
      setPostgresEnabled(enabled);
      const statusResponse = await api('/api/setup/status');
      if (statusResponse.ok) setSetup(await statusResponse.json() as SetupStatus);
      setAdminMessage(enabled ? 'PostgreSQL search enabled. Map each user to an existing database login and have each user save their own password.' : 'PostgreSQL search disabled.');
    } catch (error) {
      setAdminMessage(error instanceof Error ? error.message : 'The PostgreSQL source setting could not be saved.');
    } finally {
      setAdminBusy(false);
    }
  }

  async function discoverPostgres(afterSchema = '', afterName = '', append = false) {
    setAdminBusy(true); setAdminMessage('');
    try {
      const query = afterSchema ? `?afterSchema=${encodeURIComponent(afterSchema)}&afterName=${encodeURIComponent(afterName)}` : '';
      const response = await api(`/api/admin/postgres/discovery${query}`);
      if (!response.ok) throw new Error('Metadata discovery needs an unambiguous admin login with PostgreSQL SELECT access and saved credentials.');
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

  async function checkPostgres() {
    setAdminBusy(true);
    setAdminMessage('');
    try {
      const response = await api('/api/admin/checks/postgres', { method: 'POST' });
      if (!response.ok) throw new Error(response.status === 409 ? 'Add a reviewed identity binding, save your own database password, and approve at least one query.' : 'Your database login or an approved query check failed.');
      setAdminMessage('The authenticated database identity and approved queries passed.');
    } catch (error) {
      setAdminMessage(error instanceof Error ? error.message : 'PostgreSQL check failed.');
    } finally {
      setAdminBusy(false);
    }
  }

  async function savePostgresIdentity(event: React.FormEvent) {
    event.preventDefault();
    setAdminBusy(true);
    setAdminMessage('');
    try {
      const response = await api('/api/admin/postgres/identities', {
        method: 'PUT', body: JSON.stringify({ objectId: postgresObjectId, verifiedEmail: postgresVerifiedEmail, databaseIdentity: postgresDatabaseIdentity }),
      });
      if (!response.ok) throw new Error(response.status === 409 ? 'That verified email is already bound to another account.' : 'Check the verified email, object ID, and existing database login name.');
      const saved = await response.json() as PostgresIdentity;
      setPostgresIdentities((items) => [...items.filter((item) => item.objectId !== saved.objectId), saved].sort((a, b) => a.objectId.localeCompare(b.objectId)));
      setPostgresObjectId('');
      setPostgresVerifiedEmail('');
      setPostgresDatabaseIdentity('');
      setAdminMessage('Existing database identity binding saved and reviewed. The user must save their own database password again.');
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
      if(!response.ok) throw new Error('This profile did not pass for your database login. Contact an administrator to review permissions or schema status.');
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
    try {
      const response = await api('/api/setup/activate', {
        method: 'POST', headers: { 'X-Setup-Secret': bootstrapSecret },
      });
      if (!response.ok) throw new Error(response.status === 424 ? 'A connected source or setup check failed.' : 'Setup is not ready or the bootstrap secret is invalid.');
      setBootstrapSecret('');
      setSetup({ active: true, wizardReady: true });
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
    try {
      const response = await api('/api/ask', { method: 'POST', body: JSON.stringify({ question }) });
      const result = await response.json() as AskResult & { error?: string };
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

    {session && postgresCredentialStatus?.available && postgresCredentialStatus.mapped && <section className="setup-card">
      <h2>Your PostgreSQL sign-in</h2>
      <p className="muted">Your verified account {postgresCredentialStatus.verifiedEmail} is bound to an existing database login. Enter your own database password; it is encrypted for your account and used only for your searches.</p>
      <form className="admin-form" onSubmit={(event) => void savePostgresPassword(event)}>
        <label>Your database password<input type="password" autoComplete="current-password" value={postgresPassword} onChange={(event) => setPostgresPassword(event.target.value)} maxLength={4096} required /></label>
        <div className="button-row"><button type="submit" disabled={adminBusy || !postgresPassword}>Verify and save password</button>{postgresCredentialStatus.configured && <button type="button" disabled={adminBusy} onClick={() => void deletePostgresPassword()}>Remove saved password</button>}</div>
      </form>
      {postgresCredentialMessage && <p role="status">{postgresCredentialMessage}</p>}
      {postgresCredentialStatus.configured && postgresProfiles.length>0 && <div><h3>Business profile tests</h3><p className="muted">Tests run as your own mapped login and discard returned rows. Administrators require passing evidence from two different users before activating profiles.</p>{postgresProfiles.map((profile)=><div className="button-row" key={profile.id}><span>{profile.label} v{profile.version}</span><button type="button" disabled={adminBusy} onClick={()=>void testPostgresProfile(profile.id)}>Test as my login</button></div>)}</div>}
    </section>}

    {session?.role === 'Admin' && <section className="setup-card">
      <h2>Workspace setup</h2>
      <p>{setup?.active ? 'Workspace is active.' : setup?.wizardReady ? 'Checks passed. Enter the one-time bootstrap secret to activate.' : 'Configure and check a provider, then choose a source.'}</p>
      <form className="admin-form" onSubmit={(event) => void saveProvider(event)}>
        <label>Model provider<select value={provider} onChange={(event) => setProvider(event.target.value)}>
          <option value="openai">OpenAI</option><option value="openai_compatible">OpenAI-compatible endpoint</option><option value="anthropic">Anthropic</option>
        </select></label>
        <label>Model name<input value={model} onChange={(event) => setModel(event.target.value)} maxLength={128} required /></label>
        {provider === 'openai_compatible' && <label>HTTPS base URL<input type="url" value={baseUrl} onChange={(event) => setBaseUrl(event.target.value)} placeholder="https://provider.example/v1" required /></label>}
        <p className="muted">Each answer sends the question and selected source excerpts to this provider. Before activation, review retention, training use, and region for the exact account, endpoint, and model; the synthetic connection check does not verify those settings.</p>
        <p className="muted">Provider keys come from the operator-managed MODEL_API_KEY setting in local development or the model_api_key mounted secret in Docker. They are never sent from this page or stored in SQLite. {providerKeyConfigured ? 'A key is configured.' : 'No provider key is configured yet.'}</p>
        <div className="button-row"><button type="submit" disabled={adminBusy}>Save provider</button><button type="button" disabled={adminBusy || !model} onClick={() => void testProvider()}>Test provider</button></div>
      </form>
      <label className="source-toggle"><input type="checkbox" checked={sourceEnabled} disabled={adminBusy} onChange={(event) => void toggleOneDrive(event.target.checked)} /> Enable search in each user’s own OneDrive</label>
      <div className="source-setup">
        <label>SharePoint site URLs<textarea value={sharePointSiteUrls} onChange={(event) => setSharePointSiteUrls(event.target.value)} rows={3} placeholder="https://contoso.sharepoint.com/sites/Research" disabled={adminBusy} /></label>
        <p className="muted">One site per line, up to five. Searches each site’s default document library. Delegated Sites.Read.All consent is required; each user’s access is checked when searching and downloading.</p>
        <div className="button-row">
          <button type="button" disabled={adminBusy || !sharePointSiteUrls.trim()} onClick={() => void saveSharePoint(true)}>Save and enable</button>
          <button type="button" disabled={adminBusy || !sharePointEnabled} onClick={() => void checkSharePoint()}>Check SharePoint</button>
          <button type="button" disabled={adminBusy || !sharePointEnabled} onClick={() => void saveSharePoint(false)}>Disable</button>
        </div>
      </div>
      <div className="source-setup">
        <label className="source-toggle"><input type="checkbox" checked={teamsChatsEnabled} disabled={adminBusy} onChange={(event) => void toggleTeamsChats(event.target.checked)} /> Enable search in each user’s Teams chats</label>
        <p className="muted">Searches recent messages in the user’s private and group chats (up to ten chats and twenty messages per chat). Delegated Chat.Read consent is required. Channel messages are not included.</p>
        <button type="button" disabled={adminBusy || !teamsChatsEnabled} onClick={() => void checkTeamsChats()}>Check Teams chats</button>
      </div>
      <div className="source-setup">
        <label className="source-toggle"><input type="checkbox" checked={teamsChannelsEnabled} disabled={adminBusy} onChange={(event) => void toggleTeamsChannels(event.target.checked)} /> Enable search in each user’s joined Teams channels</label>
        <p className="muted">Searches up to five joined teams, five channels per team, and twenty recent root messages per channel. Delegated Team.ReadBasic.All, Channel.ReadBasic.All, and ChannelMessage.Read.All consent is required. Users’ channel membership is checked by Graph.</p>
        <button type="button" disabled={adminBusy || !teamsChannelsEnabled} onClick={() => void checkTeamsChannels()}>Check Teams channels</button>
      </div>
      <div className="source-setup">
        <label className="source-toggle"><input type="checkbox" checked={outlookEnabled} disabled={adminBusy} onChange={(event) => void toggleOutlook(event.target.checked)} /> Enable search in each user’s own Outlook mailbox</label>
        <p className="muted">Searches a few matching message subjects and text bodies. Delegated Mail.Read consent is required; messages are read as the signed-in user. Attachments and shared mailboxes are not searched.</p>
        <button type="button" disabled={adminBusy || !outlookEnabled} onClick={() => void checkOutlook()}>Check Outlook</button>
      </div>
      {postgresConfigured && <div className="source-setup">
        <label className="source-toggle"><input type="checkbox" checked={postgresEnabled} disabled={adminBusy} onChange={(event) => void togglePostgres(event.target.checked)} /> Enable PostgreSQL search</label>
        <p className="muted">Searches your organization's existing data using versioned DBA-approved SELECT queries. Each search uses your own database login and password over verified TLS; existing grants and row-level security remain authoritative. PostgreSQL OAuth is unsupported.</p>
        <button type="button" disabled={adminBusy || !postgresEnabled} onClick={() => void checkPostgres()}>Check my login and approved queries</button>
        <div className="button-row"><button type="button" disabled={adminBusy || !postgresEnabled} onClick={() => void discoverPostgres()}>Discover accessible schema</button></div>
        <p className="muted">Discovery lists only metadata visible to your own database login. It never reads sample rows. Only invoker-secure views with safe dependencies can be mapped; each profile access checks that the selected view key is non-null and unique, which may scan the view and time out on large views. Comments are untrusted database metadata; review them before using any description in a mapping.</p>
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
        <form className="admin-form" onSubmit={(event) => void savePostgresIdentity(event)}>
          <label>User Entra object ID<input value={postgresObjectId} onChange={(event) => setPostgresObjectId(event.target.value)} maxLength={36} required placeholder="GUID" /></label>
          <label>User verified organizational email<input type="email" value={postgresVerifiedEmail} onChange={(event) => setPostgresVerifiedEmail(event.target.value)} maxLength={254} required /></label>
          <label>Existing database login name<input value={postgresDatabaseIdentity} onChange={(event) => setPostgresDatabaseIdentity(event.target.value)} maxLength={63} required /></label>
          <button type="submit" disabled={adminBusy}>Review and save identity binding</button>
        </form>
        {postgresIdentities.length > 0 && <ul>{postgresIdentities.map((item) => <li key={item.objectId}>{item.verifiedEmail} → {item.databaseIdentity} <button type="button" disabled={adminBusy} onClick={() => void deletePostgresIdentity(item.objectId)}>Remove</button></li>)}</ul>}
        <h3>Approved query catalog</h3>
        <p className="muted">The model sees only query IDs, descriptions, and parameter types. It cannot see or generate SQL. The application binds the user's question as <code>question:text</code> and validates <code>limit:integer[1,5]</code>. Every query must return <code>id</code>, <code>title</code>, <code>content</code>, and <code>source_url</code> as text.</p>
        {postgresQueries.map((query) => <article className="query-entry" key={query.id}>
          <strong>{query.id} v{query.version}</strong><p className="muted">{query.description} · {query.approvalRecord}</p><pre>{query.sql}</pre>
          <div className="button-row"><button type="button" disabled={adminBusy} onClick={() => editPostgresQuery(query)}>Edit next version</button><button type="button" disabled={adminBusy} onClick={() => void deletePostgresQuery(query.id)}>Remove</button></div>
        </article>)}
        {postgresProfileTests.length>0 && <div><h3>Profile test evidence</h3><ul>{postgresProfileTests.map((item)=><li key={`${item.profileId}:${item.objectId}`}>{item.profileId} v{item.version} · {item.databaseIdentity} · {item.status} · {item.testedAt}{item.category?` · ${item.category}`:''}</li>)}</ul></div>}
        <form className="admin-form" onSubmit={(event) => void savePostgresQuery(event)}>
          <label>Query ID<input value={postgresToolId} onChange={(event) => setPostgresToolId(event.target.value)} maxLength={63} required placeholder="policy_search" /></label>
          <label>Description for the model<input value={postgresToolDescription} onChange={(event) => setPostgresToolDescription(event.target.value)} maxLength={512} required /></label>
          <label>Fixed SELECT SQL<textarea value={postgresToolSQL} onChange={(event) => setPostgresToolSQL(event.target.value)} rows={7} required /></label>
          <label>DBA approval record<input value={postgresToolApproval} onChange={(event) => setPostgresToolApproval(event.target.value)} maxLength={180} required placeholder="Change ticket or approval record" /></label>
          <button type="submit" disabled={adminBusy}>Save approved query version</button>
        </form>
      </div>}
      {!setup?.active && <form className="admin-form" onSubmit={(event) => void activateSetup(event)}>
        <label>One-time bootstrap secret<input id="bootstrap-secret" type="password" autoComplete="new-password" value={bootstrapSecret} onChange={(event) => setBootstrapSecret(event.target.value)} required /></label>
        <button type="submit" disabled={adminBusy || !setup?.wizardReady}>Activate workspace</button>
      </form>}
      {adminMessage && <p role="status">{adminMessage}</p>}
      <p className="muted">Answers are private to the signed-in user. Source text and questions are processed for each request and are not saved by IQ Knowledge.</p>
    </section>}

    {setup?.active && <section className="ask-card">
      <h2>Ask connected sources</h2>
      <p className="muted">Your question is searched against enabled sources; the question and selected excerpts from connected Microsoft and optional PostgreSQL sources are sent to your administrator’s model provider. IQ-kbteams does not save them, but Microsoft and the provider apply their own data policies. Personal bot messages and replies are subject to your tenant’s Teams retention policy.</p>
      <form onSubmit={(event) => void ask(event)}>
        <label htmlFor="question">Question</label>
        <textarea id="question" value={question} onChange={(event) => setQuestion(event.target.value)} maxLength={500} rows={3} required placeholder="Ask about a policy or document…" />
        <button type="submit" disabled={asking || !question.trim()}>{asking ? 'Searching connected sources…' : 'Ask privately'}</button>
      </form>
      {askMessage && <p role="status">{askMessage}</p>}
      {answer && <div className="answer" aria-live="polite">
        {answer.clarification ? <><h3>Clarification needed</h3><p>{answer.clarification.question}</p><ul>{answer.clarification.candidates.map((candidate) => <li key={candidate.id}>{candidate.displayName} <span className="muted">({candidate.id})</span></li>)}</ul></> : <><h3>Answer</h3><p className="answer-text">{answer.answer}</p></>}
        {answer.sources.length > 0 && <><h3>Sources</h3><ul>{answer.sources.map((source) => <li key={source.id}>{source.url ? <a href={source.url} target="_blank" rel="noreferrer">{source.name}</a> : source.name} <span>[{source.id}]</span></li>)}</ul></>}
      </div>}
    </section>}
    <footer>Answers use only connected sources and your organization’s access rules. Each answer is private to the signed-in account.</footer>
  </main>;
}

createRoot(document.getElementById('root')!).render(<React.StrictMode><App /></React.StrictMode>);
