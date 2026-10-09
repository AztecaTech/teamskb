// Run with a locally installed Playwright module and browser. This fixture never
// contacts Microsoft or a real database; API authorization is tested separately.
import assert from 'node:assert/strict';
import { createServer } from 'vite';
import react from '@vitejs/plugin-react';
import { fileURLToPath, pathToFileURL } from 'node:url';
import path from 'node:path';

const playwrightModule = process.argv[2] ? await import(pathToFileURL(path.resolve(process.argv[2])).href) : await import('playwright');
const playwright = playwrightModule.default || playwrightModule;
const root = fileURLToPath(new URL('..', import.meta.url));
const server = await createServer({ root, configFile: false, plugins: [react(), {
  name: 'fixture-teams-identity', enforce: 'pre',
  resolveId(id) { if (id === '@microsoft/teams-js') return '\0fixture-teams'; },
  load(id) { if (id === '\0fixture-teams') return 'export const app={initialize:async()=>{}};export const authentication={getAuthToken:async()=>"synthetic-ui-fixture"};'; },
}], optimizeDeps: { exclude: ['@microsoft/teams-js'] }, server: { host: '127.0.0.1', port: 0 } });

let browser, debugPage;
const debug = {};
try {
  await server.listen();
  const address = server.httpServer.address();
  browser = await playwright.chromium.launch({ headless: true, ...(process.argv[3] ? { executablePath: process.argv[3] } : {}) });
  const page = await browser.newPage({viewport:process.argv.includes('--mobile')?{width:390,height:844}:{width:1280,height:1000}});
  debugPage = page;
  page.setDefaultTimeout(12000);
  const errors = []; page.on('pageerror', (error) => errors.push(error.message));
  let adapter = { mode: 'application_rules', schema: 'custom', relation: 'accounts', approvalRecord: 'fixture', columns: { email: 'email', userId: 'id', role: 'label', active: 'enabled' }, rules: [] };
  const automatic = process.argv.includes('--automatic');
  const simple = process.argv.includes('--simple');
  if (process.argv.includes('--simple-fresh')) { adapter.schema=''; adapter.relation=''; adapter.columns=undefined; }
  adapter.permissionSource = automatic ? 'external' : 'internal';
  let nativeDenied = false;
  let holdNextPreview = false;
  let releaseHeldPreview;
  let notifyPreviewHeld;
  const previewHeld = new Promise((resolve) => { notifyPreviewHeld = resolve; });
  const nativeRules = [{label:'Operators',schema:'custom',relation:'records',fields:['record_key','caption','content'],scope:{kind:'user',column:'owner_key'},reviewed:true}];
  const localSaved = process.argv.includes('--internal-saved');
  if (localSaved) adapter.rules = nativeRules;
  let status = process.argv.includes('--unconfirmed') ? 'email_confirmation_required' : 'matched_permissions_required';
  let profile;
  let tests = 0;
  let emailChecks = 0;
  let pagesLoaded = 0;
  const requests = [];
  debug.errors=errors;debug.requests=requests;
  const resources = [...Array.from({length:25},(_,i)=>({schema:'custom',relation:`resource_${i+1}`,columns:['id','caption'],scalarColumns:['id','caption']})),{schema:'custom',relation:'records',columns:['record_key','caption','content','owner_key'],scalarColumns:['record_key','caption','content','owner_key']}];
  resources[25].searchProfile={id:'table_synthetic',keyColumn:'record_key',labelColumn:'caption',searchColumns:['caption','content'],returnColumns:[{name:'caption',type:'text'},{name:'content',type:'text'}]};
  const metadata = { relations:[{schema:'custom',name:'records',kind:'BASE TABLE',supported:true}],columns:['record_key','caption','content'].map((name)=>({schema:'custom',relation:'records',name,dataType:name==='record_key'?'integer':'text',nullable:false})),keys:[{schema:'custom',relation:'records',kind:'primary',columns:['record_key']}],relationships:[] };
  await page.route('**/api/**',async(route)=>{
    const request=route.request();const url=new URL(request.url());const method=request.method();const data=request.postDataJSON();requests.push(`${method} ${url.pathname}`);
    let result;let code=200;
    switch(url.pathname){
      case '/api/session':result={tenantId:'tenant',objectId:'actor',role:'Admin',active:false};break;
      case '/api/setup/status':result={active:false,wizardReady:true};break;
      case '/api/admin/provider':result={configured:true,apiKeyConfigured:true,provider:'openai',model:'fixture-model'};break;
      case '/api/admin/sources':result={sources:[{id:'user-postgres',kind:'postgres',enabled:true}]};break;
      case '/api/admin/postgres/status':result={configured:true};break;
      case '/api/admin/postgres/identities':result={identities:[]};break;
      case '/api/admin/postgres/queries':result={queries:profile?[{id:profile.id,version:1,description:profile.label,sql:'compiled fixture SELECT',approvalRecord:'actor review'}]:[]};break;
      case '/api/admin/postgres/profile-tests':result={tests:[]};break;
      case '/api/admin/postgres/auth':
        if(method==='PUT'){adapter=automatic?{...data,rules:[],claims:{}}:data;status='email_confirmation_required';result=adapter;}else result={adapter,sharedCredentialsConfigured:true};break;
      case '/api/admin/postgres/auth/discovery':result={candidates:[{schema:'custom',relation:'accounts',ready:false,columns:[{name:'id',dataType:'integer'},{name:'email',dataType:'text'},{name:'label',dataType:'text'},{name:'enabled',dataType:'boolean'}]}]};break;
      case '/api/admin/postgres/auth/labels':assert.equal(data.schema,'custom');assert.equal(data.relation,'accounts');result={roles:['Operators','Other label'],currentRole:'Operators'};break;
      case '/api/admin/postgres/auth/quick-setup':
        assert.equal(data.email,'person@example.com');assert.deepEqual(data.resources,[{schema:'custom',relation:'records',roles:['Operators','Other label']}]);
        adapter={...data.mapping,roleLabelAccess:true,permissionSource:'internal',rules:data.resources.flatMap((table)=>table.roles.map((label)=>({label,schema:table.schema,relation:table.relation,fields:['record_key','caption','content'],scope:{kind:'all'},reviewed:true})))};
        profile={id:'table_synthetic',label:'records',capability:'text_search'};tests++;emailChecks++;status='connected';result={status,adapter,tables:1};break;
      case '/api/admin/sources/postgres':assert.equal(data.enabled,true);result={enabled:true};break;
      case '/api/admin/postgres/auth/check':
        if(!automatic && !adapter.rules.some((rule)=>rule.label==='Operators'&&rule.reviewed)){code=424;result={error:'application_permission_rules_required'};}else result={userId:'7',databaseRole:'Operators',applicationRole:'Operators',authorizationMode:'application_rules'};break;
      case '/api/postgres/credentials':result={available:true,mapped:status==='connected',configured:status==='connected',status,verifiedEmail:'person@example.com',applicationRole:status==='email_confirmation_required'?'':'Operators',userId:'7',authorizationMode:'application_rules',mode:'shared-adapter',roleLabelAccess:!!adapter.roleLabelAccess};break;
      case '/api/postgres/email':
        emailChecks++;assert.equal(data.email,'person@example.com');status=automatic || adapter.rules.some((rule)=>rule.label==='Operators'&&rule.reviewed)?'connected':'matched_permissions_required';result={status,userId:'7',applicationRole:'Operators',authorizationMode:'application_rules'};break;
      case '/api/postgres/profiles':result={profiles:profile?[{id:profile.id,label:profile.label,version:1,capability:profile.capability}]:[]};break;
      case '/api/admin/postgres/auth/resources':pagesLoaded++;result=url.searchParams.has('afterSchema')?{resources:resources.slice(25)}:{resources:resources.slice(0,25),nextSchema:'custom',nextName:'resource_25'};break;
      case '/api/admin/postgres/auth/permissions':
        if(nativeDenied){code=424;result={configured:true,mode:'external',error:'permission_source_denied'};}else result=automatic?{configured:true,mode:'external',status:'resolved',userId:'7',label:'Operators',rules:nativeRules}:{configured:true,mode:'internal',status:adapter.rules.some((rule)=>rule.reviewed)?'resolved':'internal_rules_required',userId:'7',label:'Operators',rules:adapter.rules.filter((rule)=>rule.label==='Operators'&&rule.reviewed)};
        if (holdNextPreview) {
          holdNextPreview = false;
          await new Promise((resolve) => { releaseHeldPreview = resolve; notifyPreviewHeld(); });
        }
        break;
      case '/api/admin/postgres/auth/roles':result={applicationRoles:['Operators','Other label'],executionRoles:[],truncated:false};break;
      case '/api/admin/postgres/discovery':assert.equal(status,'connected');result=metadata;break;
      case '/api/admin/postgres/profiles/preview':result={version:1,sql:'compiled fixture SELECT',parameters:[],outputColumns:[],permissionExplanation:'Reviewed row and field rules apply.'};break;
      case '/api/admin/postgres/profiles':profile=data;assert.equal(data.approval,'');result={id:profile.id,version:1};break;
      case '/api/admin/postgres/readiness':result=simple&&profile?{enabled:true,ready:true,state:'ready',message:'Database search is ready.',queries:1}:{enabled:true,ready:false,state:profile?'second_user_test_required':status==='connected'?'approved_query_required':'application_resource_required',message:profile?'A second distinct database user must test.':'Configure the required resource and profile.',next:profile?'database-access':status==='connected'?'business-search-profile':'application-permissions',queries:profile?1:0};break;
      default:
        if(url.pathname.startsWith('/api/postgres/profiles/')&&url.pathname.endsWith('/test')){tests++;result={status:'passed'};}else{code=404;result={error:'unexpected_fixture_route'};errors.push(`${method} ${url.pathname}`);}
    }
    await route.fulfill({status:code,contentType:'application/json',body:JSON.stringify(result)});
  });
  await page.goto(`http://127.0.0.1:${address.port}`);
  await page.getByRole('button',{name:/^2\s*Sources$/}).click();
  await page.locator('details.source-setup').filter({has:page.locator('summary',{hasText:/^PostgreSQL/})}).locator('summary').first().click();
  if (simple) {
    await page.getByLabel('Search custom.records',{exact:true}).waitFor();
    assert.equal(await page.getByLabel('Database email',{exact:true}).inputValue(),'person@example.com');
    assert.equal(await page.getByRole('button',{name:'Save and connect',exact:true}).isDisabled(),true);
    assert.equal(await page.getByLabel('Permission system').count(),0,'technical adapter questions must be closed');
    assert.equal(await page.getByLabel('Unique key column').count(),0,'search profiles must be automatic');
    assert.equal(await page.getByLabel('Search custom.records',{exact:true}).isChecked(),false,'no table is granted by a role name alone');
    await page.getByLabel('Search custom.records',{exact:true}).check();
    const choices=page.locator('#postgres-quick-setup fieldset');
    assert.equal(await choices.getByLabel('Operators',{exact:true}).isChecked(),true,'selecting a table grants the matched role explicitly');
    assert.equal(await choices.getByLabel('Other label',{exact:true}).isChecked(),false,'other labels must not acquire access implicitly');
    await choices.getByLabel('Other label',{exact:true}).check();
    const screenshot=process.argv.find((argument)=>argument.startsWith('--screenshot='));
    if(screenshot) await page.screenshot({path:screenshot.slice('--screenshot='.length),fullPage:true});
    await page.getByRole('button',{name:'Save and connect',exact:true}).click();
    await page.getByText('Database search is ready.',{exact:true}).waitFor();
    await page.getByLabel('Search custom.records',{exact:true}).waitFor();
    assert.equal(await page.getByLabel('Search custom.records',{exact:true}).isChecked(),true,'saved table selection must be reused');
    assert.equal(await choices.getByLabel('Other label',{exact:true}).isChecked(),true,'saved role selections must be reused');
    assert.equal(tests,1,'the save action tests the prepared search configuration');
    assert.equal(emailChecks,1,'the save action confirms the same Microsoft email');
    assert.equal(await page.getByLabel('Permission system').count(),0,'connected setup must remain simple');
    assert.ok(pagesLoaded>=2,'later catalog pages must be recognized');
    assert.deepEqual(adapter.rules.map((rule)=>rule.label),['Operators','Other label']);
    assert.ok(adapter.rules.every((rule)=>rule.scope.kind==='all'&&rule.reviewed));
    assert.equal(requests.some((request)=>request.includes('/profiles/preview')),false,'no manual profile preview required');
    assert.deepEqual(errors,[]);
    console.log('PASS: detected arbitrary labels, automatic user mapping, explicit table/role access, hidden advanced fields, automatic profiles and a single-user access check.');
  } else {
  await page.getByText('Advanced database settings',{exact:true}).click();
  if (process.argv.includes('--unconfirmed')) {
    assert.equal(emailChecks,0,'first-time email confirmation must remain explicit');
    await page.getByLabel('Database account email').fill('person@example.com');
    await page.getByRole('button',{name:'Verify my database email',exact:true}).click();
    await page.getByText(/Email verified\. Matched database user 7/).waitFor();
  }
  const priorEmailChecks=emailChecks;
  if (automatic) {
    await page.getByRole('heading',{name:'Automatically selected permissions',exact:true}).waitFor();
    await page.getByText('Permitted fields: record_key, caption, content.',{exact:true}).waitFor();
    assert.equal(await page.getByLabel('Row scope').count(),0,'native access must be selected without manual scope input');
    assert.equal(await page.getByLabel('Add readable resource').count(),0,'native resources must be selected without manual resource input');
    assert.equal(pagesLoaded,0,'automatic selection must not depend on scanning all service metadata');
  } else if (localSaved) {
    await page.getByRole('heading',{name:'Permission adapter inside IQ Knowledge',exact:true}).waitFor();
    await page.getByText(/Reused 1 reviewed resource rule from IQ Knowledge/).waitFor();
    assert.equal(await page.getByLabel('content',{exact:true}).isChecked(),true,'saved readable fields must be reused');
    assert.equal(await page.getByLabel('Row scope').inputValue(),'user','saved row restriction must be reused');
    await page.locator('#application-permissions details.query-entry').filter({has:page.locator('summary',{hasText:'custom.records'})}).locator('summary').click();
    await page.getByLabel('caption',{exact:true}).uncheck();
    await page.getByRole('button',{name:'Check saved permissions and discover resources',exact:true}).click();
    await page.getByText(/Reused 1 reviewed resource rule from IQ Knowledge/).waitFor();
    assert.equal(await page.getByLabel('caption',{exact:true}).isChecked(),false,'preview must not overwrite an unsaved policy edit');
    await page.getByLabel('caption',{exact:true}).check();
    await page.getByRole('checkbox',{name:"These fields and this row access match the native application's existing permissions"}).check();
  } else {
  await page.getByRole('button',{name:'Save mapping draft',exact:true}).click();
  await page.getByText(/Mapping draft saved\. Next, choose a table/).waitFor();
  assert.equal(emailChecks,priorEmailChecks,'mapping-only draft must not authorize or recheck email');
  await page.getByLabel('Find a resource').fill('records');
  await page.getByLabel('Add readable resource').first().selectOption({label:'custom.records'});
  assert.ok(pagesLoaded>=2,'resource selection should include later metadata pages');
  await page.getByLabel('record_key',{exact:true}).check();
  await page.getByLabel('caption',{exact:true}).check();
  await page.getByLabel('content',{exact:true}).check();
  const review=page.getByRole('checkbox',{name:"These fields and this row access match the native application's existing permissions"});
  assert.equal(await review.isDisabled(),true,'unresolved scope must prevent review');
  await page.getByLabel('Row scope').selectOption('user');
  assert.equal(await review.isDisabled(),true,'missing scope column must prevent review');
  await page.getByLabel('Resource scope column').selectOption('owner_key');
  await review.check();
  }
  await page.getByRole('button',{name:'Save permissions and continue',exact:true}).click();
  await page.getByRole('heading',{name:'Create a search profile',exact:true}).waitFor();
  assert.equal(emailChecks,priorEmailChecks+1,'confirmed email should be rechecked automatically after saving rules');
  assert.equal(await page.getByLabel('Unique key column').inputValue(),'record_key');
  assert.equal(await page.getByLabel('Display column').inputValue(),'caption');
  await page.getByRole('button',{name:'Preview search profile',exact:true}).click();
  await page.getByRole('button',{name:'Save versioned profile',exact:true}).click();
  await page.getByText(/One more distinct database user needs to verify their email/).waitFor();
  assert.equal(tests,1,'saving a search profile should test the current account');
  assert.equal(profile.capability,'text_search');
  if (automatic) assert.deepEqual(adapter.rules,[],'native snapshots must not become saved manual grants');
  else {
    assert.deepEqual(adapter.rules[0].scope,{kind:'user',column:'owner_key'});
    assert.deepEqual([...adapter.rules[0].fields].sort(),['record_key','caption','content'].sort());
  }
  assert.equal(requests.some((request)=>request.includes('permission-drafts')),false);
  if (automatic) {
    nativeDenied=true;
    await page.getByRole('button',{name:'Refresh my permissions',exact:true}).click();
    await page.getByText(/Automatic permission lookup could not complete \(permission_source_denied\)/).waitFor();
    assert.equal(await page.getByText('Permitted fields: record_key, caption, content.',{exact:true}).count(),0,'revoked native fields must disappear');
    assert.equal(await page.getByLabel('Row scope').count(),0,'native denial must not expose a manual override');
  }
  if (process.argv.includes('--stale-provider')) {
    assert.ok(automatic,'the stale-provider scenario requires --automatic');
    nativeDenied = false;
    holdNextPreview = true;
    await page.getByRole('button',{name:'Refresh my permissions',exact:true}).click();
    await previewHeld;
    await page.getByLabel('Permission system').selectOption('postgres_role');
    await page.getByLabel('Permission system').selectOption('application_rules');
    await page.getByRole('heading',{name:'Permission adapter inside IQ Knowledge',exact:true}).waitFor();
    await page.getByText(/The internal adapter is selected\. Save its mapping draft/).waitFor();
    const oldResponse = page.waitForResponse((response) => response.url().endsWith('/api/admin/postgres/auth/permissions'));
    releaseHeldPreview();
    await oldResponse;
    // Allow the completed fetch and any resulting React render to finish.
    await page.evaluate(() => new Promise((resolve) => requestAnimationFrame(() => requestAnimationFrame(resolve))));
    assert.equal(await page.getByLabel('Row scope').count(),0,'an obsolete external reply must not populate internal label grants');
    console.log('PASS: a delayed external reply cannot repopulate grants after switching to the internal adapter.');
  }
  assert.deepEqual(errors,[]);
  console.log(automatic ? 'PASS: explicit external source, no service metadata scan, profile prefill, email recheck, own-user test, and revocation without manual fallback.' : localSaved ? 'PASS: internal saved fields and row scope reused, unsaved policy edits preserved, profile prefill, email recheck and own-user test.' : 'PASS: resource pagination, complete permission review, automatic email recheck, profile prefill, optional note, own-user test, and second-user guidance.');
  }
} catch(error) { console.error(JSON.stringify(debug));if(debugPage)console.error((await debugPage.locator('body').innerText()).slice(0,2600));throw error; }
finally { await browser?.close();await server.close(); }
