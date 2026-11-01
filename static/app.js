const modules = {
 students: {title:'Students', fields:['name','year','guardian'], description:'Keep student enrollment and guardian contact details together.'},
 attendance: {title:'Attendance', fields:['student','date','status'], description:'Record daily attendance with a student name or school identifier.'},
 grades: {title:'Grades', fields:['student','subject','grade'], description:'Capture subject results for each student.'},
 assets: {title:'IT inventory', fields:['tag','device','location','status'], description:'Track school equipment, locations, and availability.'},
 audits: {title:'IT audits', fields:['area','finding','status','owner','severity','evidence','due_date','remediation','reviewer','verification','closure_reason','reopen_reason','actor'], description:'Record technology audit findings and their resolution status.'},
 tickets: {title:'Support tickets', fields:['title','requester','priority','status'], description:'Keep school support requests and priorities visible.'}
};
const choices = {'attendance.status':['Present','Absent','Late'],'assets.status':['Available','In use','Repair'],'audits.status':['Draft','Open','In progress','Awaiting verification','Closed'],'audits.severity':['','Low','Medium','High','Critical'],'tickets.status':['Open','In progress','Resolved'],'tickets.priority':['Low','Medium','High']};
let current = null, records = [], counts = {}, editingAudit = null, pageOffset=0, viewRequest=0;
const $ = id => document.getElementById(id);
const label = name => name.replaceAll('_',' ').replace(/\b\w/g,char=>char.toUpperCase());
const canReadModule = key => !signedInUser || (signedInUser.role==='registrar'&&['students','attendance','grades'].includes(key)) || (['administrator','auditor'].includes(signedInUser.role)&&['audits','assets','tickets'].includes(key)) || (['remediation_owner','reviewer'].includes(signedInUser.role)&&key==='audits');
const tableFields = key => key==='audits'?['area','finding','status','owner','severity','due_date','reviewer']:modules[key].fields;
let workspaceToken = '', signedInUser = null, sessionGeneration=0, assignmentUsers=[];
let preparedBatch=null, exportCursor=0;
async function api(path, options = {}) { const generation=sessionGeneration; options.headers = {...options.headers, 'X-Schooldesk-Request':'1'}; if(workspaceToken) options.headers.Authorization = 'Bearer '+workspaceToken; const response = await fetch('/api/'+path, options); const data = await response.json(); if(generation!==sessionGeneration)throw new Error('Session changed. Request discarded.'); if(response.status===401&&signedInUser&&!['auth/login','auth/change-password','auth/reauthenticate','auth/mfa/begin','auth/mfa/confirm'].includes(path))signedOut('Session expired or revoked. Sign in again.'); if(!response.ok) throw new Error(data.error || 'Request failed'); return data; }
function cell(tag, text) { const element=document.createElement(tag); element.textContent=text; return element; }
function drawRows() {
 $('page-label').textContent='Page '+(pageOffset/50+1)+' · search filters this page';$('page-prev').disabled=pageOffset===0;$('page-next').disabled=records.length<50;
 $('rows').replaceChildren();
 const filtered=records.filter(row=>Object.values(row).join(' ').toLowerCase().includes($('search').value.toLowerCase()));
 for(const row of filtered) { const tr=document.createElement('tr'); for(const field of tableFields(current)) tr.append(cell('td',row[field] || ''));
 if(current === 'audits') { const td=document.createElement('td'); const edit=cell('button','Edit / transition');edit.type='button';edit.onclick=()=>editAudit(row);const evidence=cell('button','Evidence');evidence.type='button';evidence.onclick=()=>auditEvidence(row);const history=cell('button','History');history.type='button';history.onclick=()=>auditHistory(row.id);td.append(edit,history,evidence);tr.append(td); }
 $('rows').append(tr); }
 if(!filtered.length) { const tr=document.createElement('tr'), td=cell('td',records.length?'No matching records.':'No records yet. Add your first record above.'); td.colSpan=tableFields(current).length+(current==='audits'?1:0);tr.append(td);$('rows').append(tr); }
}
async function show(key, editing=false) {
 const request=++viewRequest; $('form').hidden=true;
 current=key; editingAudit=null; $('audit-history')?.remove(); $('evidence-panel')?.remove(); $('error').textContent='';
 document.querySelectorAll('nav button').forEach(button=>button.classList.toggle('active',button.dataset.key===(key||'')));
 $('audit-filters').hidden=key!=='audits';
 $('overview').hidden=!!key; $('module').hidden=!key; $('breadcrumb').textContent=key?modules[key].title:'Overview';
 if(!key) { await dashboard();return; }
 if(key==='audits'&&signedInUser){assignmentUsers=await api('users');if(current!==key||request!==viewRequest)return;}
 $('record-form-title').textContent=key==='audits'?'New audit finding':'Add a record';$('cancel-edit').hidden=true;$('audit-guidance').hidden=key!=='audits';
 const module=modules[key]; $('title').textContent=module.title;$('description').textContent=module.description;$('category').textContent=['students','attendance','grades'].includes(key)?'SCHOOL ADMINISTRATION':'IT OPERATIONS';$('message').textContent='';$('search').value='';$('form').replaceChildren();
 for(const field of module.fields) { const wrapper=cell('label',label(field)); const assignedOptions=key==='audits'&&signedInUser&&['owner','reviewer'].includes(field)?['',...assignmentUsers.filter(user=>user.role==='administrator'||user.role===(field==='owner'?'remediation_owner':'reviewer')).map(user=>user.username)]:null;
 const options=assignedOptions||choices[key+'.'+field]; const input=document.createElement(options?'select':(key==='audits'&&['finding','evidence','remediation','verification','closure_reason','reopen_reason'].includes(field)?'textarea':'input'));input.name=field;input.required=key!=='audits'||['area','finding','actor'].includes(field);if(key==='audits'&&field==='actor'&&signedInUser){input.value=signedInUser.username;input.readOnly=true;}if(options) options.forEach(value=>{const option=cell('option',value);option.value=value;input.append(option);});else {input.type=['date','due_date'].includes(field)?'date':'text';input.maxLength=500;}wrapper.append(input);$('form').append(wrapper); }
 const submit=cell('button','Save record');submit.type='submit';$('form').append(submit);
 const canCreate=!signedInUser||(signedInUser.role==='registrar'&&['students','attendance','grades'].includes(key))||(signedInUser.role==='administrator'&&['assets','tickets','audits'].includes(key))||(key==='audits'&&signedInUser.role==='auditor');
 $('form').hidden=editing||!canCreate;
 if(!canCreate)$('message').textContent=key==='audits'?'Choose Edit / transition on a finding assigned to you.':'This role has read-only access to these records.';
 const tr=document.createElement('tr');tableFields(key).forEach(field=>tr.append(cell('th',label(field))));if(key==='audits')tr.append(cell('th','Actions'));$('head').replaceChildren(tr);$('rows').replaceChildren();
 try { const result=await api(listPath(key)); if(current===key&&request===viewRequest){records=result;drawRows();} }catch(error){$('error').textContent=error.message;}
}
async function dashboard() {
 try {const visibleKeys=Object.keys(modules).filter(canReadModule);counts=await api('summary');$('cards').replaceChildren();for(const key of visibleKeys){const module=modules[key];const button=document.createElement('button');button.className='card';button.append(cell('div',module.title),cell('strong',counts[key]),cell('span','View records →'));button.onclick=()=>{pageOffset=0;show(key);};$('cards').append(button);}if(visibleKeys.includes('audits')){const card=cell('div','Overdue findings');card.className='card';card.append(cell('strong',counts.overdue_audits),cell('p','Active severity: '+Object.entries(counts.audit_severity).map(([severity,total])=>(severity||'Unspecified')+' '+total).join(' · ')));$('cards').append(card);}await loadWorkQueue();$('operations-card').hidden=!signedInUser||signedInUser.role!=='administrator';if(!$('operations-card').hidden)await refreshReadiness();}catch(error){$('error').textContent=error.message;}
}
for(const [key,title] of [['','Overview'],...Object.entries(modules).map(([key,m])=>[key,m.title])]){const button=cell('button',title);button.dataset.key=key;button.onclick=()=>{pageOffset=0;show(key||null);};$('nav').append(button);}
$('search').oninput=drawRows;
$('form').onsubmit=async event=>{event.preventDefault();const key=current;const data=Object.fromEntries(new FormData(event.target));const editing=key==='audits'?editingAudit:null;if(editing)data.revision=editing.revision;const button=event.target.querySelector('button');button.disabled=true;try{await api(editing?key+'/'+editing.id:key,{method:editing?'PUT':'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(data)});if(current===key){await show(key);$('message').textContent='Record saved.';}}catch(error){$('error').textContent=error.message;}finally{button.disabled=false;}};
show(null);


// Drafts are transient and rendered as text, never trusted HTML.
let assistantDraft = null;
function clearDraft() {
 assistantDraft = null;
 $('assistant-result').hidden = true;
 $('assistant-details').replaceChildren();
}
$('assistant-note').oninput = () => { clearDraft(); $('assistant-status').textContent = ''; };
$('assistant-external').onchange = clearDraft;
$('assistant-discard').onclick = () => { clearDraft(); $('assistant-note').value = ''; $('assistant-status').textContent = 'Draft discarded.'; };
$('assistant-form').onsubmit = async event => {
 event.preventDefault(); clearDraft();
 const button = event.target.querySelector('button');
 const note = $('assistant-note').value;
 const allowExternal = $('assistant-external').checked;
 button.disabled = true; $('assistant-status').textContent = 'Preparing draft…';
 try {
  const result = await api('assistant/draft', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({note, allow_external:allowExternal})});
  if ($('assistant-note').value !== note || $('assistant-external').checked !== allowExternal) {
   $('assistant-status').textContent = 'Input changed. Prepare a new draft.'; return;
  }
  assistantDraft = result.draft;
  for (const [key, value] of Object.entries(assistantDraft)) $('assistant-details').append(cell('dt', label(key.replaceAll('_', ' '))), cell('dd', value));
  $('assistant-result').hidden = false;
  $('assistant-status').textContent = result.mode === 'offline' ? 'Offline template ready. No external request was made.' : 'AI draft ready for your review.';
 } catch(error) { $('assistant-status').textContent = error.message; }
 finally { button.disabled = false; }
};
$('assistant-use').onclick = async () => {
 if (!assistantDraft) return;
 const draft = assistantDraft;
 await show('audits');
 if (current !== 'audits') return;
 for (const field of ['area', 'finding']) $('form').elements.namedItem(field).value = draft[field];
 $('form').elements.namedItem('status').value = 'Draft';
 $('message').textContent = 'Draft copied. Review and edit, then choose Save record. Recommendations remain suggestions and are not saved.';
 $('module').scrollIntoView({behavior:'smooth'});
 clearDraft();
};

async function editAudit(row) {
 const request=viewRequest+1;
 await show('audits',true);
 if(current !== 'audits'||request!==viewRequest) return;
 editingAudit = {id:row.id, revision:row.revision};
 for(const field of modules.audits.fields){const input=$('form').elements.namedItem(field);if(input.tagName==='SELECT'&&row[field]&&!Array.from(input.options).some(option=>option.value===row[field])){const legacy=cell('option',row[field]+' (legacy assignment)');legacy.value=row[field];input.append(legacy);}input.value=row[field]||'';}
 $('record-form-title').textContent='Edit finding #'+row.id;$('cancel-edit').hidden=false;
 $('form').elements.namedItem('actor').value = signedInUser?signedInUser.username:'';
 if(signedInUser&&['remediation_owner','reviewer'].includes(signedInUser.role)){
 const writable=signedInUser.role==='reviewer'?['status','verification','closure_reason']:['status','remediation','evidence'];
 for(const field of modules.audits.fields){const input=$('form').elements.namedItem(field);if(field==='actor')continue;if(!writable.includes(field)){if(input.tagName==='SELECT')input.disabled=true;else input.readOnly=true;}}
 }
 const allowed = {'Draft':['Draft','Open'],'Open':['Open','In progress'],'In progress':['In progress','Awaiting verification'],'Awaiting verification':['Awaiting verification','In progress','Closed'],'Closed':['Open']};
 const status=$('form').elements.namedItem('status');
 status.replaceChildren(...allowed[row.status].map(value=>{const option=cell('option',value);option.value=value;return option;}));
 $('form').querySelector('button').textContent='Save revision';
 $('message').textContent='Editing audit #'+row.id+' · revision '+row.revision+'. Enter the person making this change. Closed findings require a reopen reason.';
 $('form').hidden=false;
 $('module').scrollIntoView({behavior:'smooth'});
}
async function auditHistory(id, historyOffset=0) {
 try {
 const events=await api('audits/'+id+'/history?limit=100&offset='+historyOffset);
 if(current !== 'audits') return;
 $('audit-history')?.remove(); $('evidence-panel')?.remove();
 const panel=document.createElement('div');panel.id='audit-history';panel.className='panel';panel.append(cell('h2','History · audit #'+id));
 for(const event of events) { const details=document.createElement('details'); details.append(cell('summary','Revision '+event.revision+' · '+event.actor+' · '+event.recorded_at));const dl=document.createElement('dl');for(const [key,value] of Object.entries(event.snapshot)){dl.append(cell('dt',label(key.replaceAll('_',' '))),cell('dd',String(value)));}details.append(dl);panel.append(details); }
 const previous=cell('button','Previous history page');previous.type='button';previous.disabled=historyOffset===0;previous.onclick=()=>auditHistory(id,Math.max(0,historyOffset-100));const next=cell('button','Next history page');next.type='button';next.disabled=events.length<100;next.onclick=()=>auditHistory(id,historyOffset+100);panel.append(previous,next);$('module').append(panel);panel.scrollIntoView({behavior:'smooth'});
 } catch(error){$('error').textContent=error.message;}
}

$('unlock-form').onsubmit = async event => {
 event.preventDefault(); workspaceToken=$('workspace-token').value; $('workspace-token').value='';
 try { await api('audits'); $('unlock-status').textContent='Workspace unlocked for this tab.'; await show(null); }
 catch(error){workspaceToken='';$('unlock-status').textContent=error.message;}
};
$('lock-workspace').onclick = async () => { try { await api('auth/logout',{method:'POST',headers:{'Content-Type':'application/json'},body:'{}'}); } catch(error) {} workspaceToken=''; location.reload(); };

$('login-form').onsubmit = async event => {
 event.preventDefault(); const button=event.target.querySelector('button');button.disabled=true;
 const username=$('login-username').value,password=$('login-password').value,code=$('login-code').value;$('login-password').value='';$('login-code').value='';
 try {
 const result=await api('auth/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username,password,code})});
 workspaceToken=result.token;signedInUser=result.user;sessionGeneration++;$('security-panel').hidden=false;$('security-admin').hidden=!!result.mfa_setup_required||signedInUser.role!=='administrator';$('security-message').textContent='';
 $('unlock-form').hidden=true;$('login-form').hidden=true;
 // Keep logout reachable after hiding the legacy-token form.
 $('lock-workspace').hidden=false;$('identity').after($('lock-workspace'));
 document.querySelectorAll('nav button').forEach(button=>{button.hidden=!!button.dataset.key&&!canReadModule(button.dataset.key);});
 $('mfa-recovery').hidden=true;$('mfa-recovery-list').textContent='';
 for(const id of ['sessions-show','sessions-revoke-all','password-form'])$(id).hidden=!!result.mfa_setup_required;
 if(result.mfa_setup_required){$('overview').hidden=true;$('module').hidden=true;$('pipeline-panel').hidden=true;$('account-tools').open=true;$('identity').textContent='MFA enrollment required before workspace access.';await loadMFAStatus();return;}
 await loadMFAStatus();
 assignmentUsers=await api('users');
 setupPipeline();
 await show(null);
 $('identity').textContent='Signed in as '+signedInUser.username+' · '+signedInUser.role+' · 15-minute idle timeout · one-hour maximum session';

 }catch(error){$('identity').textContent=error.message;}
 finally{button.disabled=false;}
};

api('auth/status').then(status=>{
 if(signedInUser)return;
 if(status.accounts_enabled){$('unlock-form').hidden=true;$('identity').textContent='Sign in with an individual account. Legacy workspace tokens do not grant access.';}
 else {$('login-form').hidden=true;if(!status.demo_enabled){$('unlock-form').hidden=true;$('identity').textContent='Workspace locked: run python3 schooldesk.py init before serving, or deliberately enable fictional-data demo mode.';}else{$('demo-banner').hidden=false;}}
}).catch(error=>{if(!signedInUser)$('identity').textContent=error.message;});

function listPath(key) {
 const params=new URLSearchParams({limit:'50',offset:String(pageOffset)});
 if(key==='audits'){
  for(const field of ['owner','severity','status']){const value=$('filter-'+field).value;if(value)params.set(field,value);}
  if($('filter-overdue').checked)params.set('overdue','1');
 }
 return key+'?'+params;
}
$('filter-form').onsubmit=event=>{event.preventDefault();pageOffset=0;show('audits');};
$('page-prev').onclick=()=>{pageOffset=Math.max(0,pageOffset-50);show(current);};
$('page-next').onclick=()=>{pageOffset+=50;show(current);};
async function auditEvidence(row) {
 try {
 const items=await api('audits/'+row.id+'/evidence?limit=100');
 if(current!=='audits')return;
 $('evidence-panel')?.remove();const panel=document.createElement('div');panel.id='evidence-panel';panel.className='panel';panel.append(cell('h2','Evidence · audit #'+row.id));
 panel.append(cell('p','Attachments are untrusted. UTF-8 text is the default. PDFs require operator opt-in and malware scanning; a clean scan or integrity hash does not make a file safe. Open any permitted PDF only in a sandboxed viewer. Maximum 256 KiB per file and 20 files per finding.'));
 for(const item of items){const description=cell('p',item.filename+' · '+item.size+' bytes · SHA-256 '+item.sha256+' · uploaded by '+item.actor+' · scan: '+item.scan_status);const download=cell('button','Download');download.type='button';download.disabled=!item.released;download.onclick=async()=>{
  try {const headers={};if(workspaceToken)headers.Authorization='Bearer '+workspaceToken;const response=await fetch('/api/evidence/'+item.id,{headers});if(!response.ok)throw new Error('Download denied or integrity check failed.');const blob=await response.blob();const url=URL.createObjectURL(blob);const link=document.createElement('a');link.href=url;link.download='evidence-'+item.id+(item.media_type==='application/pdf'?'.pdf':'.txt');link.click();setTimeout(()=>URL.revokeObjectURL(url),1000);}catch(error){$('error').textContent=error.message;}
 };panel.append(description,download);if(signedInUser&&['administrator','auditor'].includes(signedInUser.role)){const rescan=cell('button','Rescan evidence');rescan.type='button';rescan.onclick=async()=>{try{await api('evidence/'+item.id+'/rescan',{method:'POST',headers:{'Content-Type':'application/json'},body:'{}'});await show('audits');await auditEvidence(row);}catch(error){$('error').textContent=error.message;}};panel.append(rescan);const reject=cell('button','Reject retained evidence');reject.type='button';reject.onclick=async()=>{const reason=window.prompt('Why should this attachment be rejected and retained?');if(!reason)return;try{await api('evidence/'+item.id+'/reject',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({reason})});await show('audits');await auditEvidence(row);}catch(error){$('error').textContent=error.message;}};panel.append(reject);}}
 if(signedInUser&&row.status!=='Closed'){
 const form=document.createElement('form');const label=cell('label','Evidence file');const file=document.createElement('input');file.type='file';file.accept='.txt,.pdf';file.required=true;label.append(file);const submit=cell('button','Upload evidence');submit.type='submit';form.append(label,submit);const status=cell('p','');status.setAttribute('role','status');
 form.onsubmit=async event=>{event.preventDefault();const selected=file.files[0];if(!selected||selected.size>262144){status.textContent='Choose a file of at most 256 KiB.';return;}submit.disabled=true;
 try {const bytes=new Uint8Array(await selected.arrayBuffer());let binary='';for(const byte of bytes)binary+=String.fromCharCode(byte);await api('audits/'+row.id+'/evidence',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({filename:selected.name,content_base64:btoa(binary)})});await show('audits');await auditEvidence(row);}catch(error){status.textContent=error.message;}finally{submit.disabled=false;}};
 panel.append(form,status);
 }
 $('module').append(panel);panel.scrollIntoView({behavior:'smooth'});
 }catch(error){$('error').textContent=error.message;}
}

function signedOut(message) {
 workspaceToken='';signedInUser=null;sessionGeneration++;$('pipeline-panel').hidden=true;resetPipeline();$('pipeline-file').value='';$('pipeline-job-list').replaceChildren();
 $('security-panel').hidden=true;$('module').hidden=true;$('overview').hidden=true;
 $('queue-items').replaceChildren();$('operations-status').replaceChildren();$('operations-card').hidden=true;assignmentUsers=[];$('account-tools').open=false;
 $('form').replaceChildren();$('message').textContent='';$('security-verify-status').textContent='';$('cards').replaceChildren();$('rows').replaceChildren();$('sessions-list').replaceChildren();$('security-events').replaceChildren();
 $('evidence-panel')?.remove();$('audit-history')?.remove();
 $('login-form').hidden=false;$('identity').textContent=message;
 $('mfa-enrollment').hidden=true;$('mfa-secret').textContent='';
 for(const id of ['current-password','new-password','confirm-password','login-password','login-code','mfa-password','mfa-code','reauth-password','reauth-code'])$(id).value='';
 clearDraft();$('assistant-note').value='';
}
$('sessions-show').onclick=async()=>{
 try {
 const sessions=await api('auth/sessions');$('sessions-list').replaceChildren();
 for(const session of sessions){const row=document.createElement('p');row.append(cell('span',(session.current?'This session':'Other session')+' · created '+new Date(session.created_at*1000).toLocaleString()+' · expires '+new Date(session.expires_at*1000).toLocaleString()+' '));const revoke=cell('button','Revoke session');revoke.type='button';revoke.onclick=async()=>{
 try{await api('auth/revoke-session',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({session_id:session.id})});if(session.current)signedOut('Session revoked. Sign in again.');else $('sessions-show').click();}catch(error){$('security-message').textContent=error.message;}
 };row.append(revoke);$('sessions-list').append(row);}
 }catch(error){$('security-message').textContent=error.message;}
};
$('sessions-revoke-all').onclick=async()=>{
 try{await api('auth/revoke-all',{method:'POST',headers:{'Content-Type':'application/json'},body:'{}'});signedOut('All your sessions were revoked. Sign in again.');}catch(error){$('security-message').textContent=error.message;}
};
$('password-form').onsubmit=async event=>{
 event.preventDefault();const current=$('current-password').value,next=$('new-password').value,confirmation=$('confirm-password').value;
 for(const id of ['current-password','new-password','confirm-password'])$(id).value='';
 if(next!==confirmation){$('security-message').textContent='New passwords do not match.';return;}
 const button=event.target.querySelector('button');button.disabled=true;
 try{await api('auth/change-password',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({current_password:current,new_password:next})});signedOut('Password changed and all sessions revoked. Sign in with your new password.');}
 catch(error){$('security-message').textContent=error.message;}
 finally{button.disabled=false;}
};
async function showSecurityEvents(offset=0){
 try{const events=await api('security/events?limit=50&offset='+offset);const container=$('security-events');container.replaceChildren();
 for(const event of events)container.append(cell('p','#'+event.id+' · '+event.occurred_at+' · '+event.event+' · actor: '+(event.actor||'not recorded')+' · target: '+(event.target||'none')));
 const previous=cell('button','Previous events');previous.disabled=offset===0;previous.onclick=()=>showSecurityEvents(Math.max(0,offset-50));const next=cell('button','Next events');next.disabled=events.length<50;next.onclick=()=>showSecurityEvents(offset+50);container.append(previous,next);
 }catch(error){$('security-message').textContent=error.message;}
}
$('security-events-show').onclick=()=>showSecurityEvents();
$('security-verify').onclick=async()=>{
 try{const result=await api('security/verify');$('security-verify-status').textContent=result.valid?'Chain internally consistent · '+result.count+' events · head '+result.head+'. Compare an independently saved checkpoint to detect truncation or full rewrites.':'Security event chain verification failed. Preserve the database for investigation.';}
 catch(error){$('security-verify-status').textContent=error.message;}
};

$('cancel-edit').onclick=()=>show(current);
async function loadWorkQueue(){
 const queue=await api('work-queue');$('queue-items').replaceChildren();
 $('queue-title').textContent=signedInUser&&['remediation_owner','reviewer'].includes(signedInUser.role)?'My work':'Audit work queue';
 $('queue-summary').textContent=queue.total?'Showing '+queue.shown+' of '+queue.total+' active findings, ordered by severity and deadline.':'No findings currently require action in this queue.';
 for(const item of queue.items){const button=document.createElement('button');button.type='button';button.className='queue-item';button.append(cell('strong','#'+item.id+' · '+item.area),cell('span',item.finding),cell('span',item.status+' · '+(item.severity||'Severity not set')+' · '+(item.owner||'Unassigned')+' · '+(item.due_date||'No deadline')+(item.overdue?' · OVERDUE':'')));button.onclick=()=>editAudit(item);$('queue-items').append(button);}
}
async function refreshReadiness(){
 try{const state=await api('operations/status');const container=$('operations-status');container.replaceChildren();container.append(cell('p',state.active_accounts+' active accounts · assistant '+state.ai.mode+' ('+(state.ai.configured?'configured':'configuration needed')+')'));
 container.append(cell('p',state.backup.last_success_at?'Last recorded backup: '+new Date(Number(state.backup.last_success_at)*1000).toLocaleString():'No backup recorded yet. Run the snapshot command in the operator guide.'));
 for(const warning of state.warnings)container.append(cell('p',warning));if(!state.warnings.length)container.append(cell('p','No readiness warnings.'));
 }catch(error){$('operations-status').textContent=error.message;}
}
$('operations-refresh').onclick=refreshReadiness;

function resetPipeline(){preparedBatch=null;exportCursor=0;$('pipeline-preview').replaceChildren();$('pipeline-confirm').checked=false;$('pipeline-commit').disabled=true;$('pipeline-export-next').disabled=true;$('pipeline-status').textContent='';}
function setupPipeline(){
 resetPipeline();$('pipeline-panel').hidden=false;$('pipeline-resource').replaceChildren();
 for(const key of Object.keys(modules).filter(canReadModule)){const option=cell('option',modules[key].title);option.value=key;$('pipeline-resource').append(option);}
 updatePipelineAccess();
}
function updatePipelineAccess(){resetPipeline();const resource=$('pipeline-resource').value;$('pipeline-import-tools').hidden=!signedInUser||!((signedInUser.role==='registrar'&&['students','attendance','grades'].includes(resource))||(signedInUser.role==='administrator'&&['assets','tickets','audits'].includes(resource))||(signedInUser.role==='auditor'&&resource==='audits'));}
$('pipeline-resource').onchange=()=>{$('pipeline-file').value='';updatePipelineAccess();};
$('pipeline-file').onchange=resetPipeline;
$('pipeline-export-format').onchange=()=>{exportCursor=0;$('pipeline-export-next').disabled=true;};
$('pipeline-confirm').onchange=()=>{$('pipeline-commit').disabled=!preparedBatch||!$('pipeline-confirm').checked;};
$('pipeline-form').onsubmit=async event=>{
 event.preventDefault();resetPipeline();const file=$('pipeline-file').files[0],resource=$('pipeline-resource').value;const button=event.target.querySelector('button');button.disabled=true;
 try{
 if(!file||file.size>262144)throw new Error('Choose a CSV or JSON file up to 256 KiB.');
 const text=new TextDecoder('utf-8',{fatal:true}).decode(await file.arrayBuffer());
 let source={schema_version:1,resource};
 if(file.name.toLowerCase().endsWith('.csv'))source={...source,format:'csv',data:text};
 else if(file.name.toLowerCase().endsWith('.json'))source={...source,format:'json',data:text};
 else throw new Error('Choose a .csv or .json file.');
 const result=await api('pipeline/preview',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(source)});
 if($('pipeline-file').files[0]!==file||$('pipeline-resource').value!==resource)return;
 const preview=$('pipeline-preview');
 if(!result.valid){$('pipeline-status').textContent=result.error_count+' invalid records. Nothing imported.';for(const error of result.errors)preview.append(cell('p','Row '+error.row+': '+error.code));return;}
 preparedBatch={batch_id:result.batch_id,digest:result.digest,source};
 $('pipeline-status').textContent=result.row_count+' valid records · '+result.would_insert+' proposed inserts · '+result.duplicates+' exact duplicates. Preview expires '+new Date(result.expires_at*1000).toLocaleString()+'.';
 preview.append(cell('p','Normalized preview: '+result.normalized_rows.length+' records. Expand each row to review before importing.'));
 for(const [index,row] of result.normalized_rows.entries()){const details=document.createElement('details');details.append(cell('summary','Row '+(index+1)),cell('pre',JSON.stringify(row,null,2)));preview.append(details);}
 }catch(error){$('pipeline-status').textContent=error instanceof SyntaxError?'Invalid JSON file. Nothing imported.':error.message;}
 finally{button.disabled=false;}
};
$('pipeline-commit').onclick=async()=>{
 if(!preparedBatch||!$('pipeline-confirm').checked)return;const batch=preparedBatch;$('pipeline-commit').disabled=true;
 try{const result=await api('pipeline/commit',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(batch)});resetPipeline();$('pipeline-file').value='';$('pipeline-status').textContent='Batch complete: '+result.inserted+' inserted, '+result.skipped+' exact duplicates skipped'+(result.replayed?' (previous result replayed)':'')+'.';if(!current)await dashboard();}
 catch(error){$('pipeline-status').textContent=error.message;$('pipeline-commit').disabled=false;}
};
async function exportPipelinePage(after){
 const resource=$('pipeline-resource').value,format=$('pipeline-export-format').value;
 try{const result=await api('pipeline/export',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({resource,format,after_id:after,limit:200})});
 if($('pipeline-resource').value!==resource)return;
 const content=format==='csv'?result.csv:JSON.stringify(result,null,2);const blob=new Blob([content],{type:format==='csv'?'text/csv;charset=utf-8':'application/json'});const url=URL.createObjectURL(blob);const link=document.createElement('a');link.href=url;link.download=resource+'-after-'+after+'.'+format;link.click();setTimeout(()=>URL.revokeObjectURL(url),1000);
 exportCursor=result.next_after_id;$('pipeline-export-next').disabled=!result.has_more;$('pipeline-status').textContent='Exported '+result.rows.length+' authorized records.'+(result.has_more?' More records are available; export the next page.':' End of export.');
 }catch(error){$('pipeline-status').textContent=error.message;}
}
$('pipeline-export').onclick=()=>exportPipelinePage(0);
$('pipeline-export-next').onclick=()=>{if(exportCursor!==null)exportPipelinePage(exportCursor);};
$('pipeline-jobs').onclick=async()=>{
 try{const jobs=await api('pipeline/batches?limit=50');const list=$('pipeline-job-list');list.replaceChildren();for(const job of jobs)list.append(cell('p',modules[job.resource].title+' · '+job.status+' · '+job.row_count+' rows · '+job.inserted+' inserted · '+job.skipped+' skipped · '+new Date(job.created_at*1000).toLocaleString()));if(!jobs.length)list.append(cell('p','No import batches yet.'));}catch(error){$('pipeline-status').textContent=error.message;}
};

async function loadMFAStatus(){const state=await api('auth/mfa/status');$('mfa-status').textContent=state.enabled?'Authenticator enabled.':state.required?'Authenticator enrollment required.':'Authenticator enrollment is available when the operator configures an encryption key.';$('mfa-begin-form').hidden=state.enabled;}
$('mfa-begin-form').onsubmit=async event=>{event.preventDefault();const password=$('mfa-password').value;$('mfa-password').value='';try{const result=await api('auth/mfa/begin',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({password})});$('mfa-secret').textContent=result.secret;$('mfa-enrollment').hidden=false;}catch(error){$('security-message').textContent=error.message;}};
$('mfa-confirm-form').onsubmit=async event=>{event.preventDefault();const code=$('mfa-code').value;$('mfa-code').value='';try{const result=await api('auth/mfa/confirm',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({code})});signedOut('MFA enabled. Save the recovery codes, then sign in with a new authenticator code.');$('mfa-recovery-list').textContent=result.recovery_codes.join('\n');$('mfa-recovery').hidden=false;}catch(error){$('security-message').textContent=error.message;}};
$('mfa-recovery-clear').onclick=()=>{$('mfa-recovery-list').textContent='';$('mfa-recovery').hidden=true;};
$('reauth-form').onsubmit=async event=>{event.preventDefault();const password=$('reauth-password').value,code=$('reauth-code').value;$('reauth-password').value='';$('reauth-code').value='';try{await api('auth/reauthenticate',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({password,code})});$('security-message').textContent='Authentication refreshed for five minutes. Retry the sensitive action.';}catch(error){$('security-message').textContent=error.message;}};
