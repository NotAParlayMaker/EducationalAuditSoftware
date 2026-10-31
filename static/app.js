const modules = {
 students: {title:'Students', fields:['name','year','guardian'], description:'Keep student enrollment and guardian contact details together.'},
 attendance: {title:'Attendance', fields:['student','date','status'], description:'Record daily attendance with a student name or school identifier.'},
 grades: {title:'Grades', fields:['student','subject','grade'], description:'Capture subject results for each student.'},
 assets: {title:'IT inventory', fields:['tag','device','location','status'], description:'Track school equipment, locations, and availability.'},
 audits: {title:'IT audits', fields:['area','finding','status','owner','severity','evidence','due_date','remediation','reviewer','verification','closure_reason','reopen_reason','actor'], description:'Record technology audit findings and their resolution status.'},
 tickets: {title:'Support tickets', fields:['title','requester','priority','status'], description:'Keep school support requests and priorities visible.'}
};
const choices = {'attendance.status':['Present','Absent','Late'],'assets.status':['Available','In use','Repair'],'audits.status':['Draft','Open','In progress','Awaiting verification','Closed'],'audits.severity':['','Low','Medium','High','Critical'],'tickets.status':['Open','In progress','Resolved'],'tickets.priority':['Low','Medium','High']};
let current = null, records = [], counts = {}, editingAudit = null;
const $ = id => document.getElementById(id);
const label = name => name.charAt(0).toUpperCase()+name.slice(1);
let workspaceToken = '';
async function api(path, options = {}) { options.headers = {...options.headers, 'X-Schooldesk-Request':'1'}; if(workspaceToken) options.headers.Authorization = 'Bearer '+workspaceToken; const response = await fetch('/api/'+path, options); const data = await response.json(); if(!response.ok) throw new Error(data.error || 'Request failed'); return data; }
function cell(tag, text) { const element=document.createElement(tag); element.textContent=text; return element; }
function drawRows() {
 $('rows').replaceChildren();
 const filtered=records.filter(row=>Object.values(row).join(' ').toLowerCase().includes($('search').value.toLowerCase()));
 for(const row of filtered) { const tr=document.createElement('tr'); for(const field of modules[current].fields) tr.append(cell('td',row[field] || ''));
 if(current === 'audits') { const td=document.createElement('td'); const edit=cell('button','Edit / transition');edit.type='button';edit.onclick=()=>editAudit(row);const history=cell('button','History');history.type='button';history.onclick=()=>auditHistory(row.id);td.append(edit,history);tr.append(td); }
 $('rows').append(tr); }
 if(!filtered.length) { const tr=document.createElement('tr'), td=cell('td',records.length?'No matching records.':'No records yet. Add your first record above.'); td.colSpan=modules[current].fields.length;tr.append(td);$('rows').append(tr); }
}
async function show(key) {
 current=key; editingAudit=null; $('audit-history')?.remove(); $('error').textContent='';
 document.querySelectorAll('nav button').forEach(button=>button.classList.toggle('active',button.dataset.key===(key||'')));
 $('overview').hidden=!!key; $('module').hidden=!key; $('breadcrumb').textContent=key?modules[key].title:'Overview';
 if(!key) { await dashboard();return; }
 const module=modules[key]; $('title').textContent=module.title;$('description').textContent=module.description;$('category').textContent=['students','attendance','grades'].includes(key)?'SCHOOL ADMINISTRATION':'IT OPERATIONS';$('message').textContent='';$('search').value='';$('form').replaceChildren();
 for(const field of module.fields) { const wrapper=cell('label',label(field)); const options=choices[key+'.'+field]; const input=document.createElement(options?'select':'input');input.name=field;input.required=key!=='audits'||['area','finding','actor'].includes(field);if(options) options.forEach(value=>{const option=cell('option',value);option.value=value;input.append(option);});else {input.type=['date','due_date'].includes(field)?'date':'text';input.maxLength=500;}wrapper.append(input);$('form').append(wrapper); }
 const submit=cell('button','Save record');submit.type='submit';$('form').append(submit);
 const tr=document.createElement('tr');module.fields.forEach(field=>tr.append(cell('th',label(field))));if(key==='audits')tr.append(cell('th','Actions'));$('head').replaceChildren(tr);$('rows').replaceChildren();
 try { const result=await api(key); if(current===key){records=result;drawRows();} }catch(error){$('error').textContent=error.message;}
}
async function dashboard() {
 try {const results=await Promise.all(Object.keys(modules).map(async key=>[key,(await api(key)).length]));counts=Object.fromEntries(results);$('cards').replaceChildren();for(const [key,module] of Object.entries(modules)){const button=document.createElement('button');button.className='card';button.append(cell('div',module.title),cell('strong',counts[key]),cell('span','View records →'));button.onclick=()=>show(key);$('cards').append(button);}}catch(error){$('error').textContent=error.message;}
}
for(const [key,title] of [['','Overview'],...Object.entries(modules).map(([key,m])=>[key,m.title])]){const button=cell('button',title);button.dataset.key=key;button.onclick=()=>show(key||null);$('nav').append(button);}
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
 await show('audits');
 if(current !== 'audits') return;
 editingAudit = {id:row.id, revision:row.revision};
 for(const field of modules.audits.fields) $('form').elements.namedItem(field).value = row[field] || '';
 $('form').elements.namedItem('actor').value = '';
 const allowed = {'Draft':['Draft','Open'],'Open':['Open','In progress'],'In progress':['In progress','Awaiting verification'],'Awaiting verification':['Awaiting verification','In progress','Closed'],'Closed':['Open']};
 const status=$('form').elements.namedItem('status');
 status.replaceChildren(...allowed[row.status].map(value=>{const option=cell('option',value);option.value=value;return option;}));
 $('form').querySelector('button').textContent='Save revision';
 $('message').textContent='Editing audit #'+row.id+' · revision '+row.revision+'. Enter the person making this change. Closed findings require a reopen reason.';
 $('module').scrollIntoView({behavior:'smooth'});
}
async function auditHistory(id) {
 try {
 const events=await api('audits/'+id+'/history');
 if(current !== 'audits') return;
 $('audit-history')?.remove();
 const panel=document.createElement('div');panel.id='audit-history';panel.className='panel';panel.append(cell('h2','History · audit #'+id));
 for(const event of events) { const details=document.createElement('details'); details.append(cell('summary','Revision '+event.revision+' · '+event.actor+' · '+event.recorded_at));const dl=document.createElement('dl');for(const [key,value] of Object.entries(event.snapshot)){dl.append(cell('dt',label(key.replaceAll('_',' '))),cell('dd',String(value)));}details.append(dl);panel.append(details); }
 $('module').append(panel);panel.scrollIntoView({behavior:'smooth'});
 } catch(error){$('error').textContent=error.message;}
}

$('unlock-form').onsubmit = async event => {
 event.preventDefault(); workspaceToken=$('workspace-token').value; $('workspace-token').value='';
 try { await api('audits'); $('unlock-status').textContent='Workspace unlocked for this tab.'; await show(null); }
 catch(error){workspaceToken='';$('unlock-status').textContent=error.message;}
};
$('lock-workspace').onclick = () => { workspaceToken=''; location.reload(); };
