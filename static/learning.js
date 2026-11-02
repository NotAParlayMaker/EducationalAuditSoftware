/* Learning records stay local and all dynamic content is rendered as text. */
window.learningUI=(()=>{
 let generation=0,group=null,student=null,classes=[],teachers=[],versions=[];
 const root=$('learning-content'),status=$('learning-status'),nav=cell('button','Learning evidence');nav.id='learning-nav';nav.dataset.key='learning';nav.hidden=true;$('nav').append(nav);
 const registrar=()=>signedInUser?.role==='registrar';
 const allowed=()=>signedInUser&&['registrar','teacher'].includes(signedInUser.role);
 const pretty=v=>String(v).replaceAll('_',' '),el=(tag,v='')=>cell(tag,String(v??''));
 const base=(cid=group?.id,sid=null)=>'classes/'+cid+(sid?'/students/'+sid:'');
 function button(title,fn){const b=el('button',title);b.type='button';b.onclick=fn;return b;}
 function panel(title,parent=root){const p=el('div');p.className='panel learning-block';p.append(el('h2',title));parent.append(p);return p;}
 function field(form,name,title,options=null,type='text',value='',optional=false){
  const label=el('label',title),input=document.createElement(options?'select':type==='textarea'?'textarea':'input');input.name=name;input.required=!optional;
  if(options)for(const [key,text] of options){const o=el('option',text);o.value=key;input.append(o);}else if(type!=='textarea')input.type=type;
  input.maxLength=type==='textarea'?2000:100;input.value=value;label.append(input);form.append(label);return input;
 }
 function form(parent,id,title,action){const f=el('form');f.id=id;parent.append(f);const send=el('button',title);send.type='submit';f.finish=()=>f.append(send);
  f.onsubmit=async e=>{e.preventDefault();const stamp=generation;send.disabled=true;status.textContent='';try{await action(Object.fromEntries(new FormData(f)),stamp);}catch(error){if(stamp===generation)status.textContent=error.message;}finally{send.disabled=false;}};return f;
 }
 async function save(path,data,stamp,after){const result=await api('learning/'+path,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(data)});if(stamp!==generation)return;await after(result);if(!status.textContent)status.textContent='Saved.';}
 function skillName(id){const s=versions.find(s=>s.id===id);return s?s.title+' / '+s.rubric_version:'Historical skill #'+id;}
 function reviewDetails(review){if(!review)return 'No teacher review';const d=el('details');d.append(el('summary',pretty(review.judgment)),el('p',review.rationale),el('p','Recorded by '+review.actor+' at '+review.recorded_at),el('p','Evidence: '+review.evidence_ids.map(id=>'#'+id).join(', ')));return d;}
 function table(parent,headers,rows){const wrap=el('div'),t=el('table'),h=el('tr');wrap.className='tablewrap';for(const v of headers)h.append(el('th',v));t.append(h);for(const values of rows){const tr=el('tr');for(const v of values){const td=el('td');if(v instanceof Node)td.append(v);else td.textContent=String(v??'');tr.append(td);}t.append(tr);}wrap.append(t);parent.append(wrap);}
 function hide(){generation++;$('learning-panel').hidden=true;nav.classList.remove('active');$('assistant').hidden=!!signedInUser&&['registrar','teacher'].includes(signedInUser.role);}
 function clear(){generation++;root.replaceChildren();status.textContent='';classes=[];teachers=[];versions=[];group=null;student=null;nav.hidden=true;hide();}
 async function open(desired){
  if(!allowed())return;const stamp=++generation;root.replaceChildren();status.textContent='';student=null;
  for(const id of ['overview','module','pipeline-panel','assistant'])$(id).hidden=true;$('learning-panel').hidden=false;$('breadcrumb').textContent='Learning evidence';document.querySelectorAll('nav button').forEach(b=>b.classList.remove('active'));nav.classList.add('active');
  try{
   const result=await Promise.all([api('learning/classes'),registrar()?api('learning/teachers'):Promise.resolve([])]);if(stamp!==generation)return;[classes,teachers]=result;
   if(registrar()){
    const p=panel('Create a class'),f=form(p,'learning-class-form','Create class',async(d,g)=>save('classes',d,g,r=>open(r.id)));
    field(f,'name','Class name');field(f,'teacher','Assigned teacher',teachers.map(t=>[t.username,t.username]));f.finish();if(!teachers.length)p.append(el('p','No active teacher accounts are available. Ask the account operator to provision one.'));
   }
   if(!classes.length){root.append(el('p',registrar()?'Create a class and enroll students to begin.':'No classes are currently assigned to you.'));return;}
   const label=el('label','Class'),select=document.createElement('select');select.id='learning-class';for(const item of classes){const o=el('option',item.name+' · '+item.teacher);o.value=item.id;select.append(o);}label.append(select);root.append(label);
   select.value=String(desired||group?.id||classes[0].id);if(!select.value)select.value=String(classes[0].id);const body=el('div');body.id='learning-class-body';root.append(body);select.onchange=()=>loadClass(Number(select.value));await loadClass(Number(select.value));
  }catch(error){if(stamp===generation)status.textContent=error.message;}
 }
 async function loadClass(cid){
  const stamp=++generation;group=classes.find(c=>c.id===cid);student=null;const parent=$('learning-class-body');parent.replaceChildren();status.textContent='';
  try{
   const [roster,skills,coverage]=await Promise.all(['enrollments','skills','coverage'].map(action=>api('learning/'+base(cid)+'/'+action)));if(stamp!==generation)return;versions=skills;const active=skills.filter(s=>s.active);
   if(registrar()){
    const p=panel('Class and roster management',parent),f=form(p,'learning-assignment-form','Change teacher',async(d,g)=>save(base(cid)+'/assignment',{teacher:d.teacher,revision:group.revision},g,()=>open(cid)));
    field(f,'teacher','Assigned teacher',teachers.map(t=>[t.username,t.username]),'text',group.teacher);f.finish();
    const search=form(p,'learning-student-search','Find students',async(d,g)=>{const found=await api('learning/students?search='+encodeURIComponent(d.search));if(g!==generation)return;picker.replaceChildren();for(const s of found){const o=el('option','#'+s.id+' · '+s.name+' · '+s.year);o.value=s.id;picker.append(o);}status.textContent=found.length+' students found (up to 50).';});field(search,'search','Student name',null,'text','',true);search.finish();
    const enroll=form(p,'learning-enrollment-form','Enroll student',async(d,g)=>save(base(cid)+'/enrollments',{student_id:Number(d.student_id),active:true,revision:0},g,()=>loadClass(cid)));const picker=field(enroll,'student_id','Student',[]);enroll.finish();p.append(el('p','Use Re-enroll for an existing inactive roster entry.'));
   }
   const rosterPanel=panel('Class roster',parent);table(rosterPanel,['ID','Student','Year','Enrollment','Actions'],roster.map(s=>{const actions=el('div');actions.append(button('Open evidence',()=>loadStudent(cid,s.id)));if(registrar())actions.append(button(s.active?'Remove from class':'Re-enroll',async()=>{const g=generation;try{await save(base(cid)+'/enrollments',{student_id:s.id,active:!s.active,revision:s.revision},g,()=>loadClass(cid));}catch(error){if(g===generation)status.textContent=error.message;}}));return [s.id,s.name,s.year,s.active?'Active':'Inactive',actions];}));
   const p=panel('Skills and rubric versions',parent);p.append(el('p','A new rubric version preserves prior evidence and starts a separate review record.'));
   table(p,['Code','Skill','Version','Criteria'],active.map(s=>[s.code,s.title,s.rubric_version,s.criteria]));if(skills.some(s=>!s.active)){const old=el('details');old.append(el('summary','Earlier rubric versions'));table(old,['Code','Skill','Version','Criteria'],skills.filter(s=>!s.active).map(s=>[s.code,s.title,s.rubric_version,s.criteria]));p.append(old);}const f=form(p,'learning-skill-form','Add rubric version',async(d,g)=>save(base(cid)+'/skills',d,g,()=>loadClass(cid)));
   field(f,'code','Skill code');field(f,'title','Skill title').maxLength=120;field(f,'rubric_version','Rubric version').maxLength=40;field(f,'criteria','What reasoning would demonstrate this skill?',null,'textarea').maxLength=1000;f.finish();
   const report=panel('Observation opportunities',parent);report.append(el('p',coverage.note+' Recent means the last '+coverage.window_days+' days. Missing opportunities are not incorrect responses.'));
   table(report,['Student','Completed','Skills covered','Missing','Formats','Open reassessments','Follow-up'],coverage.students.map(s=>[s.name,s.recent_completed,coverage.active_skills?s.skills_with_recent_evidence+' / '+coverage.active_skills:'No active skills',s.missing_count,s.formats,s.open_requests,s.fewer_observed_opportunities?'Fewer observations than class median':'']));
   const detail=el('div');detail.id='learning-student-detail';parent.append(detail);
  }catch(error){if(stamp===generation)status.textContent=error.message;}
 }
 async function refreshLearner(cid,sid){const stamp=generation;await loadClass(cid);if(generation===stamp+1&&group?.id===cid&&$('learning-student-detail'))await loadStudent(cid,sid);}
 async function loadStudent(cid,sid,before=null,append=false){
  const stamp=++generation,parent=$('learning-student-detail');if(!append)parent.replaceChildren();status.textContent='';
  try{
   const [data,evidence]=await Promise.all([api('learning/'+base(cid,sid)+(before?'?before_id='+before:'')),append?Promise.resolve(null):api('learning/'+base(cid,sid)+'/observations?limit=100')]);if(stamp!==generation)return;student=data.student;
   if(!append){
    parent.append(el('h2',student.name+' · Student #'+student.id));parent.scrollIntoView({behavior:'smooth'});
    const summary=panel('Evidence and teacher judgments',parent);summary.append(el('p','Counts describe coverage. Judgments come from a human; no confidence percentage or placement decision is generated.'));
    table(summary,['Skill / rubric','Recent / total completed','Formats','Latest teacher judgment','Evidence indicators'],data.skills.map(s=>[s.title+' / '+s.rubric_version,s.recent_completed+' / '+s.total_completed,s.formats,reviewDetails(s.review),s.flags.map(pretty).join('; ')]));
    const options=data.skills.map(s=>[s.id,s.title+' / '+s.rubric_version]),current=evidence.rows.filter(o=>!o.superseded);
    const p=panel('Record an observation or correction',parent);p.append(el('p','Describe the performance and conditions. Avoid diagnoses and unrelated personal details. Corrections retain the original record.'));
    const f=form(p,'learning-observation-form','Save observation',async(d,g)=>save(base(cid,sid)+'/observations',{...d,skill_id:Number(d.skill_id),supersedes_id:d.supersedes_id?Number(d.supersedes_id):null},g,()=>refreshLearner(cid,sid)));
    field(f,'skill_id','Skill / rubric',options);const day=new Date(),today=day.getFullYear()+'-'+String(day.getMonth()+1).padStart(2,'0')+'-'+String(day.getDate()).padStart(2,'0');field(f,'observed_on','Assessment date',null,'date',today);
    field(f,'method','Format',['written','oral','diagram','transfer','practice'].map(v=>[v,pretty(v)]));field(f,'outcome','Observed outcome',['demonstrated','developing','incorrect','not_assessed','absent','inaccessible'].map(v=>[v,pretty(v)]));
    field(f,'context','Task and assessment conditions',null,'textarea').maxLength=500;field(f,'observation','What was observed?',null,'textarea');field(f,'source_id','Unique source reference',null,'text',crypto.randomUUID());field(f,'supersedes_id','Correction of evidence ID (optional)',null,'number','',true);field(f,'correction_reason','Correction reason (required for corrections)',null,'textarea','',true).maxLength=1000;f.finish();
    const obs=panel('Recorded evidence',parent);table(obs,['ID / source','Date / format','Skill / rubric','Outcome','Context / observation','State / action'],evidence.rows.map(o=>{const action=el('div',o.superseded?'Superseded':'Current');if(!o.superseded&&data.skills.some(s=>s.id===o.skill_id))action.append(button('Correct',()=>{for(const key of ['skill_id','observed_on','method','outcome','context','observation'])f.elements.namedItem(key).value=o[key];f.elements.namedItem('supersedes_id').value=o.id;f.elements.namedItem('source_id').value=crypto.randomUUID();f.elements.namedItem('correction_reason').focus();}));return [o.id+' / '+o.source_id,o.observed_on+' / '+o.method,skillName(o.skill_id),pretty(o.outcome),o.context+' · '+o.observation,action];}));if(evidence.has_more)obs.append(el('p','Showing the latest 100 observations. Earlier records remain in the activity timeline and paginated API.'));
    const r=panel('Record a formative teacher review',parent),rf=form(r,'learning-review-form','Record teacher review',async(d,g)=>{const s=data.skills.find(s=>s.id===Number(d.skill_id)),ids=[...rf.querySelectorAll('input[name=evidence_id]:checked')].map(i=>Number(i.value));await save(base(cid,sid)+'/reviews',{skill_id:Number(d.skill_id),judgment:d.judgment,rationale:d.rationale,evidence_ids:ids,previous_review_id:s?.review?.id??null},g,()=>refreshLearner(cid,sid));});
    const rs=field(rf,'skill_id','Skill / rubric',options);field(rf,'judgment','Teacher judgment',['insufficient_evidence','developing','demonstrated_across_contexts'].map(v=>[v,pretty(v)]));field(rf,'rationale','Rationale and limits of the evidence',null,'textarea');const citations=el('fieldset');citations.append(el('legend','Supporting completed observations'));rf.append(citations);
    function fillCitations(){for(const label of [...citations.querySelectorAll('label')])label.remove();for(const o of current.filter(o=>o.skill_id===Number(rs.value)&&!['not_assessed','absent','inaccessible'].includes(o.outcome))){const label=el('label','#'+o.id+' · '+o.observed_on+' · '+o.method+' · '+pretty(o.outcome)),input=document.createElement('input');input.type='checkbox';input.name='evidence_id';input.value=o.id;label.prepend(input);citations.append(label);}}rs.onchange=fillCitations;fillCitations();
    const ack=el('label','I reviewed the cited evidence and rationale.'),check=document.createElement('input');check.type='checkbox';check.required=true;ack.prepend(check);rf.append(ack);rf.finish();r.append(el('p','Demonstrated across contexts requires demonstrated observations on two dates, in two formats and contexts. This is a workflow minimum, not a validated mastery model.'));
    const req=panel('Request another opportunity or record a challenge',parent);req.append(el('p','The signed-in educator records the request. Student or guardian origin is reported, not authenticated.'));const q=form(req,'learning-request-form','Open reassessment',async(d,g)=>save(base(cid,sid)+'/reassessments',{...d,skill_id:Number(d.skill_id)},g,()=>refreshLearner(cid,sid)));
    field(q,'skill_id','Skill / rubric',options);field(q,'reported_source','Reported request source',['student','guardian','teacher'].map(v=>[v,v]));field(q,'reason','Reason for reassessment',null,'textarea').maxLength=1000;field(q,'student_statement','Student explanation (optional)',null,'textarea','',true);q.finish();
    for(const request of data.reassessments){const box=el('div');box.append(el('h3','#'+request.id+' · '+request.status),el('p',request.reason),el('p',request.student_statement));req.append(box);if(request.status==='Open'){
     const resolve=form(box,'learning-resolve-'+request.id,'Resolve reassessment',async(d,g)=>save(base(cid,sid)+'/reassessments/'+request.id+'/resolve',{revision:request.revision,resolution:d.resolution,observation_id:d.observation_id?Number(d.observation_id):null},g,()=>refreshLearner(cid,sid)));field(resolve,'resolution','Resolution and follow-up',null,'textarea');field(resolve,'observation_id','Supporting evidence (optional)',[['','No linked evidence'],...current.filter(o=>o.skill_id===request.skill_id&&!['not_assessed','absent','inaccessible'].includes(o.outcome)).map(o=>[o.id,'#'+o.id+' · '+o.observed_on])],'text','',true);resolve.finish();
    }else box.append(el('p',request.resolution));}
    const history=panel('Evidence and decision timeline',parent);history.id='learning-timeline';history.append(el('p','Activity is ordered by recording time; assessment dates are retained separately. Earlier judgments and corrections remain visible.'));
   }
   const timeline=$('learning-timeline');$('learning-older')?.remove();for(const event of data.activity.rows){const detail=el('details'),dl=el('dl');detail.append(el('summary',event.recorded_at+' · '+pretty(event.kind)+' · '+event.actor));for(const [key,value] of Object.entries(event.snapshot))dl.append(el('dt',pretty(key)),el('dd',typeof value==='object'?JSON.stringify(value):value));detail.append(dl);timeline.append(detail);}if(data.activity.has_more){const older=button('Older activity',()=>loadStudent(cid,sid,data.activity.next_before_id,true));older.id='learning-older';timeline.append(older);}
  }catch(error){if(stamp===generation)status.textContent=error.message;}
 }
 nav.onclick=()=>open();
 return {hide,clear,signedIn:async()=>{nav.hidden=!allowed();$('assistant').hidden=!!signedInUser&&['registrar','teacher'].includes(signedInUser.role);if(signedInUser?.role==='teacher')await open();}};
})();
