const modules = {
 students: {title:'Students', fields:['name','year','guardian'], description:'Keep student enrollment and guardian contact details together.'},
 attendance: {title:'Attendance', fields:['student','date','status'], description:'Record daily attendance with a student name or school identifier.'},
 grades: {title:'Grades', fields:['student','subject','grade'], description:'Capture subject results for each student.'},
 assets: {title:'IT inventory', fields:['tag','device','location','status'], description:'Track school equipment, locations, and availability.'},
 audits: {title:'IT audits', fields:['area','finding','status'], description:'Record technology audit findings and their resolution status.'},
 tickets: {title:'Support tickets', fields:['title','requester','priority','status'], description:'Keep school support requests and priorities visible.'}
};
const choices = {'attendance.status':['Present','Absent','Late'],'assets.status':['Available','In use','Repair'],'audits.status':['Open','In progress','Resolved'],'tickets.status':['Open','In progress','Resolved'],'tickets.priority':['Low','Medium','High']};
let current = null, records = [], counts = {};
const $ = id => document.getElementById(id);
const label = name => name.charAt(0).toUpperCase()+name.slice(1);
async function api(path, options) { const response = await fetch('/api/'+path, options); const data = await response.json(); if(!response.ok) throw new Error(data.error || 'Request failed'); return data; }
function cell(tag, text) { const element=document.createElement(tag); element.textContent=text; return element; }
function drawRows() {
 $('rows').replaceChildren();
 const filtered=records.filter(row=>Object.values(row).join(' ').toLowerCase().includes($('search').value.toLowerCase()));
 for(const row of filtered) { const tr=document.createElement('tr'); for(const field of modules[current].fields) tr.append(cell('td',row[field])); $('rows').append(tr); }
 if(!filtered.length) { const tr=document.createElement('tr'), td=cell('td',records.length?'No matching records.':'No records yet. Add your first record above.'); td.colSpan=modules[current].fields.length;tr.append(td);$('rows').append(tr); }
}
async function show(key) {
 current=key; $('error').textContent='';
 document.querySelectorAll('nav button').forEach(button=>button.classList.toggle('active',button.dataset.key===(key||'')));
 $('overview').hidden=!!key; $('module').hidden=!key; $('breadcrumb').textContent=key?modules[key].title:'Overview';
 if(!key) { await dashboard();return; }
 const module=modules[key]; $('title').textContent=module.title;$('description').textContent=module.description;$('category').textContent=['students','attendance','grades'].includes(key)?'SCHOOL ADMINISTRATION':'IT OPERATIONS';$('message').textContent='';$('search').value='';$('form').replaceChildren();
 for(const field of module.fields) { const wrapper=cell('label',label(field)); const options=choices[key+'.'+field]; const input=document.createElement(options?'select':'input');input.name=field;input.required=true;if(options) options.forEach(value=>{const option=cell('option',value);option.value=value;input.append(option);});else {input.type=field==='date'?'date':'text';input.maxLength=500;}wrapper.append(input);$('form').append(wrapper); }
 const submit=cell('button','Save record');submit.type='submit';$('form').append(submit);
 const tr=document.createElement('tr');module.fields.forEach(field=>tr.append(cell('th',label(field))));$('head').replaceChildren(tr);$('rows').replaceChildren();
 try { const result=await api(key); if(current===key){records=result;drawRows();} }catch(error){$('error').textContent=error.message;}
}
async function dashboard() {
 try {const results=await Promise.all(Object.keys(modules).map(async key=>[key,(await api(key)).length]));counts=Object.fromEntries(results);$('cards').replaceChildren();for(const [key,module] of Object.entries(modules)){const button=document.createElement('button');button.className='card';button.append(cell('div',module.title),cell('strong',counts[key]),cell('span','View records →'));button.onclick=()=>show(key);$('cards').append(button);}}catch(error){$('error').textContent=error.message;}
}
for(const [key,title] of [['','Overview'],...Object.entries(modules).map(([key,m])=>[key,m.title])]){const button=cell('button',title);button.dataset.key=key;button.onclick=()=>show(key||null);$('nav').append(button);}
$('search').oninput=drawRows;
$('form').onsubmit=async event=>{event.preventDefault();const key=current;const data=Object.fromEntries(new FormData(event.target));const button=event.target.querySelector('button');button.disabled=true;try{await api(key,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(data)});if(current===key){await show(key);$('message').textContent='Record saved.';}}catch(error){$('error').textContent=error.message;}finally{button.disabled=false;}};
show(null);
