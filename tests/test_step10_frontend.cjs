/* Framework-free DOM contract tests. These are not browser layout/visual tests. */
'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const {randomUUID} = require('node:crypto');
const {test} = require('node:test');
const assets=path.join(__dirname,'..','app','dashboard');

class Element {
  constructor(tag='div') {this.tagName=tag.toUpperCase();this.children=[];this.attributes={};this.dataset={};this.listeners={};this.value='';this.hidden=false;this.disabled=false;this.open=false;this.className='';this._text='';
    this.classList={toggle:(name,on)=>{const classes=new Set(this.className.split(' ').filter(Boolean));on ? classes.add(name) : classes.delete(name);this.className=[...classes].join(' ');}};}
  set textContent(value) {this._text=String(value);this.children=[];}
  get textContent() {return this._text+this.children.map(child=>child.textContent).join('');}
  append(...items) {this.children.push(...items);}
  replaceChildren(...items) {this._text='';this.children=[...items];}
  prepend(...items) {this.children.unshift(...items);}
  setAttribute(key,value) {this.attributes[key]=String(value);if(key.startsWith('data-')) this.dataset[key.slice(5)]=String(value);}
  getAttribute(key) {return this.attributes[key] ?? null;}
  addEventListener(event,fn) {(this.listeners[event] ||= []).push(fn);}
  async fire(event,values={}) {if(event==='click' && this.disabled) return;for(const fn of this.listeners[event] || []) await fn({preventDefault(){},...values});}
  showModal() {this.open=true;}
  close() {if(this.open){this.open=false;for(const fn of this.listeners.close || []) fn();}}
  focus() {this.focused=true;}
  scrollIntoView() {}
  setCustomValidity(value) {this.validationMessage=value;}
  reportValidity() {return !this.validationMessage;}
}

function harness({viewer=false,status='PENDING',failAuth=false}={}) {
  const ids=new Map(), elements=[], events={}, timers=[];
  const html=fs.readFileSync(path.join(assets,'index.html'),'utf8');
  for(const match of html.matchAll(/<([a-z][\w-]*)\b([^>]*)>/gi)) {
    const element=new Element(match[1]), attributes=match[2];
    for(const attr of attributes.matchAll(/([\w-]+)(?:="([^"]*)")?/g)) {
      const name=attr[1], value=attr[2] || '';element.setAttribute(name,value);
      if(name==='id') ids.set(value,element);
      if(name==='hidden') element.hidden=true;
      if(name==='disabled') element.disabled=true;
    }
    elements.push(element);
  }
  const document={getElementById:id=>{assert(ids.has(id),'Unknown DOM id '+id);return ids.get(id);},
    createElement:tag=>new Element(tag),querySelectorAll:selector=>{
      const attr=selector.match(/^\[([^\]]+)\]$/)?.[1];assert(attr,'Unsupported test selector '+selector);
      return elements.filter(element=>Object.hasOwn(element.attributes,attr));
    }};
  let clock=Date.now();class ClockDate extends Date {constructor(value){super(value===undefined ? clock : value);}static now(){return clock;}}
  const requests=[];let model,overview;let failingExecution=false;let deferredOverview=null;let overviewEntered=null;
  let deferredIdentity=null,identityEntered=null,revoked=false;
  const runtime={document,structuredClone,AbortController,DOMException,TypeError,Date:ClockDate,Intl,
    crypto:{randomUUID},setTimeout,clearTimeout,setInterval:fn=>{timers.push(fn);return 0;},
    addEventListener:(event,fn)=>{events[event]=fn;},console};
  Object.defineProperty(runtime,'localStorage',{get(){throw new Error('Persistent credential storage is forbidden');}});
  Object.defineProperty(runtime,'sessionStorage',{get(){throw new Error('Persistent credential storage is forbidden');}});
  const context=vm.createContext(runtime);
  vm.runInContext(fs.readFileSync(path.join(assets,'sample.js'),'utf8'),context);
  model=structuredClone(runtime.SentinelSample.details[1042]);
  model.incident.id=3;model.incident.alert_id=3;model.request.id=3;model.request.incident_id=3;
  model.evidence.forEach(item=>{item.provenance='authenticated_current';item.fresh=true;});
  model.eligibility={advisory:true,reason:'Current collector evidence verified',evidence_current:true,
    can_review:false,can_propose:false,can_approve:status==='PENDING',can_reject:status==='PENDING',
    can_execute:status==='APPROVED',can_verify:false,can_rollback:false};
  model.checked_at=new Date(clock).toISOString();model.request.status=status;
  model.incident.request_status=status;
  overview={checked_at:model.checked_at,counts:{incidents:1,pending:1,active_effects:0,rollbacks:0},
    incidents:[model.incident],alerts:[model.alert],has_more:false,next_before_id:null};
  runtime.fetch=async(url,options)=>{
    requests.push({url,options});
    assert.equal(options.credentials,'omit');assert.equal(options.mode,'same-origin');
    assert.equal(options.cache,'no-store');assert(!url.includes('test-token'));
    assert.equal(options.headers['X-Analyst-Id'],'test_analyst');
    assert.equal(options.headers['X-Analyst-Token'],'test-token-'+'a'.repeat(40));
    const response=(data,code=200)=>({ok:code===200,status:code,json:async()=>structuredClone(data)});
    if(url==='/dashboard/api/identity') {
      if(deferredIdentity) {identityEntered();return deferredIdentity;}
      return failAuth ? response({detail:'Analyst not authorized'},403) :
        response({analyst_id:'test_analyst',role:viewer ? 'viewer' : 'analyst',can_decide:!viewer});
    }
    if(url==='/dashboard/api/overview') {
      if(revoked) return response({detail:'Analyst not authorized'},403);
      if(deferredOverview) {if(overviewEntered) overviewEntered();return deferredOverview;}
      return response(overview);
    }
    if(url==='/dashboard/api/incidents/3') return response(model);
    if(url==='/response-requests/3/decision') {
      const payload=JSON.parse(options.body);model.request.status=payload.decision;
      model.incident.request_status=payload.decision;
      model.eligibility.can_approve=false;model.eligibility.can_reject=false;
      model.eligibility.can_execute=payload.decision==='APPROVED';
      return response({status:payload.decision});
    }
    if(url==='/response-requests/3/execute') {
      if(failingExecution) {failingExecution=false;throw new TypeError('Injected lost connection');}
      model.request.status='SIMULATED_EXECUTED';model.incident.request_status='SIMULATED_EXECUTED';
      model.eligibility.can_execute=false;model.eligibility.can_rollback=true;model.eligibility.can_verify=true;
      return response({status:'SIMULATED_EXECUTED',replayed:false});
    }
    if(url==='/response-requests/3/rollback') {
      model.request.status='SIMULATED_ROLLED_BACK';model.eligibility.can_rollback=false;model.eligibility.can_verify=false;
      return response({status:'SIMULATED_ROLLED_BACK',replayed:false});
    }
    throw new Error('Unexpected client request '+url);
  };
  vm.runInContext(fs.readFileSync(path.join(assets,'dashboard.js'),'utf8'),context);
  const byID=id=>ids.get(id);
  const action=name=>elements.find(element=>element.dataset.action===name);
  const tab=name=>elements.find(element=>element.dataset.tab===name);
  const connect=async()=>{
    await byID('session-button').fire('click');
    byID('analyst-id').value='test_analyst';byID('analyst-token').value='test-token-'+'a'.repeat(40);
    await byID('connect-form').fire('submit');
  };
  return {byID,action,tab,connect,requests,model,overview,elements,events,timers,
    advance:milliseconds=>{clock+=milliseconds;for(const timer of timers) timer();},
    revoke:()=>{revoked=true;},
    failExecution:()=>{failingExecution=true;},
    deferIdentity:()=>{let resolve;deferredIdentity=new Promise(r=>{resolve=r;});
      const finish=()=>resolve({ok:true,status:200,json:async()=>({analyst_id:'test_analyst',role:'analyst',can_decide:true})});
      finish.started=new Promise(r=>{identityEntered=r;});return finish;},
    deferOverview:()=>{let resolve;deferredOverview=new Promise(r=>{resolve=r;});
      const finish=data=>resolve({ok:true,status:200,json:async()=>data});
      finish.started=new Promise(r=>{overviewEntered=r;});return finish;}
  };
}

test('default walkthrough makes no requests and disables mutations',()=>{
  const app=harness();assert.equal(app.requests.length,0);
  assert.equal(app.byID('incident-rows').children.length,3);
  assert(app.byID('context-banner').textContent.includes('SAMPLE DATA'));
  assert(app.elements.filter(e=>e.dataset.action).every(e=>e.disabled));
});

test('case selection, evidence/audit tabs, source labels and search work',async()=>{
  const app=harness();
  await app.byID('incident-rows').children[2].children[0].children[0].fire('click');
  assert(app.byID('triage-source').textContent.includes('Gemini · sample'));
  await app.tab('evidence').fire('click');assert.equal(app.byID('view-evidence').hidden,false);
  assert.equal(app.byID('evidence-list').children.length,2);
  await app.tab('audit').fire('click');assert.equal(app.byID('view-audit').hidden,false);
  assert(app.byID('audit-list').textContent.includes('Rolled back'));
  app.byID('search').value='does-not-exist';await app.byID('search').fire('input');
  assert.equal(app.byID('queue-empty').hidden,false);
  await app.tab('audit').fire('keydown',{key:'Home'});
  assert.equal(app.tab('overview').getAttribute('aria-selected'),'true');
});

test('connect uses headers, clears the token field and supports viewer read-only access',async()=>{
  const app=harness({viewer:true});await app.connect();
  assert.equal(app.requests.length,3);
  assert(app.byID('session-label').textContent.includes('Disconnect'));
  assert.equal(app.byID('analyst-token').value,'');
  assert(app.elements.filter(e=>e.dataset.action).every(e=>e.disabled));
  await app.byID('session-button').fire('click');
  assert.equal(app.byID('session-label').textContent,'Connect analyst');
});

test('failed sign-in stays in sample mode and gives an accessible error',async()=>{
  const app=harness({failAuth:true});await app.connect();
  assert.equal(app.byID('connect-error').hidden,false);
  assert.equal(app.byID('analyst-token').value,'');
  assert.equal(app.byID('session-label').textContent,'Connect analyst');
});

test('approval requires confirmation and never executes a simulation',async()=>{
  const app=harness();await app.connect();
  assert.equal(app.action('approve').disabled,false);
  await app.action('approve').fire('click');
  assert.equal(app.requests.filter(r=>r.options.method==='POST').length,0);
  assert.equal(app.byID('action-dialog').open,true);
  app.byID('action-reason').value='Current signed observations reviewed';
  await app.byID('action-form').fire('submit');
  const posts=app.requests.filter(r=>r.options.method==='POST');
  assert.equal(posts.length,1);assert.equal(posts[0].url,'/response-requests/3/decision');
  assert.equal(JSON.parse(posts[0].options.body).decision,'APPROVED');
  assert.equal(app.action('execute').disabled,false);
  assert.equal(app.byID('action-reason').value,'');
});

test('ambiguous execution requires refresh and retries with the same key',async()=>{
  const app=harness({status:'APPROVED'});await app.connect();app.failExecution();
  await app.action('execute').fire('click');await app.byID('action-form').fire('submit');
  assert(app.byID('notice').textContent.includes('result is unknown'));
  assert.equal(app.action('execute').disabled,true);
  await app.byID('refresh-button').fire('click');
  await app.action('execute').fire('click');await app.byID('action-form').fire('submit');
  const posts=app.requests.filter(r=>r.url.endsWith('/execute'));
  assert.equal(posts.length,2);
  assert.equal(posts[0].options.headers['Idempotency-Key'],posts[1].options.headers['Idempotency-Key']);
  assert.match(posts[0].options.headers['Idempotency-Key'],/^dashboard-[a-f0-9-]{36}$/);
  assert.equal(app.action('execute').disabled,true); // The committed detail, not an old overview row, controls actions.
});

test('snapshot expires and a refresh restores eligible actions',async()=>{
  const app=harness({status:'APPROVED'});await app.connect();
  app.advance(61000);assert.equal(app.action('execute').disabled,true);
  assert(app.byID('eligibility-note').textContent.includes('Snapshot expired'));
});

test('live loading clears all illustrative rows before accepting server data',async()=>{
  const app=harness();const resolve=app.deferOverview();
  const connecting=app.connect();
  // Wait for the request boundary, without assuming a number of promise turns.
  await resolve.started;
  assert.equal(app.byID('incident-rows').children.length,0);
  assert.equal(app.byID('metric-incidents').textContent,'—');
  assert.equal(app.byID('queue-caption').textContent,'No live snapshot loaded');
  resolve(app.overview);await connecting;
  assert.equal(app.byID('incident-rows').children.length,1);
});

test('disconnect during a pending refresh cannot restore records or credentials',async()=>{
  const app=harness();await app.connect();
  const resolve=app.deferOverview();const pending=app.byID('refresh-button').fire('click');
  await app.byID('session-button').fire('click');resolve(app.overview);await pending;
  assert.equal(app.byID('session-label').textContent,'Connect analyst');
  assert(app.byID('context-banner').textContent.includes('SAMPLE DATA'));
  assert(app.elements.filter(e=>e.dataset.action).every(e=>e.disabled));
});

test('provider and collector text is inserted as text nodes',async()=>{
  const app=harness();app.model.reasoning.outcome.summary='<img src=x onerror=alert(1)> untrusted data';
  await app.connect();
  assert.equal(app.byID('outcome-summary').textContent,'<img src=x onerror=alert(1)> untrusted data');
  assert.equal(app.byID('outcome-summary').children.length,0);
  app.events.pagehide();assert(app.elements.filter(e=>e.dataset.action).every(e=>e.disabled));
});

test('cancelling a pending sign-in cannot establish a late session',async()=>{
  const app=harness();const resolve=app.deferIdentity();const connecting=app.connect();
  await resolve.started;app.byID('connect-dialog').close();resolve();await connecting;
  assert.equal(app.byID('session-label').textContent,'Connect analyst');
  assert(app.byID('notice').textContent.includes('Connection cancelled'));
  assert.equal(app.byID('analyst-token').value,'');
});

test('server revocation clears the session and explains the switch to sample data',async()=>{
  const app=harness();await app.connect();app.revoke();
  await app.byID('refresh-button').fire('click');
  assert.equal(app.byID('session-label').textContent,'Connect analyst');
  assert(app.byID('notice').textContent.includes('access was revoked'));
  assert(app.byID('context-banner').textContent.includes('SAMPLE DATA'));
});
