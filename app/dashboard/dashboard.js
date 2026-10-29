/* Same-origin client. Credentials and idempotency keys live only in this tab's memory. */
(() => {
  'use strict';
  const $ = id => document.getElementById(id);
  const state = {mode:'sample',credentials:null,identity:null,overview:null,detail:null,
    selected:null,tab:'overview',busy:0,epoch:0,selection:0,controllers:new Set(),keys:new Map(),pendingAction:null,connecting:false};
  const labels = {
    ATTACK_CONFIRMED:'Attack confirmed',ATTACK_FAILED:'Attack failed',INCONCLUSIVE:'Inconclusive',
    SIMULATED_ONLY:'Awaiting review',PENDING:'Pending decision',APPROVED:'Approved',REJECTED:'Rejected',
    SIMULATED_EXECUTED:'Simulated block',SIMULATION_FAILED:'Simulation failed',SIMULATED_ROLLED_BACK:'Rolled back',
    REQUEST_CREATED:'Response proposed',REQUEST_APPROVED:'Analyst approved',REQUEST_REJECTED:'Analyst rejected',
    AUTHENTICATED_INVESTIGATION:'Signed evidence assessed',SIMULATION_EXECUTING:'Simulation started',
    SIMULATION_VERIFIED:'Effect verified',SIMULATION_VERIFICATION_FAILED:'Verification failed',
    SIMULATION_ROLLING_BACK:'Rollback started',SIMULATION_ROLLBACK_DENIED:'Rollback denied',
    failed_login:'Repeated login failures',sql_injection:'SQL injection pattern',successful_login:'Successful login',
    authentication_logs:'Authentication logs',application_logs:'Application logs',fallback_rules:'Fallback rules',gemini:'Gemini',unknown:'Not recorded'
  };
  const label = value => labels[value] || String(value || 'Not recorded').replaceAll('_',' ').toLowerCase();
  const node = (tag, className, value) => {
    const element = document.createElement(tag);
    if (className) element.className = className;
    if (value !== undefined) element.textContent = String(value);
    return element;
  };
  const children = (parent,...items) => { parent.replaceChildren(...items); return parent; };
  const stamp = value => {
    if (!value) return 'Not recorded';
    const normalized = /^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d$/.test(value) ? value.replace(' ','T')+'Z' : value;
    const date = new Date(normalized);
    return Number.isNaN(date.getTime()) ? 'Unknown time' : new Intl.DateTimeFormat('en-GB',{
      month:'short',day:'2-digit',hour:'2-digit',minute:'2-digit',hour12:false,timeZone:'UTC'}).format(date)+' UTC';
  };
  const safeID = value => {
    if (!Number.isSafeInteger(value) || value < 1) throw new Error('This record ID cannot be represented safely in the browser. Use the API directly.');
    return String(value);
  };
  const badge = (value, style) => node('span','badge '+(style || (
    ['ATTACK_CONFIRMED','high'].includes(value) ? 'danger' :
    ['PENDING','APPROVED','medium','SIMULATED_ONLY'].includes(value) ? 'warning' :
    ['SIMULATED_ROLLED_BACK','SIMULATED_EXECUTED','ATTACK_FAILED','authenticated_current'].includes(value) ? 'success' : '')),
    value === 'authenticated_current' ? 'Current & verified' : value === 'sample_only' ? 'Sample record' : label(value));
  const sourceBadge = record => node('span','source-pill '+(record?.source || 'unknown'),
    '◈ '+label(record?.source || 'unknown')+(state.mode === 'sample' ? ' · sample' : ''));
  function notice(message, error=false) {
    $('notice').textContent = message; $('notice').className = 'notice'+(error ? ' error' : ''); $('notice').hidden = !message;
  }
  function busy(delta) {
    state.busy = Math.max(0,state.busy+delta); $('loading').hidden = !state.busy;
    $('refresh-button').disabled = !!state.busy;
    $('load-more').disabled = !!state.busy;
    renderActions();
  }
  function invalidate() {
    state.epoch++; state.selection++;
    for (const controller of state.controllers) controller.abort();
    state.controllers.clear(); state.credentials=null; state.identity=null; state.keys.clear();
    state.pendingAction=null; state.detail=null; state.selected=null; state.busy=0; state.connecting=false;
    $('analyst-token').value=''; $('action-reason').value=''; $('action-dialog').close();
    busy(0);
  }
  async function request(path, options={}) {
    if (!state.credentials) throw new Error('Connect an analyst identity first.');
    if (!path.startsWith('/') || path.startsWith('//')) throw new Error('Invalid API path.');
    const epoch=state.epoch; const credentials=state.credentials;
    const controller=new AbortController(); state.controllers.add(controller);
    const timeout=setTimeout(()=>controller.abort(),options.method ? 25000 : 12000);
    try {
      const response=await fetch(path,{...options,credentials:'omit',mode:'same-origin',cache:'no-store',
        signal:controller.signal,headers:{'X-Analyst-Id':credentials.id,'X-Analyst-Token':credentials.token,
          ...(options.body ? {'Content-Type':'application/json'} : {}),...options.headers}});
      const result=await response.json();
      if (epoch !== state.epoch) throw new DOMException('Session changed','AbortError');
      if (!response.ok) {
        if (state.mode === 'live' && (response.status === 401 || (response.status === 403 && result.detail === 'Analyst not authorized'))) {
          useSample(false); notice('Session expired or access was revoked. Credentials cleared; reconnect to continue.',true);
          throw new Error('Analyst session ended');
        }
        const error=new Error(result.detail || 'The server denied this request.'); error.status=response.status; throw error;
      }
      return result;
    } finally {clearTimeout(timeout); state.controllers.delete(controller);}
  }
  function fail(error, operation=false) {
    if (error.name === 'AbortError') {
      notice(operation ? 'The response was interrupted. The result may be committed. Refresh before retrying; this session retains the same idempotency key.' : 'Request cancelled or timed out. Refresh to try again.',true);
    } else if (error instanceof TypeError) {
      notice(operation ? 'Connection lost. The result is unknown. Refresh before retrying; the same idempotency key is retained in this session.' : 'Cannot reach the local API. Check that the server is running, then refresh.',true);
    } else notice(error.message,true);
  }
  function useSample(showNotice=true) {
    invalidate(); state.mode='sample'; state.overview=structuredClone(globalThis.SentinelSample.overview);
    state.selected=state.overview.incidents[0]?.id || null;
    state.detail=state.selected ? structuredClone(globalThis.SentinelSample.details[state.selected]) : null;
    $('session-label').textContent='Connect analyst'; $('sample-button').disabled=true;
    $('context-banner').replaceChildren(node('span','context-icon','◈'),
      children(node('div'),node('strong',null,'Sample walkthrough'),node('span',null,'Illustrative records. Read-only. Connect an analyst to view your local database.')),
      node('span','sample-pill','SAMPLE DATA'));
    $('search').value=''; $('status-filter').value='all';
    render(); if (showNotice) notice('');
  }
  function render() {
    const data=state.overview;
    if (!data) {
      for (const id of ['incidents','pending','active','rollbacks']) $('metric-'+id).textContent='—';
      $('incident-rows').replaceChildren(); $('alert-list').replaceChildren(); $('queue-count').textContent='0';
      $('queue-caption').textContent='No live snapshot loaded'; $('snapshot-time').textContent='Not loaded';
      $('queue-empty').hidden=false; $('load-more').hidden=true; renderDetail(); return;
    }
    for (const [id,key] of [['incidents','incidents'],['pending','pending'],['active','active_effects'],['rollbacks','rollbacks']]) $('metric-'+id).textContent=data.counts[key];
    $('snapshot-time').textContent=state.mode === 'sample' ? 'Illustrative snapshot' : 'Refreshed '+stamp(data.checked_at);
    $('queue-count').textContent=data.incidents.length;
    $('queue-caption').textContent=state.mode === 'sample' ? '3 illustrative cases · no database writes' : data.incidents.length+' loaded cases · newest first';
    $('load-more').hidden=state.mode !== 'live' || !data.has_more;
    renderQueue(); renderSignals(); renderDetail();
  }
  function renderQueue() {
    const term=$('search').value.trim().toLowerCase(), filter=$('status-filter').value;
    const rows=(state.overview?.incidents || []).filter(row=>{
      const response=row.request_status || row.response_status;
      const match=filter === 'all' || (filter === 'pending' && ['SIMULATED_ONLY','APPROVED'].includes(response)) ||
        (filter === 'active' && response === 'SIMULATED_EXECUTED') || (filter === 'rolled_back' && response === 'SIMULATED_ROLLED_BACK');
      return match && [row.id,row.source_ip,row.target,row.assessment,row.event_type].some(value=>String(value).toLowerCase().includes(term));
    });
    $('incident-rows').replaceChildren(...rows.map(row=>{
      const tr=node('tr',row.id === state.selected ? 'is-selected' : '');
      const open=node('button','case-open'); open.type='button';
      open.append(node('span',null,'INC–'+row.id),node('strong',null,label(row.event_type)),node('small',null,row.source_ip+' · '+row.target));
      open.setAttribute('aria-label','Open incident '+row.id+': '+label(row.event_type));
      if (row.id === state.selected) open.setAttribute('aria-current','true');
      open.addEventListener('click',()=>selectCase(row.id));
      const first=node('td'); first.append(open);
      const assessment=node('td'); assessment.append(badge(row.assessment));
      const response=node('td'); response.append(badge(row.request_status || row.response_status));
      tr.append(first,assessment,response,node('td',null,'›')); return tr;
    }));
    $('queue-empty').hidden=!!rows.length;
  }
  function renderSignals() {
    const alerts=state.overview?.alerts || [];
    $('alert-list').replaceChildren(...alerts.map(alert=>children(node('div','signal'),node('span','signal-icon','⌁'),
      children(node('div'),node('strong',null,label(alert.event_type)),node('p',null,alert.source_ip+' · '+alert.target)),node('time',null,stamp(alert.created_at)))));
    if (!alerts.length) $('alert-list').append(node('p','empty-state','No alerts have been recorded yet.'));
  }
  async function selectCase(id) {
    if (state.busy) return;
    try {safeID(id);} catch(error) {fail(error); return;}
    const selection=++state.selection; state.selected=id; state.detail=null; renderQueue(); renderDetail();
    if (state.mode === 'sample') {state.detail=structuredClone(globalThis.SentinelSample.details[id]); renderDetail(); return;}
    const epoch=state.epoch; busy(1);
    try {const detail=await request('/dashboard/api/incidents/'+safeID(id));
      if (selection === state.selection && epoch === state.epoch) {state.detail=detail; renderDetail();}
    } catch(error) {if (epoch === state.epoch) fail(error);} finally {if (epoch === state.epoch) busy(-1);}
  }
  function renderDetail() {
    const data=state.detail; $('detail-empty').hidden=!!data; $('case-content').hidden=!data;
    if (!data) return;
    const row=data.incident;
    $('case-number').textContent='INCIDENT '+row.id;
    children($('case-severity'),badge(row.severity)); $('case-severity').className='';
    $('case-title').textContent=label(row.event_type);
    $('case-ip').textContent=row.source_ip; $('case-target').textContent=row.target;
    $('case-assessment').textContent=label(row.assessment);
    $('outcome-summary').textContent=data.reasoning.outcome.summary || 'No outcome explanation was recorded.';
    children($('outcome-source'),sourceBadge(data.reasoning.outcome));
    children($('triage-source'),sourceBadge(data.reasoning.triage));
    $('triage-summary').textContent=[data.reasoning.triage.summary,data.reasoning.triage.fallback_reason ? 'Fallback: '+data.reasoning.triage.fallback_reason : ''].filter(Boolean).join(' ');
    $('timeline').replaceChildren(...data.timeline.map(event=>children(node('li'),node('strong',null,label(event.title)),
      children(node('div'),node('span',null,event.detail),node('time',null,stamp(event.at))))));
    children($('response-state'),badge(data.request?.status || 'NO_PROPOSAL')); $('response-state').className='';
    $('eligibility').textContent=state.mode === 'sample' ? 'Read-only walkthrough · connect an analyst to take action.' : data.eligibility.reason;
    $('eligibility-note').textContent=state.mode === 'sample' ? data.eligibility.reason : 'Snapshot: '+stamp(data.checked_at)+'. Advisory only; every action is authorized again by the server.';
    $('effect-state').textContent=data.block_present ? 'A simulated block record is currently present for this source IP. Other incidents may share it.' : 'No simulated block record is present for this source IP.';
    $('telemetry-list').replaceChildren(...data.telemetry.slice(0,3).map(item=>children(node('div','telemetry'),
      node('strong',null,label(item.operation)+' · '+(item.matched ? 'Probe matched' : 'Probe mismatch')),
      node('span',null,'Expected blocked: '+item.expected_blocked+' · Observed blocked: '+item.observed_blocked),
      node('div',null,'Synthetic SQLite probe · '+stamp(item.created_at)))));
    renderEvidence(); renderAudit(); renderActions(); setTab(state.tab);
  }
  function renderEvidence() {
    const data=state.detail;
    $('evidence-count').textContent=data.evidence.length;
    $('evidence-list').replaceChildren(...data.evidence.map(item=>{
      const card=node('article','evidence-card');
      card.append(children(node('header'),node('strong',null,label(item.tool)),badge(item.provenance,item.provenance === 'untrusted_or_expired' ? 'warning' : undefined)));
      const dl=node('dl','evidence-meta');
      for (const [key,value] of [['Collector',item.collector_id],['Collected',stamp(item.collected_at)],['Freshness',state.mode === 'sample' ? 'Illustrative only' : item.fresh ? 'Within the evidence window' : 'Expired or invalid']]) dl.append(node('dt',null,key),node('dd',null,value));
      card.append(dl);
      const observations=node('div','observations');
      for (const [key,value] of Object.entries(item.observations)) observations.append(children(node('div','observation'),node('span',null,label(key)),node('strong',null,String(value))));
      card.append(observations); return card;
    }));
    if (!data.evidence.length) $('evidence-list').append(node('div','empty-state','No signed collector evidence is stored for this incident.'));
    if (data.evidence_truncated) $('evidence-list').prepend(node('p','form-error','Showing the first 100 evidence records. Eligibility is denied for this truncated set.'));
    $('step-list').replaceChildren(...data.reasoning.steps.map(step=>children(node('div','step-row'),node('strong',null,label(step.tool)),node('span',null,step.status+' · '+step.source))));
    if (!data.reasoning.steps.length) $('step-list').append(node('p','reason-note','No investigation steps were recorded.'));
  }
  function renderAudit() {
    const data=state.detail;
    $('audit-caption').textContent=state.mode === 'sample' ? 'Illustrative sample events. No server audit records were written.' : (data.audit_has_more ? 'Latest 100 persisted events, oldest to newest. Use /audit-history for older records.' : 'Persisted server events for this incident, oldest to newest.');
    $('audit-list').replaceChildren(...data.audit.map(event=>children(node('article','audit-card'),
      children(node('header'),node('strong',null,label(event.action)),node('time',null,stamp(event.created_at))),
      node('p',null,'Actor: '+event.actor+' · Request: '+(event.request_id || 'not yet proposed')),
      node('p',null,Object.entries(event.details).map(([key,value])=>label(key)+': '+String(value)).join(' · ')))));
    if (!data.audit.length) $('audit-list').append(node('div','empty-state','No response audit events have been recorded for this incident.'));
  }
  const ACTIONS={
    review:{title:'Review signed collector logs',description:'Run the existing deterministic assessment of the current signed observations. This does not approve or execute a response.'},
    propose:{title:'Create a simulated response proposal',description:'Create a pending request from the verified incident. An authorized analyst must decide before execution.'},
    approve:{title:'Approve this proposal',description:'Record approval after reviewing current evidence. Approval never runs the simulation.',reason:true},
    reject:{title:'Reject this proposal',description:'Record a rejection and its review reason. This does not change a firewall or create an effect.',reason:true},
    execute:{title:'Run the approved simulation',description:'Create a simulated SQLite block, verify its database effect and record an audit receipt. No operating-system or network firewall action occurs.'},
    verify:{title:'Verify the simulated effect',description:'Probe the simulated block table and persist a verification audit. This checks database state, not real network traffic.'},
    rollback:{title:'Roll back the simulated effect',description:'Record an authorized rollback. A shared or legacy block may be retained to protect another active simulation.',reason:true}
  };
  function isStale() {return !state.detail || Date.now()-new Date(state.detail.checked_at).getTime()>60000;}
  function actionAllowed(action) {
    return state.mode === 'live' && !!state.identity?.can_decide && !state.busy && !isStale() && !!state.detail?.eligibility['can_'+action];
  }
  function renderActions() {
    if (state.mode === 'live' && state.detail && isStale()) $('eligibility-note').textContent='Snapshot expired. Refresh before taking an action. The server independently rechecks every operation.';
    for (const button of document.querySelectorAll('[data-action]')) {
      const action=button.dataset.action;
      button.disabled=!actionAllowed(action);
      button.title=state.mode !== 'live' ? 'Read-only sample. Connect an analyst to use API actions.' :
        !state.identity?.can_decide ? 'Your viewer role is read-only.' :
        isStale() ? 'Refresh the snapshot before taking an action.' :
        !state.detail?.eligibility['can_'+action] ? 'This action is unavailable in the current response state.' : ACTIONS[action].description;
    }
    $('action-submit').disabled=!!state.busy;
  }
  function setTab(tab, focus=false) {
    state.tab=tab;
    for (const button of document.querySelectorAll('[data-tab]')) {
      const selected=button.dataset.tab === tab;
      button.setAttribute('aria-selected',String(selected)); button.tabIndex=selected ? 0 : -1;
      $('view-'+button.dataset.tab).hidden=!selected;
      if (selected && focus) button.focus();
    }
  }
  async function refresh(append=false) {
    if (state.busy) return;
    if (state.mode === 'sample') {useSample(); return;}
    const epoch=state.epoch; busy(1); notice('');
    try {
      const before=append ? state.overview?.next_before_id : null;
      const result=await request('/dashboard/api/overview'+(before ? '?before_id='+safeID(before) : ''));
      if (epoch !== state.epoch) return;
      if (append) {
        const merged=new Map(state.overview.incidents.map(item=>[item.id,item]));
        for (const item of result.incidents) merged.set(item.id,item);
        result.incidents=[...merged.values()];
      }
      state.overview=result;
      if (!state.selected || !result.incidents.some(row=>row.id === state.selected)) state.selected=result.incidents[0]?.id || null;
      state.detail=state.selected ? await request('/dashboard/api/incidents/'+safeID(state.selected)) : null;
      if (epoch === state.epoch) {render(); return true;}
    } catch(error) {if (epoch === state.epoch) {state.detail=null; renderDetail(); fail(error);}}
    finally {if (epoch === state.epoch) busy(-1);}
    return false;
  }
  async function connect(event) {
    event.preventDefault(); if (state.busy) return;
    const id=$('analyst-id').value.trim(), token=$('analyst-token').value;
    invalidate(); state.credentials={id,token}; state.connecting=true; const epoch=state.epoch;
    $('connect-error').hidden=true; $('connect-submit').disabled=true; busy(1);
    try {
      const identity=await request('/dashboard/api/identity');
      if (epoch !== state.epoch) return;
      state.identity=identity; state.connecting=false; state.mode='live'; state.overview=null; state.detail=null;
      $('analyst-token').value=''; $('connect-dialog').close();
      $('session-label').textContent=identity.analyst_id+' · Disconnect'; $('sample-button').disabled=false;
      $('context-banner').replaceChildren(node('span','context-icon','◈'),
        children(node('div'),node('strong',null,identity.data_context === 'isolated_demo' ? 'Connected to isolated demo databases' : 'Connected to your local database'),
          node('span',null,identity.role+' access · explicit actions only · no automatic refresh')),
        node('span','sample-pill',identity.data_context === 'isolated_demo' ? 'ISOLATED DEMO · SIMULATION ONLY' : 'LIVE DATABASE · SIMULATION ONLY'));
      $('search').value=''; $('status-filter').value='all'; notice('');
      render();
    } catch(error) {
      if (epoch === state.epoch) {
        useSample(false); $('connect-error').textContent='Unable to connect. Check your analyst ID, token and server availability.';
        $('connect-error').hidden=false; $('analyst-token').value='';
      }
    } finally {$('connect-submit').disabled=false; if (epoch === state.epoch) busy(-1);}
    if (state.mode === 'live') await refresh();
  }
  function openAction(action) {
    if (!actionAllowed(action)) return;
    state.pendingAction={action,incident:state.detail.incident.id,request:state.detail.request?.id};
    $('action-title').textContent=ACTIONS[action].title;
    $('action-description').textContent='Incident '+state.detail.incident.id+'. '+ACTIONS[action].description;
    $('reason-field').hidden=!ACTIONS[action].reason; $('action-reason').required=!!ACTIONS[action].reason;
    $('action-reason').disabled=!ACTIONS[action].reason; $('action-reason').setCustomValidity('');
    $('action-reason').value=''; $('action-dialog').showModal();
  }
  async function submitAction(event) {
    event.preventDefault(); const pending=state.pendingAction;
    if (!pending || !actionAllowed(pending.action) || state.detail.incident.id !== pending.incident) return;
    const reason=$('action-reason').value.trim();
    if (ACTIONS[pending.action].reason && reason.length<3) {$('action-reason').setCustomValidity('Enter at least three non-space characters.'); $('action-reason').reportValidity(); return;}
    const action=pending.action, epoch=state.epoch; const options={method:'POST'};
    let path;
    try {
      if (action === 'review') path='/incidents/'+safeID(pending.incident)+'/investigate-authenticated';
      else if (action === 'propose') path='/response-requests/for-incident/'+safeID(pending.incident);
      else {
        path='/response-requests/'+safeID(pending.request)+'/'+(['approve','reject'].includes(action) ? 'decision' : action);
        if (['approve','reject'].includes(action)) options.body=JSON.stringify({decision:action === 'approve' ? 'APPROVED' : 'REJECTED',reason});
        if (['execute','rollback'].includes(action)) {
          const name=pending.request+'/'+action;
          if (!state.keys.has(name)) state.keys.set(name,'dashboard-'+crypto.randomUUID());
          options.headers={'Idempotency-Key':state.keys.get(name)};
        }
        if (action === 'rollback') options.body=JSON.stringify({reason});
      }
    } catch(error) {fail(error); return;}
    busy(1); $('action-dialog').close();
    let success=false;
    try {
      const result=await request(path,options); success=true;
      if (epoch === state.epoch) notice(label(result.status || result.assessment)+(result.replayed ? ' · Historical receipt returned.' : ' · Recorded by the server.'));
    } catch(error) {if (epoch === state.epoch) {if (state.detail) state.detail.checked_at='1970-01-01T00:00:00Z'; fail(error,true);}} finally {
      if (epoch === state.epoch) {state.pendingAction=null; busy(-1);}
    }
    if (success && epoch === state.epoch) {
      const message=$('notice').textContent; const refreshed=await refresh(); if (refreshed && epoch === state.epoch) notice(message);
    }
  }

  $('session-button').addEventListener('click',()=>{
    if (state.mode === 'live') {useSample(); notice('Disconnected. Analyst credentials and operation keys were cleared.');}
    else {$('connect-error').hidden=true; $('connect-dialog').showModal();}
  });
  $('sample-button').addEventListener('click',()=>useSample());
  $('refresh-button').addEventListener('click',()=>refresh()); $('load-more').addEventListener('click',()=>refresh(true));
  $('search').addEventListener('input',renderQueue); $('status-filter').addEventListener('change',renderQueue);
  $('connect-form').addEventListener('submit',connect); $('action-form').addEventListener('submit',submitAction);
  $('action-reason').addEventListener('input',()=> $('action-reason').setCustomValidity(''));
  for (const button of document.querySelectorAll('[data-close]')) button.addEventListener('click',()=>$(button.dataset.close).close());
  $('connect-dialog').addEventListener('close',()=>{
    $('analyst-token').value='';
    if (state.connecting) {useSample(false); notice('Connection cancelled. Credentials cleared.');}
  });
  $('action-dialog').addEventListener('close',()=>{$('action-reason').value='';$('action-reason').setCustomValidity('');state.pendingAction=null;});
  for (const button of document.querySelectorAll('[data-action]')) button.addEventListener('click',()=>openAction(button.dataset.action));
  const tabs=[...document.querySelectorAll('[data-tab]')];
  for (const [index,button] of tabs.entries()) {
    button.addEventListener('click',()=>setTab(button.dataset.tab));
    button.addEventListener('keydown',event=>{
      let next;
      if (event.key === 'ArrowRight') next=(index+1)%tabs.length;
      else if (event.key === 'ArrowLeft') next=(index+tabs.length-1)%tabs.length;
      else if (event.key === 'Home') next=0;
      else if (event.key === 'End') next=tabs.length-1;
      if (next !== undefined) {event.preventDefault(); setTab(tabs[next].dataset.tab,true);}
    });
  }
  for (const button of document.querySelectorAll('[data-nav]')) button.addEventListener('click',()=>{
    for (const other of document.querySelectorAll('[data-nav]')) other.classList.toggle('selected',other===button);
    if (button.dataset.nav === 'audit') {setTab('audit'); $('detail-panel').scrollIntoView({behavior:'smooth',block:'start'});}
    else if (button.dataset.nav === 'incidents') $('queue-panel').scrollIntoView({behavior:'smooth',block:'start'});
    else $('main').scrollIntoView({behavior:'smooth',block:'start'});
  });
  // A restored page never keeps an analyst session alive through the back/forward cache.
  addEventListener('pagehide',()=>invalidate());
  addEventListener('pageshow',event=>{if (event.persisted) useSample();});
  setInterval(renderActions,5000);
  useSample();
})();
