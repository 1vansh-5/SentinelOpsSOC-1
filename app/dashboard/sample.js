/* Illustrative records only. Never ingested, signed, or eligible for a real API action. */
(() => {
  'use strict';
  const base = new Date(); base.setUTCSeconds(0, 0);
  const at = minutes => new Date(base.getTime() - minutes * 60000).toISOString();
  const incident = (id, event, assessment, status, severity, ip, target) => ({
    id, alert_id:id - 1000, created_at:at(id === 1042 ? 8 : id === 1041 ? 23 : 47),
    event_type:event, assessment, response_status:status, severity, source_ip:ip,
    target, confidence:'high', reasoning_source:'fallback_rules'
  });
  const cases = [
    incident(1042,'failed_login','ATTACK_CONFIRMED','SIMULATED_ONLY','high','8.8.8.8','identity-gateway'),
    incident(1041,'sql_injection','ATTACK_FAILED','SIMULATED_ONLY','medium','1.1.1.1','customer-api'),
    incident(1040,'failed_login','ATTACK_CONFIRMED','SIMULATED_ROLLED_BACK','high','9.9.9.9','admin-console')
  ];
  cases[0].request_status='PENDING'; cases[1].request_status=null; cases[2].request_status='SIMULATED_ROLLED_BACK';
  const audit = (id,action,minutes,details={}) => ({id,action,actor:'sample_analyst',created_at:at(minutes),request_id:501,details});
  const details = {};
  for (const [index, row] of cases.entries()) {
    const failed = row.id === 1041; const rolled = row.id === 1040;
    const request = failed ? null : {id:rolled ? 499 : 501,incident_id:row.id,
      status:rolled ? 'SIMULATED_ROLLED_BACK' : 'PENDING',
      source_ip:row.source_ip,action:'SIMULATED_BLOCK',requested_at:at(rolled ? 43 : 5),
      decided_at:rolled ? at(42) : null,decided_by:rolled ? 'sample_analyst' : null,
      lifecycle_state:rolled ? 'ROLLED_BACK' : null};
    const evidence = [
      {id:101+index*2,collector_id:'sample-edge-01',collected_at:at(rolled ? 45 : 7+index*15),
        provenance:'sample_only',fresh:false,tool:'authentication_logs',observations:{
          login_attempts:36,failed_logins:failed ? 36 : 35,successful_login:!failed,session_created:!failed}},
      {id:102+index*2,collector_id:'sample-app-01',collected_at:at(rolled ? 44 : 6+index*15),
        provenance:'sample_only',fresh:false,tool:'application_logs',observations:{
          unauthorized_access_observed:!failed,http_status:failed ? 403 : 200}}
    ];
    const events = failed ? [] : [audit(1,'AUTHENTICATED_INVESTIGATION',rolled ? 44 : 6),audit(2,'REQUEST_CREATED',rolled ? 43 : 5)];
    if (rolled) events.push(
      audit(3,'REQUEST_APPROVED',42,{reason:'Sample: reviewed corroborating observations.'}),
      audit(4,'SIMULATION_EXECUTING',41,{mode:'SIMULATION_ONLY'}),
      audit(5,'SIMULATED_EXECUTED',41,{verification_status:'VERIFIED'}),
      audit(6,'SIMULATION_ROLLING_BACK',36,{reason:'Sample walkthrough complete.'}),
      audit(7,'SIMULATED_ROLLED_BACK',36,{block_retained:false,verification_status:'VERIFIED'})
    );
    const explanation = failed ? 'The illustrative login attempts failed and the application denied access. Monitor the attempt; no response proposal is shown.' :
      'Illustrative authentication and application observations corroborate a completed login and unauthorized access. A response requires an explicit analyst decision.';
    details[row.id] = {
      checked_at:at(0), mode:'SIMULATION_ONLY',incident:row,
      alert:{...row,id:row.alert_id,created_at:at(rolled ? 48 : index*15+9),details:'Synthetic illustrative walkthrough. No collector data was ingested.'},
      reasoning:{triage:{source:rolled ? 'gemini' : 'fallback_rules',ai_status:rolled ? 'gemini' : 'fallback_rules',
        summary:rolled ? 'Illustrative Gemini advisory: correlate the authentication event with application logs.' : 'Deterministic triage: correlate repeated failed logins with current collector observations.',
        fallback_reason:rolled ? '' : 'SAMPLE_FALLBACK',assessment:'REQUIRES_REVIEW',model:rolled ? 'gemini-3.5-flash-lite' : ''},
        outcome:{source:'fallback_rules',ai_status:'fallback_rules',summary:explanation,fallback_reason:'',assessment:row.assessment},
        steps:evidence.map(e=>({tool:e.tool,status:'completed',source:'sample_only',reasoning_source:'fallback_rules'}))},
      evidence,evidence_truncated:false,request,
      eligibility:{advisory:true,reason:'Read-only sample. These illustrative records are not cryptographically verified and cannot authorize API actions.',
        evidence_current:false,can_review:false,can_propose:false,can_approve:false,can_reject:false,
        can_execute:false,can_verify:false,can_rollback:false},
      telemetry:rolled ? [{id:2,operation:'ROLLBACK',source:'synthetic_sqlite_probe',created_at:at(36),expected_blocked:false,observed_blocked:false,matched:true},
        {id:1,operation:'EXECUTION',source:'synthetic_sqlite_probe',created_at:at(41),expected_blocked:true,observed_blocked:true,matched:true}] : [],
      audit:events,audit_has_more:false,block_present:false,
      timeline:[{at:at(rolled ? 48 : index*15+9),title:'Alert recorded',detail:'Illustrative '+row.event_type},
        {at:row.created_at,title:'Investigation recorded',detail:'Illustrative '+row.assessment},
        ...events.map(e=>({at:e.created_at,title:e.action,detail:e.actor}))]
    };
  }
  globalThis.SentinelSample = {
    overview:{checked_at:at(0),mode:'SIMULATION_ONLY',counts:{incidents:3,pending:1,active_effects:0,rollbacks:1},
      incidents:cases,alerts:cases.map(c=>({...c,id:c.alert_id,status:'investigated',created_at:c.created_at})),has_more:false,next_before_id:null},
    details
  };
})();
