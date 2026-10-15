(async()=>{
  const expected="irn:intuit::identity:remediation/session-has-recent-authentication";
  const report=message=>{
    document.title=message;
    document.documentElement.setAttribute("data-intuit-auth-diagnostic",message);
    alert(message);
  };
  const live=v=>!!(v&&typeof v.remediate==="function"&&v.authorization&&typeof v.authorization.isAuthorizedBatch==="function");
  const fromProps=p=>{
    if(!p)return null;
    if(live(p.sandbox))return p.sandbox;
    if(live(p.pluginSandbox))return p.pluginSandbox;
    for(const st of [p.store,p.value&&p.value.store]){
      try{
        const state=st&&typeof st.getState==="function"&&st.getState();
        if(state&&state.appState&&live(state.appState.sandbox))return state.appState.sandbox;
      }catch(_e){}
    }
    return null;
  };
  const fromFiber=f=>{
    const seen=new WeakSet();
    while(f&&typeof f==="object"&&!seen.has(f)){
      seen.add(f);
      for(const p of [f.memoizedProps,f.pendingProps,f.stateNode&&f.stateNode.props]){
        const sb=fromProps(p);
        if(sb)return sb;
      }
      f=f.return;
    }
    return null;
  };
  let sandbox=null;
  for(const el of document.querySelectorAll("*")){
    for(const key of Object.getOwnPropertyNames(el)){
      if(key.startsWith("__reactFiber$")||key.startsWith("__reactInternalInstance$")||key.startsWith("__reactContainer$")){
        sandbox=fromFiber(el[key]);
        if(sandbox)break;
      }
    }
    if(sandbox)break;
  }
  if(!sandbox){report("Intuit sandbox not found");return;}
  const request={
    batchRequest:[{
      resource:{id:"irn.intuit.authentication.verifyAuthCredentialWriteAccess"},
      action:{id:"read"}
    }],
    apiVersion:"v2"
  };
  const getDecision=async()=>{
    const result=await sandbox.authorization.isAuthorizedBatch(request);
    if(!Array.isArray(result)||!result.length||!result[0]||typeof result[0].isAuthorized!=="boolean"){
      throw new Error("Credential-write authorization returned no decision");
    }
    return result[0];
  };
  let decision=await getDecision();
  if(!decision.isAuthorized){
    const remediation=(decision.remediation||[]).find(x=>x&&x.id===expected);
    if(!remediation){
      report("Credential-write denied without expected recent-auth remediation");
      return;
    }
    await sandbox.remediate({
      remediations:btoa(JSON.stringify({remediations:[{id:remediation.id}]}))
    });
    decision=await getDecision();
  }
  report("Credential-write recentAuth="+!!decision.isAuthorized);
})()
