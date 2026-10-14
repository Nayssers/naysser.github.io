(() => {
  const marker = "H1_EXTERNAL_JS_LOADED_91D4";
  globalThis.__H1_EXTERNAL_JS_PROOF__ = marker;
  document.title = marker;

  const proof = document.createElement("div");
  proof.id = "h1-external-js-proof";
  proof.textContent = marker;
  proof.style.cssText =
    "position:fixed;inset:16px auto auto 16px;z-index:2147483647;padding:12px;background:#fff;color:#000;border:2px solid #000;font:16px monospace";
  document.body.appendChild(proof);
})();
