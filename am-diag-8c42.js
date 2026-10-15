/*
 * p46: native-sequence Intuit sign-in email-change validation with fixed,
 * non-sensitive diagnostic states for a
 * researcher-owned account.
 *
 * REVIEW/EXECUTION RULES
 * - This source file is inert until a researcher intentionally executes it
 *   on https://accounts.intuit.com while signed in to their own account.
 * - Use a newly created Guerrilla Mail inbox. The researcher enters the
 *   address and OTP locally; this script never sends Guerrilla mailbox tokens
 *   through a proxy.
 * - Intuit cookies, session identifiers, verifier tokens, OTPs, auth IDs, and
 *   response bodies are never printed, placed in the document title, or sent
 *   to a third-party host.
 * - The existing Account Manager DOM is preserved. Only a small status/input
 *   panel is appended.
 * - Candidate-email verification stays bound to the selected authn slot.
 * - The final ReplaceEmail mutation intentionally omits the slot header,
 *   matching the deployed Account Manager email-change saga exactly.
 *
 * This file was created by static analysis only. It is not deployed and was
 * not executed as part of its creation.
 */
(async function p46NativeSequenceDiagnostic() {
  "use strict";

  var AUTHN_API_KEY = "prdakyres3YphxpI5f5NhtHOzVAHTTAuQmL8UmCB";
  var ACCOUNT_MANAGER_API_KEY = "prdakyresHrPbNYmoGmqMbZzZslfhGPRbBpwMfzE";
  var RECENT_AUTH_RESOURCE =
    "irn.intuit.authentication.verifyAuthCredentialWriteAccess";
  var RECENT_AUTH_REMEDIATION =
    "irn:intuit::identity:remediation/session-has-recent-authentication";
  var ACCOUNT_MANAGER_ASSET = "Intuit.identity.experiences.oneintuitam";
  var SIGNIN_ASSET = "Intuit.cto.iam.ius";
  var GRAPHQL_URL = "/identity-api/v2/graphql";

  var PANEL_ID = "p46-native-sequence-status";
  var allowedStages = new Set([
    "START",
    "CONTEXT",
    "PREPARE",
    "CURRENT_AUTH",
    "EMAIL_INPUT",
    "OTP_SENT",
    "VERIFY",
    "SIGN_IN",
    "REPLACE",
    "CREDENTIAL_ACCEPTED",
    "DENIED",
    "ERROR",
    "NO_SANDBOX",
    "AUTH_NO_DECISION",
    "AUTH_NO_REMEDIATION",
    "AUTH_STILL_DENIED",
    "CONTEXT_NO_AUTHID",
    "CONTEXT_MISMATCH",
    "SLOT_NO_MATCH",
    "PREPARE_FAILED",
    "OTP_INIT_FAILED",
    "OTP_VERIFY_FAILED",
    "SIGNIN_FAILED",
    "REPLACE_DENIED",
  ]);

  function panel() {
    var root = document.getElementById(PANEL_ID);
    if (root) return root;

    root = document.createElement("section");
    root.id = PANEL_ID;
    root.setAttribute("role", "status");
    root.setAttribute("aria-live", "polite");
    root.style.cssText =
      "position:fixed;right:16px;bottom:16px;z-index:2147483647;" +
      "width:min(420px,calc(100vw - 32px));padding:14px;" +
      "border:2px solid #2ca01c;border-radius:8px;background:#fff;" +
      "color:#111;font:14px/1.4 system-ui,sans-serif;" +
      "box-shadow:0 8px 30px rgba(0,0,0,.28)";

    var heading = document.createElement("strong");
    heading.textContent = "P46 researcher-owned account test";
    root.appendChild(heading);

    var status = document.createElement("div");
    status.dataset.p46Status = "true";
    status.style.cssText = "margin-top:8px";
    status.textContent = "START";
    root.appendChild(status);

    var controls = document.createElement("div");
    controls.dataset.p46Controls = "true";
    controls.style.cssText = "margin-top:10px";
    root.appendChild(controls);

    (document.body || document.documentElement).appendChild(root);
    return root;
  }

  function stage(name) {
    var safe = allowedStages.has(name) ? name : "ERROR";
    document.title = "P46:" + safe;
    var status = panel().querySelector("[data-p46-status]");
    status.textContent = safe;
  }

  function clearControls() {
    var controls = panel().querySelector("[data-p46-controls]");
    while (controls.firstChild) controls.removeChild(controls.firstChild);
    return controls;
  }

  function fail(stageName) {
    stage(stageName);
    throw new Error("P46 stopped safely");
  }

  function uuid() {
    if (crypto.randomUUID) return crypto.randomUUID();
    return "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx".replace(
      /[xy]/g,
      function (c) {
        var r = (Math.random() * 16) | 0;
        return (c === "x" ? r : (r & 3) | 8).toString(16);
      },
    );
  }

  function cookieValue(name) {
    var escaped = name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    var match = document.cookie.match(
      new RegExp("(?:^|;\\s*)" + escaped + "=([^;]*)"),
    );
    return match ? decodeURIComponent(match[1]) : "";
  }

  function sanitizedHeaders(options) {
    var opts = options || {};
    var session = cookieValue("ius_session");
    var visitor = cookieValue("ivid");
    var headers = {
      "Content-Type": "application/json; charset=utf-8",
      authorization:
        "Intuit_APIKey intuit_apikey=" +
        (opts.accountManager ? ACCOUNT_MANAGER_API_KEY : AUTHN_API_KEY) +
        ", intuit_apikey_version=1.0",
      intuit_flowid: opts.flowId,
      intuit_tid: uuid(),
      intuit_offeringid: opts.accountManager ? SIGNIN_ASSET : ACCOUNT_MANAGER_ASSET,
      intuit_intentassetalias: opts.accountManager
        ? SIGNIN_ASSET
        : ACCOUNT_MANAGER_ASSET,
      intuit_visitorid: visitor,
      intuit_sessionid: session,
      intuit_profilingid: session,
    };

    if (!opts.accountManager) {
      headers.intuit_offeringenv = "prd";
      headers.intuit_identity_routing = "SBSEG";
      headers.intuit_locale = "en-us";
      headers.intuit_country = "US";
      headers.intuit_samesite_support = "true";
      headers.intuit_origin = "https://accounts.intuit.com";
      headers.Intuit_Interception = "ignore-response";
    }

    if (opts.routingId) headers.intuit_routingid = opts.routingId;
    if (opts.slot) headers.intuit_authn_session_slot = opts.slot;
    if (opts.scope) {
      headers.intuit_baggage = btoa(
        JSON.stringify(
          opts.scope === "account_manager"
            ? { scope_area: opts.scope }
            : { scope_area: opts.scope, additional_fields: {} },
        ),
      );
    }
    return headers;
  }

  function isLiveSandbox(value) {
    return !!(
      value &&
      typeof value.remediate === "function" &&
      value.authorization &&
      typeof value.authorization.isAuthorizedBatch === "function" &&
      value.appContext &&
      typeof value.appContext.getIdentityContext === "function"
    );
  }

  function sandboxFromProps(props) {
    if (!props) return null;
    if (isLiveSandbox(props.sandbox)) return props.sandbox;
    if (isLiveSandbox(props.pluginSandbox)) return props.pluginSandbox;

    var stores = [];
    if (props.store) stores.push(props.store);
    if (props.value && props.value.store) stores.push(props.value.store);
    for (var i = 0; i < stores.length; i++) {
      try {
        if (typeof stores[i].getState === "function") {
          var state = stores[i].getState();
          if (state && state.appState && isLiveSandbox(state.appState.sandbox)) {
            return state.appState.sandbox;
          }
        }
      } catch (_) {}
    }
    return null;
  }

  function inspectFiber(fiber) {
    var seen = new WeakSet();
    while (fiber && typeof fiber === "object" && !seen.has(fiber)) {
      seen.add(fiber);
      var candidates = [
        fiber.memoizedProps,
        fiber.pendingProps,
        fiber.stateNode && fiber.stateNode.props,
      ];
      for (var i = 0; i < candidates.length; i++) {
        var found = sandboxFromProps(candidates[i]);
        if (found) return found;
      }
      fiber = fiber.return;
    }
    return null;
  }

  function findSandbox() {
    var nodes = document.querySelectorAll("*");

    for (var i = 0; i < nodes.length; i++) {
      var keys;
      try {
        keys = Object.getOwnPropertyNames(nodes[i]);
      } catch (_) {
        continue;
      }
      for (var j = 0; j < keys.length; j++) {
        if (
          keys[j].indexOf("__reactFiber$") === 0 ||
          keys[j].indexOf("__reactInternalInstance$") === 0 ||
          keys[j].indexOf("__reactContainer$") === 0
        ) {
          var found = inspectFiber(nodes[i][keys[j]]);
          if (found) return found;
        }
      }
    }
    return null;
  }

  async function waitForSandbox() {
    var deadline = Date.now() + 20000;
    do {
      var sandbox = findSandbox();
      if (sandbox) return sandbox;
      await new Promise(function (resolve) {
        setTimeout(resolve, 250);
      });
    } while (Date.now() < deadline);
    fail("NO_SANDBOX");
  }

  async function ensureRecentAuth(sandbox) {
    var response = await sandbox.authorization.isAuthorizedBatch({
      batchRequest: [
        {
          resource: { id: RECENT_AUTH_RESOURCE },
          action: { id: "read" },
        },
      ],
      apiVersion: "v2",
    });
    var decision = Array.isArray(response) ? response[0] : null;
    if (!decision) fail("AUTH_NO_DECISION");
    if (decision.isAuthorized) return;

    var remediation = (decision.remediation || []).find(function (item) {
      return item && item.id === RECENT_AUTH_REMEDIATION;
    });
    if (!remediation || typeof sandbox.remediate !== "function")
      fail("AUTH_NO_REMEDIATION");

    stage("CURRENT_AUTH");
    await sandbox.remediate({
      remediations: btoa(
        JSON.stringify({ remediations: [{ id: remediation.id }] }),
      ),
    });

    response = await sandbox.authorization.isAuthorizedBatch({
      batchRequest: [
        {
          resource: { id: RECENT_AUTH_RESOURCE },
          action: { id: "read" },
        },
      ],
      apiVersion: "v2",
    });
    decision = Array.isArray(response) ? response[0] : null;
    if (!decision || !decision.isAuthorized) fail("AUTH_STILL_DENIED");
  }

  function requestLocalInput(config) {
    return new Promise(function (resolve, reject) {
      var controls = clearControls();

      if (config.linkHref) {
        var helperLink = document.createElement("a");
        helperLink.href = config.linkHref;
        helperLink.target = "_blank";
        helperLink.rel = "noopener noreferrer";
        helperLink.textContent = config.linkText || "Open helper";
        helperLink.style.cssText = "display:block;margin-bottom:8px";
        controls.appendChild(helperLink);
      }

      var label = document.createElement("label");
      label.textContent = config.label;
      label.style.cssText = "display:block;margin-bottom:6px";

      var input = document.createElement("input");
      input.type = config.type || "text";
      input.autocomplete = config.autocomplete || "off";
      input.inputMode = config.inputMode || "text";
      input.style.cssText =
        "box-sizing:border-box;width:100%;padding:8px;border:1px solid #777;" +
        "border-radius:4px";

      var button = document.createElement("button");
      button.type = "button";
      button.textContent = "Continue";
      button.style.cssText =
        "margin-top:8px;padding:8px 12px;border:0;border-radius:4px;" +
        "background:#2ca01c;color:white;font-weight:600";

      function submit() {
        var value = input.value.trim();
        input.value = "";
        if (!config.validate(value)) {
          reject(new Error("invalid local input"));
          return;
        }
        clearControls();
        resolve(value);
      }

      button.addEventListener("click", submit, { once: true });
      input.addEventListener("keydown", function (event) {
        if (event.key === "Enter") {
          event.preventDefault();
          button.click();
        }
      });

      label.appendChild(input);
      controls.appendChild(label);
      controls.appendChild(button);
      input.focus();
    });
  }

  async function jsonRequest(url, options) {
    var response = await fetch(url, options);
    var text = await response.text();
    var parsed = null;
    try {
      parsed = JSON.parse(text);
    } catch (_) {}
    return { ok: response.ok, status: response.status, body: parsed };
  }

  async function prepareSignIn(flowId) {
    stage("PREPARE");
    return jsonRequest("/identity-api/preparesignin/graphql", {
      method: "POST",
      credentials: "include",
      cache: "no-store",
      headers: sanitizedHeaders({
        flowId: flowId,
      }),
      body: JSON.stringify({
        query:
          "mutation PrepareSignIn($input:Identity_BrowserPrepareSignInInput!){" +
          "identityBrowserPrepareSignIn(input:$input){__typename " +
          "authenticationSessionSlots{name digitalIdentity{legacyAuthId pseudonymId}}}}",
        variables: {
          input: {
            intent: { appGroup: "Identity", assetAlias: ACCOUNT_MANAGER_ASSET },
            clientCapabilitySet: "v1",
          },
        },
      }),
    });
  }

  function selectLiveSlot(identityContext, slots) {
    var contextAuthId = identityContext.digitalIdentityLegacyAuthId || "";
    var contextSlot = (identityContext.authnSessionSlot || "").trim();
    if (!contextAuthId) fail("CONTEXT_NO_AUTHID");

    var matching = slots.filter(function (slot) {
      return (
        slot &&
        slot.digitalIdentity &&
        slot.digitalIdentity.legacyAuthId === contextAuthId
      );
    });
    if (!matching.length) fail("SLOT_NO_MATCH");

    var selected = matching.find(function (slot) {
      return slot.name === contextSlot;
    });
    if (!selected) selected = matching[0];

    return {
      slot: selected.name,
      authId: contextAuthId,
      finalSlots:
        selected.name === "qbn" ? ["qbn"] : ["qbn", selected.name],
    };
  }

  async function verifyCandidateEmail(flowId, selected, email) {
    var factorHeaders = sanitizedHeaders({
      flowId: flowId,
      slot: selected.slot,
      scope: "remediation",
    });

    stage("OTP_SENT");
    var initialized = await jsonRequest("/factors/v1/verifier/initialize/email", {
      method: "POST",
      credentials: "include",
      cache: "no-store",
      headers: factorHeaders,
      body: JSON.stringify({
        verifierPolicyId: "emailOtpSignIn",
        emailAddress: email,
      }),
    });
    var verifierSessionId =
      initialized.body && initialized.body.verifierSessionId;
    if (!initialized.ok || !verifierSessionId) fail("OTP_INIT_FAILED");

    var otp = await requestLocalInput({
      label: "Paste the six-digit code from the fresh Guerrilla inbox.",
      type: "password",
      autocomplete: "one-time-code",
      inputMode: "numeric",
      validate: function (value) {
        return /^\d{6}$/.test(value);
      },
    });

    stage("VERIFY");
    factorHeaders = sanitizedHeaders({
      flowId: flowId,
      slot: selected.slot,
      scope: "remediation",
    });
    var verified = await jsonRequest("/factors/v1/verifier/verify/email", {
      method: "POST",
      credentials: "include",
      cache: "no-store",
      headers: factorHeaders,
      body: JSON.stringify({ verifierSessionId: verifierSessionId, otp: otp }),
    });
    otp = "";
    verifierSessionId = "";
    var verifierToken = verified.body && verified.body.verifierToken;
    if (!verified.ok || !verifierToken) fail("OTP_VERIFY_FAILED");

    stage("SIGN_IN");
    var signedIn = await jsonRequest("/identity-api/signin/graphql", {
      method: "POST",
      credentials: "include",
      cache: "no-store",
      headers: sanitizedHeaders({
        flowId: flowId,
        slot: selected.slot,
        scope: "remediation",
      }),
      body: JSON.stringify({
        query:
          "mutation SignInWithVerifierToken(" +
          "$input:Identity_BrowserSignInWithVerifierTokenInput!){" +
          "identityBrowserSignInWithVerifierToken(input:$input){__typename " +
          "...on Identity_BrowserSignInWithVerifierTokenNothingElseRequired{" +
          "successCode authenticationSession{digitalIdentity{legacyAuthId}}}" +
          "...on Identity_BrowserSignInWithVerifierTokenAccessDenied{__typename}" +
          "...on Identity_BrowserSignInWithVerifierTokenSomethingElseRequired{" +
          "__typename}...on Identity_SignInError{__typename}}}",
        variables: {
          input: {
            intent: {
              appGroup: "Identity",
              assetAlias: ACCOUNT_MANAGER_ASSET,
              securityCategory: "ORANGE",
              redirectUri:
                "https://accounts.intuit.com/app/account-manager/security/email",
              rememberMe: false,
            },
            clientCapabilitySet: "v13",
            finalSlotNames: selected.finalSlots,
            deviceCapabilities: {
              passkeySupported: false,
              simTs43Supported: false,
              digitalCredential: { userAgentAllowsProtocols: [] },
            },
            inputSlotName: selected.slot,
            tenantIds: ["50000003"],
            verifierToken: verifierToken,
          },
        },
      }),
    });
    verifierToken = "";

    var result =
      signedIn.body &&
      signedIn.body.data &&
      signedIn.body.data.identityBrowserSignInWithVerifierToken;
    var returnedAuthId =
      result &&
      result.authenticationSession &&
      result.authenticationSession.digitalIdentity &&
      result.authenticationSession.digitalIdentity.legacyAuthId;
    if (
      !signedIn.ok ||
      !result ||
      result.__typename !==
        "Identity_BrowserSignInWithVerifierTokenNothingElseRequired" ||
      result.successCode !== "NOTHING_ELSE_REQUIRED" ||
      !returnedAuthId ||
      returnedAuthId !== selected.authId
    ) {
      fail("SIGNIN_FAILED");
    }
  }

  async function replaceEmail(flowId, selected, email) {
    stage("REPLACE");
    var response = await jsonRequest(GRAPHQL_URL, {
      method: "POST",
      credentials: "include",
      cache: "no-store",
      headers: sanitizedHeaders({
        flowId: flowId,
        scope: "account_manager",
        accountManager: true,
        routingId: selected.authId,
      }),
      body: JSON.stringify({
        operationName: "ReplaceEmail",
        query:
          "mutation ReplaceEmail(" +
          "$input:Identity_CreateOrReplaceEmailCredentialInput!){" +
          "identityCreateOrReplaceEmailCredential(input:$input){__typename " +
          "...on Identity_CreateOrReplaceEmailCredentialSuccess{status}" +
          "...on Identity_CredentialUnauthorizedError{message}" +
          "...on Identity_CredentialInvalidInputError{message}" +
          "...on Identity_DigitalIdentityLockedOutError{message}" +
          "...on Identity_EmailCredentialMatchesExistingError{message}}}",
        variables: { input: { newEmailAddress: email } },
      }),
    });

    var result =
      response.body &&
      response.body.data &&
      response.body.data.identityCreateOrReplaceEmailCredential;
    if (
      response.ok &&
      result &&
      result.__typename === "Identity_CreateOrReplaceEmailCredentialSuccess"
    ) {
      email = "";
      stage("CREDENTIAL_ACCEPTED");
      clearControls();
      return true;
    }
    email = "";
    fail("REPLACE_DENIED");
  }

  try {
    if (location.origin !== "https://accounts.intuit.com") fail("ERROR");
    stage("START");

    var flowId =
      (window.intuit && window.intuit.ius && window.intuit.ius.flowId) || uuid();

    stage("CONTEXT");
    var sandbox = await waitForSandbox();
    await ensureRecentAuth(sandbox);

    var identityContext = sandbox.appContext.getIdentityContext() || {};
    var userAuthInfo =
      typeof sandbox.appContext.getUserAuthInfo === "function"
        ? sandbox.appContext.getUserAuthInfo() || {}
        : {};
    var currentAuthId = String(userAuthInfo.authId || "");
    var contextAuthId = String(
      identityContext.digitalIdentityLegacyAuthId || "",
    );
    if (!currentAuthId || currentAuthId !== contextAuthId)
      fail("CONTEXT_MISMATCH");

    var prepared = await prepareSignIn(flowId);
    var prepareResult =
      prepared.body &&
      prepared.body.data &&
      prepared.body.data.identityBrowserPrepareSignIn;
    var slots = (prepareResult && prepareResult.authenticationSessionSlots) || [];
    if (!prepared.ok || !slots.length) fail("PREPARE_FAILED");
    var selected = selectLiveSlot(identityContext, slots);
    selected.authId = currentAuthId;

    stage("EMAIL_INPUT");
    var email = await requestLocalInput({
      label: "Paste the newly generated disposable address.",
      linkHref: "https://www.guerrillamail.com/",
      linkText: "Open a fresh Guerrilla Mail inbox",
      type: "email",
      autocomplete: "off",
      inputMode: "email",
      validate: function (value) {
        return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);
      },
    });

    await verifyCandidateEmail(flowId, selected, email);
    await replaceEmail(flowId, selected, email);
  } catch (_) {
    if (!/^P46:/.test(document.title)) stage("ERROR");
  }
})();
