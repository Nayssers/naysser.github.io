/*
 * p50: exact Account Manager sandbox Intuit sign-in email-change validation
 * with fixed, non-sensitive diagnostic stages for a researcher-owned account.
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
 * - Diagnostics are restricted to a fixed allowlist of coarse stages. They
 *   disclose no request or response values.
 * - The existing Account Manager DOM is preserved. Only a small status/input
 *   panel is appended.
 * - The exact deployed Account Manager sandbox is read from the plugin's own
 *   webpack module 29205. The helper does not infer a sandbox from React DOM
 *   internals.
 * - The exact sandbox is reacquired after recent-auth remediation.
 * - A fresh PrepareSignIn response must contain exactly one distinct,
 *   non-empty legacyAuthId across every identity-owned slot.  The helper
 *   stops before OTP initialization when multiple identities are present.
 * - That unique legacyAuthId must equal
 *   sandbox.appContext.getUserAuthInfo().authId. Any legacyAuthId exposed by
 *   getIdentityContext() must also match.
 * - Candidate-email verification stays bound to the selected authn slot,
 *   and SignInWithVerifierToken must return that exact legacyAuthId.
 * - The final ReplaceEmail mutation intentionally omits the slot header,
 *   matching the deployed Account Manager email-change saga exactly.
 *
 * This file was created by static analysis only. It is not deployed and was
 * not executed as part of its creation.
 */
(async function p50ExactAccountSandbox() {
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

  var PANEL_ID = "p50-exact-account-sandbox-status";
  var allowedStages = new Set([
    "START",
    "CONTEXT",
    "PREPARE",
    "CURRENT_AUTH",
    "AUTHZ_OK",
    "IDENTITY_BOUND",
    "SLOT_SELECTED",
    "EMAIL_INPUT",
    "OTP_SENT",
    "VERIFY",
    "VERIFY_OK",
    "SIGN_IN",
    "SIGNIN_SUCCESS",
    "SIGNIN_ACCESS_DENIED",
    "SIGNIN_MORE_REQUIRED",
    "SIGNIN_ERROR_RESULT",
    "SIGNIN_BAD_SUCCESS_CODE",
    "SIGNIN_IDENTITY_MISMATCH",
    "SIGNIN_HTTP_ERROR",
    "SIGNIN_NO_RESULT",
    "SIGNIN_OTHER",
    "REPLACE",
    "REPLACE_RECENT_AUTH_REQUIRED",
    "REPLACE_SUCCESS_STATUS_SET",
    "REPLACE_SUCCESS_STATUS_EMPTY",
    "REPLACE_UNAUTHORIZED",
    "REPLACE_INVALID_INPUT",
    "REPLACE_LOCKED",
    "REPLACE_EXISTING",
    "REPLACE_HTTP_ERROR",
    "REPLACE_NO_RESULT",
    "REPLACE_OTHER",
    "CREDENTIAL_ACCEPTED",
    "DENIED",
    "ERROR",
  ]);
  var terminalStages = new Set([
    "SIGNIN_ACCESS_DENIED",
    "SIGNIN_MORE_REQUIRED",
    "SIGNIN_ERROR_RESULT",
    "SIGNIN_BAD_SUCCESS_CODE",
    "SIGNIN_IDENTITY_MISMATCH",
    "SIGNIN_HTTP_ERROR",
    "SIGNIN_NO_RESULT",
    "SIGNIN_OTHER",
    "REPLACE_RECENT_AUTH_REQUIRED",
    "REPLACE_UNAUTHORIZED",
    "REPLACE_INVALID_INPUT",
    "REPLACE_LOCKED",
    "REPLACE_EXISTING",
    "REPLACE_HTTP_ERROR",
    "REPLACE_NO_RESULT",
    "REPLACE_OTHER",
    "CREDENTIAL_ACCEPTED",
    "DENIED",
    "ERROR",
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
    heading.textContent = "P50 researcher-owned account diagnostic";
    root.appendChild(heading);

    var status = document.createElement("div");
    status.dataset.p50Status = "true";
    status.style.cssText = "margin-top:8px";
    status.textContent = "START";
    root.appendChild(status);

    var trace = document.createElement("div");
    trace.dataset.p50Trace = "true";
    trace.style.cssText =
      "margin-top:6px;color:#555;font:12px/1.35 ui-monospace,monospace;" +
      "overflow-wrap:anywhere";
    trace.textContent = "START";
    root.appendChild(trace);

    var controls = document.createElement("div");
    controls.dataset.p50Controls = "true";
    controls.style.cssText = "margin-top:10px";
    root.appendChild(controls);

    (document.body || document.documentElement).appendChild(root);
    return root;
  }

  function stage(name) {
    var safe = allowedStages.has(name) ? name : "ERROR";
    document.title = "P50:" + safe;
    var status = panel().querySelector("[data-p50-status]");
    status.textContent = safe;
    var trace = panel().querySelector("[data-p50-trace]");
    var prior = trace.textContent ? trace.textContent.split(" > ") : [];
    if (prior[prior.length - 1] !== safe) prior.push(safe);
    trace.textContent = prior.slice(-12).join(" > ");
  }

  function clearControls() {
    var controls = panel().querySelector("[data-p50-controls]");
    while (controls.firstChild) controls.removeChild(controls.firstChild);
    return controls;
  }

  function fail(stageName) {
    stage(stageName === "DENIED" ? "DENIED" : "ERROR");
    throw new Error("P50 stopped safely");
  }

  function diagnosticFail(stageName) {
    stage(terminalStages.has(stageName) ? stageName : "ERROR");
    throw new Error("P50 stopped safely");
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
      typeof value.appContext.getIdentityContext === "function" &&
      typeof value.appContext.getUserAuthInfo === "function"
    );
  }

  var accountManagerWebpackRequire = null;

  function getAccountManagerWebpackRequire() {
    if (accountManagerWebpackRequire) return accountManagerWebpackRequire;

    var queue = self.webpackChunkoiam_account_manager_ui;
    if (!queue || typeof queue.push !== "function") return null;

    try {
      var chunkId = "p50-account-sandbox-" + Date.now() + "-" + uuid();
      queue.push([
        [chunkId],
        {},
        function (webpackRequire) {
          accountManagerWebpackRequire = webpackRequire;
        },
      ]);
    } catch (_) {
      return null;
    }
    return accountManagerWebpackRequire;
  }

  function getExactAccountSandbox() {
    try {
      var webpackRequire = getAccountManagerWebpackRequire();
      if (!webpackRequire) return null;

      // In the deployed Account Manager bundle, module 29205 is the plugin's
      // own sandbox holder. X5 stores the host-provided sandbox, Qu returns it,
      // and ei derives the native authentication-session slot.
      var bridge = webpackRequire(29205);
      if (!bridge || typeof bridge.Qu !== "function") return null;

      var sandbox = bridge.Qu();
      if (!isLiveSandbox(sandbox)) return null;
      return { sandbox: sandbox, bridge: bridge };
    } catch (_) {
      return null;
    }
  }

  async function waitForExactAccountSandbox() {
    var deadline = Date.now() + 20000;
    do {
      var exact = getExactAccountSandbox();
      if (exact) return exact;
      await new Promise(function (resolve) {
        setTimeout(resolve, 250);
      });
    } while (Date.now() < deadline);
    fail("ERROR");
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
    if (!decision) fail("DENIED");
    if (decision.isAuthorized) return;

    var remediation = (decision.remediation || []).find(function (item) {
      return item && item.id === RECENT_AUTH_REMEDIATION;
    });
    if (!remediation || typeof sandbox.remediate !== "function") fail("DENIED");

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
    if (!decision || !decision.isAuthorized) fail("DENIED");
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

  function responseRequiresRecentAuth(response) {
    var value = "";
    try {
      value = response.headers.get("intuit_remediations") || "";
    } catch (_) {
      return false;
    }
    if (!value) return false;
    if (
      value.indexOf(RECENT_AUTH_REMEDIATION) !== -1 ||
      value.indexOf("session-has-recent-authentication") !== -1
    ) {
      return true;
    }

    try {
      var normalized = value
        .replace(/-/g, "+")
        .replace(/_/g, "/")
        .replace(/\s/g, "");
      while (normalized.length % 4) normalized += "=";
      var decoded = atob(normalized);
      return (
        decoded.indexOf(RECENT_AUTH_REMEDIATION) !== -1 ||
        decoded.indexOf("session-has-recent-authentication") !== -1
      );
    } catch (_) {
      return false;
    }
  }

  async function jsonRequest(url, options) {
    var response = await fetch(url, options);
    var text = await response.text();
    var parsed = null;
    try {
      parsed = JSON.parse(text);
    } catch (_) {}
    return {
      ok: response.ok,
      status: response.status,
      body: parsed,
      recentAuthRequired: responseRequiresRecentAuth(response),
    };
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

  function readExactAccountIdentity(exact) {
    var sandbox = exact.sandbox;
    var userAuthInfo;
    var identityContext;
    try {
      userAuthInfo = sandbox.appContext.getUserAuthInfo() || {};
      identityContext = sandbox.appContext.getIdentityContext() || {};
    } catch (_) {
      fail("DENIED");
    }

    var authId = String(userAuthInfo.authId || "").trim();
    if (!authId) fail("DENIED");

    var contextLegacyIds = [];
    [
      identityContext.digitalIdentityLegacyAuthId,
      identityContext.legacyAuthId,
      identityContext.digitalIdentity &&
        identityContext.digitalIdentity.legacyAuthId,
    ].forEach(function (value) {
      var candidate = String(value || "").trim();
      if (candidate && contextLegacyIds.indexOf(candidate) === -1) {
        contextLegacyIds.push(candidate);
      }
    });

    // An identity-context legacy ID is optional in some host contexts. When
    // present, every exposed value must identify the same current user as the
    // exact Account Manager sandbox's getUserAuthInfo().authId.
    if (
      contextLegacyIds.length > 1 ||
      (contextLegacyIds.length === 1 && contextLegacyIds[0] !== authId)
    ) {
      fail("DENIED");
    }

    return {
      authId: authId,
      identityContext: identityContext,
    };
  }

  function currentSlotHint(exact) {
    var hints = [];
    try {
      if (exact.bridge && typeof exact.bridge.ei === "function") {
        hints.push(exact.bridge.ei(exact.sandbox));
      }
    } catch (_) {}
    try {
      var ius = window.intuit && window.intuit.ius;
      if (ius) {
        hints.push(ius.authnSessionSlot);
        hints.push(ius.authenticationSessionSlot);
        hints.push(ius.slotName);
      }
    } catch (_) {}
    try {
      var identityContext = exact.sandbox.appContext.getIdentityContext() || {};
      hints.push(identityContext.authnSessionSlot);
      hints.push(identityContext.authenticationSessionSlot);
      hints.push(identityContext.slotName);
    } catch (_) {}

    for (var i = 0; i < hints.length; i++) {
      if (typeof hints[i] === "string" && hints[i].trim()) {
        return hints[i].trim();
      }
    }
    return "";
  }

  function bindSingleIdentity(slots, slotHint, currentAuthId) {
    var identitySlots = slots.filter(function (slot) {
      return !!(
        slot &&
        typeof slot.name === "string" &&
        slot.name.trim() &&
        slot.digitalIdentity &&
        String(slot.digitalIdentity.legacyAuthId || "").trim()
      );
    });
    if (!identitySlots.length) fail("DENIED");

    var uniqueAuthIds = [];
    identitySlots.forEach(function (slot) {
      var authId = String(slot.digitalIdentity.legacyAuthId).trim();
      if (uniqueAuthIds.indexOf(authId) === -1) uniqueAuthIds.push(authId);
    });

    // This is the identity boundary.  Never initialize the candidate-email
    // verifier when PrepareSignIn exposes more than one current identity.
    if (uniqueAuthIds.length !== 1) fail("DENIED");

    var rootAuthId = uniqueAuthIds[0];
    if (rootAuthId !== currentAuthId) fail("DENIED");
    var selected = null;
    if (slotHint) {
      selected = identitySlots.find(function (slot) {
        return slot.name === slotHint;
      });
    }
    if (!selected) {
      selected = identitySlots.find(function (slot) {
        return slot.name === "qbn";
      });
    }
    // Every remaining slot is already proven to map to the same root authId,
    // so falling back to the first slot cannot cross an account boundary.
    if (!selected) selected = identitySlots[0];

    var selectedName = selected.name.trim();
    return {
      slot: selectedName,
      authId: rootAuthId,
      finalSlots:
        selectedName === "qbn" ? ["qbn"] : ["qbn", selectedName],
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
    if (!initialized.ok || !verifierSessionId) fail("DENIED");

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
    if (!verified.ok || !verifierToken) fail("DENIED");
    stage("VERIFY_OK");

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
    if (!signedIn.ok) diagnosticFail("SIGNIN_HTTP_ERROR");
    if (!result) diagnosticFail("SIGNIN_NO_RESULT");

    switch (result.__typename) {
      case "Identity_BrowserSignInWithVerifierTokenNothingElseRequired":
        if (result.successCode !== "NOTHING_ELSE_REQUIRED") {
          diagnosticFail("SIGNIN_BAD_SUCCESS_CODE");
        }
        if (!returnedAuthId || returnedAuthId !== selected.authId) {
          diagnosticFail("SIGNIN_IDENTITY_MISMATCH");
        }
        stage("SIGNIN_SUCCESS");
        break;
      case "Identity_BrowserSignInWithVerifierTokenAccessDenied":
        diagnosticFail("SIGNIN_ACCESS_DENIED");
        break;
      case "Identity_BrowserSignInWithVerifierTokenSomethingElseRequired":
        diagnosticFail("SIGNIN_MORE_REQUIRED");
        break;
      case "Identity_SignInError":
        diagnosticFail("SIGNIN_ERROR_RESULT");
        break;
      default:
        diagnosticFail("SIGNIN_OTHER");
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
    email = "";

    if (response.recentAuthRequired) {
      diagnosticFail("REPLACE_RECENT_AUTH_REQUIRED");
    }
    if (!response.ok) diagnosticFail("REPLACE_HTTP_ERROR");
    if (!result) diagnosticFail("REPLACE_NO_RESULT");

    switch (result.__typename) {
      case "Identity_CreateOrReplaceEmailCredentialSuccess":
        if (
          result.status !== null &&
          typeof result.status !== "undefined" &&
          String(result.status).trim()
        ) {
          stage("REPLACE_SUCCESS_STATUS_SET");
        } else {
          stage("REPLACE_SUCCESS_STATUS_EMPTY");
        }
        stage("CREDENTIAL_ACCEPTED");
        clearControls();
        return true;
      case "Identity_CredentialUnauthorizedError":
        diagnosticFail("REPLACE_UNAUTHORIZED");
        break;
      case "Identity_CredentialInvalidInputError":
        diagnosticFail("REPLACE_INVALID_INPUT");
        break;
      case "Identity_DigitalIdentityLockedOutError":
        diagnosticFail("REPLACE_LOCKED");
        break;
      case "Identity_EmailCredentialMatchesExistingError":
        diagnosticFail("REPLACE_EXISTING");
        break;
      default:
        diagnosticFail("REPLACE_OTHER");
    }
  }

  try {
    if (location.origin !== "https://accounts.intuit.com") fail("ERROR");
    stage("START");

    stage("CONTEXT");
    var exact = await waitForExactAccountSandbox();
    var sandbox = exact.sandbox;
    await ensureRecentAuth(sandbox);
    stage("AUTHZ_OK");

    // Recent-auth remediation can refresh both the plugin sandbox and shell
    // flow context. Re-read module 29205 after the gate; do not retain a stale
    // sandbox instance from before remediation.
    exact = await waitForExactAccountSandbox();
    sandbox = exact.sandbox;
    var accountIdentity = readExactAccountIdentity(exact);

    // Read the flow only after the authorization gate has passed.
    var flowId =
      (window.intuit && window.intuit.ius && window.intuit.ius.flowId) || uuid();
    var slotHint = currentSlotHint(exact);

    var prepared = await prepareSignIn(flowId);
    var prepareResult =
      prepared.body &&
      prepared.body.data &&
      prepared.body.data.identityBrowserPrepareSignIn;
    var slots = (prepareResult && prepareResult.authenticationSessionSlots) || [];
    if (!prepared.ok || !slots.length) fail("DENIED");
    var selected = bindSingleIdentity(
      slots,
      slotHint,
      accountIdentity.authId,
    );
    stage("IDENTITY_BOUND");
    stage("SLOT_SELECTED");

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
    var currentStage = document.title.indexOf("P50:") === 0
      ? document.title.slice(4)
      : "";
    if (!terminalStages.has(currentStage)) stage("ERROR");
  }
})();

