import assert from "node:assert/strict";
import test from "node:test";
import { JSDOM } from "jsdom";

import {
  addPasskeyWithLink,
  base64UrlToBytes,
  bytesToBase64Url,
  configureFastPasskey,
  credentialToJSON,
  formatPasskeyDate,
  initFastPasskey,
  initPasskeyAddLink,
  initPasskeyAuth,
  initPasskeyManagement,
  interpolate,
  loginWithPasskey,
  publicKeyFromJSON,
  registerWithPasskey,
  renderPasskeys,
  requestJson,
  setAuthTab,
  setPasskeyNameFormState,
  transitionAuthPanels,
} from "../src/fastpasskey/static/fastpasskey.js";


function response(jsonData = {}, { ok = true, status = 200 } = {}) {
  return {
    ok,
    status,
    async json() {
      return jsonData;
    },
  };
}


function installDom(html, fetchImpl) {
  const dom = new JSDOM(html, { url: "https://example.com/login" });
  const previous = new Map();
  for (const [name, value] of Object.entries({
    window: dom.window,
    document: dom.window.document,
    navigator: dom.window.navigator,
    FormData: dom.window.FormData,
    Event: dom.window.Event,
    HTMLElement: dom.window.HTMLElement,
    HTMLFormElement: dom.window.HTMLFormElement,
    HTMLInputElement: dom.window.HTMLInputElement,
    HTMLButtonElement: dom.window.HTMLButtonElement,
    fetch: fetchImpl,
  })) {
    previous.set(name, globalThis[name]);
    Object.defineProperty(globalThis, name, { configurable: true, writable: true, value });
  }
  return () => {
    dom.window.close();
    for (const [name, value] of previous) {
      Object.defineProperty(globalThis, name, { configurable: true, writable: true, value });
    }
  };
}


function tick() {
  return new Promise((resolve) => setTimeout(resolve, 0));
}


test("WebAuthn JSON conversion handles nested binary values", () => {
  assert.deepEqual([...base64UrlToBytes("AQID")], [1, 2, 3]);
  assert.equal(bytesToBase64Url(new Uint8Array([1, 2, 3])), "AQID");
  const options = publicKeyFromJSON({
    challenge: "AQID",
    user: { id: "BAUG" },
    excludeCredentials: [{ id: "BwgJ" }],
    allowCredentials: [{ id: "CgsM" }],
  });
  assert.deepEqual([...options.user.id], [4, 5, 6]);
  assert.deepEqual([...options.excludeCredentials[0].id], [7, 8, 9]);
  assert.deepEqual([...options.allowCredentials[0].id], [10, 11, 12]);
  assert.deepEqual(
    credentialToJSON({ rawId: new Uint8Array([1, 2, 3]), nested: [new Uint8Array([4])] }),
    { rawId: "AQID", nested: ["BA"] },
  );
  assert.equal(credentialToJSON(new Uint8Array([5]).buffer), "BQ");
  assert.deepEqual(credentialToJSON({ toJSON: () => ({ rawId: new Uint8Array([6]) }) }), {
    rawId: "Bg",
  });
  assert.equal(credentialToJSON("plain"), "plain");
  assert.equal(interpolate("Added {date}", { date: "today" }), "Added today");
  assert.equal(interpolate("Keep {unknown}", {}), "Keep {unknown}");
});


test("default client supports locale, translation, navigation, and navigation absence", async () => {
  const restore = installDom(`
    <section data-passkey-auth data-next-url="/dashboard">
      <p data-auth-error hidden></p><p data-auth-success hidden></p>
      <form data-passkey-register>
        <input name="display_name" value="Owner"><input name="email" value="owner@example.com">
      </form>
    </section>
  `, async (url) => response(url.endsWith("/options")
    ? { challenge: "AQID", user: { id: "BAUG" } }
    : {}));
  const destinations = [];
  const previousLocation = globalThis.location;
  try {
    window.PublicKeyCredential = class {};
    navigator.credentials = {
      create: async () => ({ id: "created", rawId: new Uint8Array([1]).buffer }),
    };
    Object.defineProperty(globalThis, "location", {
      configurable: true,
      writable: true,
      value: { assign: (url) => destinations.push(url) },
    });
    assert.equal(formatPasskeyDate(null), "Never used yet");
    assert.match(formatPasskeyDate("2026-07-18T12:00:00Z"), /2026/);
    const root = document.querySelector("[data-passkey-auth]");
    const form = document.querySelector("[data-passkey-register]");
    await registerWithPasskey(root, form);
    assert.deepEqual(destinations, ["/dashboard"]);
    Object.defineProperty(globalThis, "location", {
      configurable: true,
      writable: true,
      value: undefined,
    });
    Object.defineProperty(globalThis, "navigator", {
      configurable: true,
      writable: true,
      value: { credentials: navigator.credentials },
    });
    assert.match(formatPasskeyDate("2026-07-18T12:00:00Z"), /2026/);
    root.removeAttribute("data-next-url");
    await registerWithPasskey(root, form);
    navigator.credentials.get = async () => ({
      id: "login", rawId: new Uint8Array([2]).buffer,
    });
    await loginWithPasskey(root);
  } finally {
    Object.defineProperty(globalThis, "location", {
      configurable: true,
      writable: true,
      value: previousLocation,
    });
    restore();
  }
});


test("login and registration use the packaged passkey client", async () => {
  const calls = [];
  const restore = installDom(`
    <section data-passkey-auth data-next-url="/dashboard">
      <p data-auth-error hidden></p><p data-auth-success hidden></p>
      <div data-auth-panels>
        <div data-auth-tab-panel="signin"></div>
        <div data-auth-tab-panel="signup" hidden></div>
      </div>
      <button data-auth-tab-trigger="signin"></button>
      <button data-auth-tab-trigger="signup"></button>
      <form data-passkey-register>
        <input name="display_name" value="Owner"><input name="email" value="owner@example.com">
        <button type="submit">Register</button>
      </form>
      <form data-passkey-login><button type="button" data-passkey-login-button>Login</button></form>
    </section>
  `, async (url, options) => {
    calls.push([url, options]);
    if (url.endsWith("/options")) {
      return response({ challenge: "AQID", user: { id: "BAUG" } });
    }
    return response({});
  });
  try {
    window.PublicKeyCredential = class {};
    navigator.credentials = {
      create: async () => ({ id: "created", rawId: new Uint8Array([1]).buffer }),
      get: async () => ({ id: "login", rawId: new Uint8Array([2]).buffer }),
    };
    const destinations = [];
    initFastPasskey({
      navigate: (url) => destinations.push(url),
      translate: (_key, _values, fallback) => fallback,
    });
    document.querySelector("[data-passkey-register]").dispatchEvent(
      new Event("submit", { bubbles: true, cancelable: true }),
    );
    await tick();
    document.querySelector("[data-passkey-login-button]").click();
    await tick();
    assert.deepEqual(destinations, ["/dashboard", "/dashboard"]);
    assert.deepEqual(
      calls.map(([url]) => url),
      [
        "/api/v1/auth/register/options",
        "/api/v1/auth/register/verify",
        "/api/v1/auth/login/options",
        "/api/v1/auth/login/verify",
      ],
    );
  } finally {
    restore();
  }
});


test("management client adds, renames, and deletes passkeys", async () => {
  let passkeys = [
    { id: "one", name: "Phone", created_at: "2026-07-18T12:00:00Z", last_used_at: null },
    { id: "two", name: "Laptop", created_at: "2026-07-18T12:00:00Z", last_used_at: null },
  ];
  const restore = installDom(`
    <section data-user-settings><section data-passkey-management>
      <button data-passkey-add>Add</button>
      <form data-passkey-name-form hidden><span data-passkey-name-title></span>
        <input name="name" data-passkey-name-input><button data-passkey-name-submit>Save</button>
        <button type="button" data-passkey-name-cancel>Cancel</button></form>
      <div data-passkey-empty></div><div data-passkey-list></div>
      <div data-passkey-error hidden></div><div data-passkey-success hidden></div>
      <div data-passkey-delete-overlay hidden><section data-passkey-delete-panel hidden>
        <p data-passkey-delete-copy></p><button data-passkey-delete-confirm>Delete</button>
        <button data-passkey-delete-close>Close</button></section></div>
    </section></section>
  `, async (url) => {
    if (url.endsWith("/passkeys")) {
      return response(passkeys);
    }
    if (url.endsWith("/options")) {
      return response({ challenge: "AQID", user: { id: "BAUG" } });
    }
    return response({});
  });
  try {
    window.PublicKeyCredential = class {};
    navigator.credentials = {
      create: async () => ({ id: "new", rawId: new Uint8Array([1]).buffer }),
      get: async () => ({ id: "two", rawId: new Uint8Array([2]).buffer }),
    };
    initFastPasskey({ translate: (_key, _values, fallback) => fallback });
    await tick();
    assert.match(document.querySelector("[data-passkey-list]").textContent, /Phone/);
    document.querySelector("[data-passkey-add]").click();
    const form = document.querySelector("[data-passkey-name-form]");
    form.querySelector("input").value = "Tablet";
    passkeys = [...passkeys, { id: "three", name: "Tablet", created_at: "2026-07-18T12:00:00Z", last_used_at: null }];
    form.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
    await tick();
    assert.match(document.querySelector("[data-passkey-list]").textContent, /Tablet/);

    document.querySelector('[data-passkey-rename="two"]').click();
    form.querySelector("input").value = "Travel key";
    form.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
    await tick();
    assert.equal(
      document.querySelector("[data-passkey-success]").textContent,
      "Passkey renamed after confirming it still works.",
    );

    document.querySelector('[data-passkey-delete="one"]').click();
    assert.equal(
      document.querySelector("[data-passkey-delete-copy]").textContent,
      "To delete Phone, you must authenticate with another passkey to confirm you still have a working Passkey after deleting one.",
    );
    document.querySelector("[data-passkey-delete-close]").click();
    document.querySelector('[data-passkey-delete="one"]').click();
    document.querySelector("[data-passkey-delete-confirm]").click();
    await tick();
    assert.equal(document.querySelector("[data-passkey-success]").textContent, "Passkey deleted.");
  } finally {
    restore();
  }
});


test("auth initialization handles tabs, unsupported browsers, and failures", async () => {
  const restore = installDom(`
    <section data-passkey-auth>
      <p data-auth-error hidden></p><p data-auth-success hidden></p>
      <div data-auth-panels>
        <div data-auth-tab-panel="signin"></div>
        <div data-auth-tab-panel="signup" hidden></div>
      </div>
      <button data-auth-tab-trigger="signin"></button>
      <button data-auth-tab-trigger="signup"></button>
      <form data-passkey-register>
        <input name="display_name" value="Owner"><input name="email" value="owner@example.com">
        <button type="submit">Register</button>
      </form>
      <button data-passkey-login-button>Login</button>
    </section>
  `, async () => response({}, { ok: false, status: 400 }));
  try {
    delete window.PublicKeyCredential;
    navigator.credentials = undefined;
    initPasskeyAuth();
    assert.equal(document.querySelector("[data-auth-error]").textContent, "This browser does not support passkeys.");

    window.PublicKeyCredential = class {};
    navigator.credentials = {
      create: async () => { throw "registration rejected"; },
      get: async () => { throw "login rejected"; },
    };
    document.querySelectorAll("button").forEach((button) => { button.disabled = false; });
    initFastPasskey({ translate: (_key, _values, fallback) => fallback });
    document.querySelector('[data-auth-tab-trigger="signup"]').click();
    assert.equal(document.querySelector('[data-auth-tab-panel="signup"]').hidden, false);
    document.querySelector("[data-passkey-register]").dispatchEvent(
      new Event("submit", { bubbles: true, cancelable: true }),
    );
    await tick();
    document.querySelectorAll("button").forEach((button) => { button.disabled = false; });
    document.querySelector("[data-passkey-login-button]").click();
    await tick();
    assert.match(document.querySelector("[data-auth-error]").textContent, /failed/i);

    globalThis.fetch = async () => response({ challenge: "AQID", user: { id: "BAUG" } });
    document.querySelectorAll("button").forEach((button) => { button.disabled = false; });
    document.querySelector("[data-passkey-register]").dispatchEvent(
      new Event("submit", { bubbles: true, cancelable: true }),
    );
    await tick();
    document.querySelectorAll("button").forEach((button) => { button.disabled = false; });
    document.querySelector("[data-passkey-login-button]").click();
    await tick();

    setAuthTab(document.createElement("div"), "signup");
    transitionAuthPanels(document.createElement("div"), () => {});
    transitionAuthPanels(document.querySelector("[data-passkey-auth]"), () => {});
    document.querySelector("[data-auth-error]").remove();
    document.querySelector("[data-auth-success]").remove();
    delete window.PublicKeyCredential;
    navigator.credentials = undefined;
    initPasskeyAuth();
    document.querySelector("[data-passkey-auth]").remove();
    initPasskeyAuth();
  } finally {
    restore();
  }
});


test("animated auth panel transition settles and focuses registration", () => {
  const restore = installDom(`
    <section data-passkey-auth><div data-auth-panels>
      <div data-auth-tab-panel="signin"></div><div data-auth-tab-panel="signup"></div>
    </div>
    <button data-auth-tab-trigger="signin"></button><button data-auth-tab-trigger="signup"></button>
    <form data-passkey-register><input name="display_name"></form></section>
  `, async () => response({}));
  try {
    const group = document.querySelector("[data-auth-panels]");
    group.getBoundingClientRect = () => ({ height: 20 });
    Object.defineProperty(group, "scrollHeight", { configurable: true, value: 40 });
    setAuthTab(document.querySelector("[data-passkey-auth]"), "signup");
    group.dispatchEvent(new Event("transitionend"));
    assert.equal(group.style.height, "");
  } finally {
    restore();
  }
});


test("add-link client handles success, missing token, unsupported browser, and failure", async () => {
  const calls = [];
  const restore = installDom(`
    <section data-passkey-add-link data-passkey-add-token="link-token">
      <p data-auth-error hidden></p><p data-auth-success hidden></p>
      <button data-passkey-add-link-button>Add</button>
    </section>
  `, async (url) => {
    calls.push(url);
    return response(url.endsWith("/options")
      ? { challenge: "AQID", user: { id: "BAUG" } }
      : {});
  });
  try {
    window.PublicKeyCredential = class {};
    navigator.credentials = {
      create: async () => ({ id: "created", rawId: new Uint8Array([1]).buffer }),
    };
    const destinations = [];
    initFastPasskey({
      navigate: (url) => destinations.push(url),
      translate: (_key, _values, fallback) => fallback,
    });
    document.querySelector("[data-passkey-add-link-button]").click();
    await tick();
    assert.deepEqual(calls, [
      "/api/v1/auth/passkey-add/link-token/options",
      "/api/v1/auth/passkey-add/link-token/verify",
    ]);
    assert.deepEqual(destinations, ["/"]);

    document.querySelector("[data-passkey-add-link]").removeAttribute("data-passkey-add-token");
    await assert.rejects(addPasskeyWithLink(document.querySelector("[data-passkey-add-link]")), /missing/i);
    navigator.credentials.create = async () => { throw "creation rejected"; };
    document.querySelector("[data-passkey-add-link]").setAttribute("data-passkey-add-token", "link-token");
    document.querySelector("[data-passkey-add-link-button]").click();
    await tick();
    assert.equal(document.querySelector("[data-auth-error]").textContent, "Passkey add failed.");
    navigator.credentials.create = async () => { throw new Error("creation failed"); };
    document.querySelector("[data-passkey-add-link-button]").click();
    await tick();
    assert.equal(document.querySelector("[data-auth-error]").textContent, "creation failed");

    delete window.PublicKeyCredential;
    navigator.credentials = undefined;
    initPasskeyAddLink();
    assert.equal(document.querySelector("[data-auth-error]").textContent, "This browser does not support passkeys.");
    document.querySelector("[data-passkey-add-link]").remove();
    initPasskeyAddLink();
  } finally {
    restore();
  }
});


test("rendering and name form helpers cover empty and incomplete markup", () => {
  const restore = installDom(`
    <section data-passkey-management>
      <button data-passkey-add>Add</button>
      <form data-passkey-name-form><input name="name" data-passkey-name-input>
        <span data-passkey-name-title></span><button data-passkey-name-submit></button></form>
      <div data-passkey-empty></div><div data-passkey-list></div>
    </section>
  `, async () => response({}));
  try {
    const root = document.querySelector("[data-passkey-management]");
    renderPasskeys(root, []);
    assert.equal(root.querySelector("[data-passkey-empty]").hidden, false);
    renderPasskeys(root, [{
      id: "one", name: '<img src=x onerror="throw 1">', created_at: "2026-07-18T12:00:00Z",
      last_used_at: "2026-07-18T12:30:00Z",
    }]);
    assert.equal(root.querySelector("img"), null);
    assert.equal(root.querySelector(".passkey-row strong").textContent, '<img src=x onerror="throw 1">');
    assert.doesNotMatch(root.querySelector(".passkey-row").textContent, /\{date\}/);
    assert.equal(root.querySelector('[data-passkey-delete="one"]').disabled, true);
    setPasskeyNameFormState(root, {
      mode: "add", name: "Phone", title: "Name", submitLabel: "Continue",
    });
    setPasskeyNameFormState(root, null);
    assert.equal(root.querySelector("[data-passkey-name-form]").hidden, true);
    renderPasskeys(document.createElement("div"), []);
    setPasskeyNameFormState(document.createElement("div"), null);
  } finally {
    restore();
  }
});


test("management handles unsupported, blank, cancellation, operation errors, and refresh errors", async () => {
  const html = `
    <section data-user-settings><section data-passkey-management>
      <button data-passkey-add>Add</button>
      <form data-passkey-name-form hidden><span data-passkey-name-title></span>
        <input name="name" data-passkey-name-input><button data-passkey-name-submit>Save</button>
        <button type="button" data-passkey-name-cancel>Cancel</button></form>
      <div data-passkey-empty></div><div data-passkey-list></div>
      <div data-passkey-error hidden></div><div data-passkey-success hidden></div>
      <div data-passkey-delete-overlay hidden><section data-passkey-delete-panel hidden>
        <p data-passkey-delete-copy></p><button data-passkey-delete-confirm>Delete</button>
        <button data-passkey-delete-close>Close</button></section></div>
    </section></section>`;
  let failRefresh = false;
  const restore = installDom(html, async (url) => {
    if (url.endsWith("/passkeys") && failRefresh) {
      return response({ detail: "refresh failed" }, { ok: false, status: 500 });
    }
    if (url.endsWith("/passkeys")) {
      return response([
        { id: "one", name: "Phone", created_at: "2026-07-18T12:00:00Z", last_used_at: null },
        { id: "two", name: "Laptop", created_at: "2026-07-18T12:00:00Z", last_used_at: null },
      ]);
    }
    return response({ detail: "operation failed" }, { ok: false, status: 400 });
  });
  try {
    delete window.PublicKeyCredential;
    navigator.credentials = undefined;
    initPasskeyManagement();
    assert.equal(document.querySelector("[data-passkey-error]").textContent, "This browser does not support passkeys.");

    window.PublicKeyCredential = class {};
    navigator.credentials = {
      create: async () => ({ id: "created" }),
      get: async () => ({ id: "asserted" }),
    };
    document.querySelectorAll("button").forEach((button) => { button.disabled = false; });
    initFastPasskey({ translate: (_key, _values, fallback) => fallback });
    await tick();
    const form = document.querySelector("[data-passkey-name-form]");
    const nameInput = form.querySelector("[data-passkey-name-input]");
    nameInput.remove();
    form.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
    form.prepend(nameInput);
    document.querySelector("[data-passkey-add]").click();
    document.querySelector("[data-passkey-name-cancel]").click();
    document.querySelector("[data-passkey-add]").click();
    form.querySelector("input").value = "   ";
    form.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
    assert.equal(document.querySelector("[data-passkey-error]").textContent, "Passkey name is required.");

    form.querySelector("input").value = "Tablet";
    form.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
    await tick();
    assert.equal(document.querySelector("[data-passkey-error]").textContent, "operation failed");

    document.querySelector('[data-passkey-rename="one"]').removeAttribute("data-passkey-current-name");
    document.querySelector('[data-passkey-rename="one"]').click();
    form.querySelector("input").value = "Travel";
    form.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
    await tick();
    assert.equal(document.querySelector("[data-passkey-error]").textContent, "operation failed");

    document.querySelector('[data-passkey-delete="one"]').closest(".passkey-row").querySelector("strong").remove();
    document.querySelector('[data-passkey-delete="one"]').click();
    document.dispatchEvent(new window.KeyboardEvent("keydown", { key: "Escape" }));
    document.querySelector('[data-passkey-delete="one"]').click();
    document.querySelector("[data-passkey-delete-confirm]").click();
    await tick();
    assert.equal(document.querySelector("[data-passkey-error]").textContent, "operation failed");

    failRefresh = true;
    await initPasskeyManagement();
    await tick();
    assert.equal(document.querySelector("[data-passkey-error]").textContent, "refresh failed");
    document.querySelector("[data-passkey-delete-overlay]").remove();
    document.querySelector('[data-passkey-delete="one"]').click();
    document.querySelector("[data-user-settings]").remove();
    initPasskeyManagement();
  } finally {
    restore();
  }
});


test("request helper covers GET, unauthorized, malformed, and structured failures", async () => {
  const destinations = [];
  configureFastPasskey({
    apiBase: "/auth",
    navigate: (url) => destinations.push(url),
    translate: (_key, _values, fallback) => fallback,
  });
  const responses = [
    response({}, { ok: false, status: 401 }),
    { ok: true, status: 200, json: async () => { throw new Error("not json"); } },
    response({ detail: { reason: "bad" } }, { ok: false, status: 400 }),
    response({ detail: "specific failure" }, { ok: false, status: 400 }),
  ];
  const previousFetch = globalThis.fetch;
  globalThis.fetch = async () => responses.shift();
  try {
    await assert.rejects(requestJson("/me"), /Unauthorized/);
    assert.deepEqual(destinations, ["/login"]);
    assert.deepEqual(await requestJson("/me"), {});
    await assert.rejects(requestJson("/me", {}), /Passkey request failed/);
    await assert.rejects(requestJson("/me", {}), /specific failure/);
  } finally {
    globalThis.fetch = previousFetch;
    configureFastPasskey({ apiBase: "/api/v1/auth" });
  }
});
