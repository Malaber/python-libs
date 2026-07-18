import assert from "node:assert/strict";
import test from "node:test";
import { JSDOM } from "jsdom";

import {
  base64UrlToBytes,
  bytesToBase64Url,
  credentialToJSON,
  initFastPasskey,
  publicKeyFromJSON,
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
    await new Promise((resolve) => setTimeout(resolve, 0));
    document.querySelector("[data-passkey-login-button]").click();
    await new Promise((resolve) => setTimeout(resolve, 0));
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
    await new Promise((resolve) => setTimeout(resolve, 0));
    assert.match(document.querySelector("[data-passkey-list]").textContent, /Phone/);
    document.querySelector("[data-passkey-add]").click();
    const form = document.querySelector("[data-passkey-name-form]");
    form.querySelector("input").value = "Tablet";
    passkeys = [...passkeys, { id: "three", name: "Tablet", created_at: "2026-07-18T12:00:00Z", last_used_at: null }];
    form.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
    await new Promise((resolve) => setTimeout(resolve, 0));
    assert.match(document.querySelector("[data-passkey-list]").textContent, /Tablet/);

    document.querySelector('[data-passkey-rename="two"]').click();
    form.querySelector("input").value = "Travel key";
    form.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
    await new Promise((resolve) => setTimeout(resolve, 0));
    assert.equal(
      document.querySelector("[data-passkey-success]").textContent,
      "Passkey renamed after confirming it still works.",
    );
  } finally {
    restore();
  }
});
