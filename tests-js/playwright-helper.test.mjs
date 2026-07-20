import assert from "node:assert/strict";
import test from "node:test";

import {
  DEFAULT_AUTHENTICATOR_OPTIONS,
  createVirtualAuthenticator,
  withFastPasskeyAuthenticator,
} from "../src/fastpasskey/testing/playwright.mjs";


function fakeContext() {
  const calls = [];
  let nextId = 1;
  const cdp = {
    async send(method, payload) {
      calls.push([method, payload]);
      if (method === "WebAuthn.addVirtualAuthenticator") {
        return { authenticatorId: `auth-${nextId++}` };
      }
      return {};
    },
  };
  return {
    calls,
    context: { newCDPSession: async () => cdp },
  };
}


test("virtual authenticator helper installs, replaces, and disposes authenticators", async () => {
  const { calls, context } = fakeContext();
  const authenticator = await createVirtualAuthenticator(context, {}, { transport: "usb" });
  assert.equal(authenticator.authenticatorId, "auth-1");
  assert.deepEqual(calls[1], [
    "WebAuthn.addVirtualAuthenticator",
    { options: { ...DEFAULT_AUTHENTICATOR_OPTIONS, transport: "usb" } },
  ]);
  assert.equal(await authenticator.replace({ isUserVerified: false }), "auth-2");
  await authenticator.dispose();
  await authenticator.dispose();
  assert.deepEqual(calls.map(([method]) => method), [
    "WebAuthn.enable",
    "WebAuthn.addVirtualAuthenticator",
    "WebAuthn.removeVirtualAuthenticator",
    "WebAuthn.addVirtualAuthenticator",
    "WebAuthn.removeVirtualAuthenticator",
  ]);
  assert.equal(await authenticator.replace(), "auth-3");
  await authenticator.dispose();
});


test("Playwright fixture installs and always disposes its authenticator", async () => {
  const { calls, context } = fakeContext();
  let fixture;
  const extended = { marker: "extended" };
  const baseTest = {
    extend(definition) {
      fixture = definition.fastPasskeyAuthenticator;
      return extended;
    },
  };
  assert.equal(withFastPasskeyAuthenticator(baseTest), extended);
  let fixtureId;
  await fixture({ context, page: {} }, async (authenticator) => {
    fixtureId = authenticator.authenticatorId;
  });
  assert.equal(fixtureId, "auth-1");
  assert.equal(calls.at(-1)[0], "WebAuthn.removeVirtualAuthenticator");
});
