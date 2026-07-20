const DEFAULT_AUTHENTICATOR_OPTIONS = {
  protocol: "ctap2",
  transport: "internal",
  hasResidentKey: true,
  hasUserVerification: true,
  isUserVerified: true,
  automaticPresenceSimulation: true,
};


async function createVirtualAuthenticator(context, page, options = {}) {
  const cdp = await context.newCDPSession(page);
  await cdp.send("WebAuthn.enable");
  const authenticatorOptions = { ...DEFAULT_AUTHENTICATOR_OPTIONS, ...options };
  let authenticatorId;

  const add = async (overrides = {}) => {
    const result = await cdp.send("WebAuthn.addVirtualAuthenticator", {
      options: { ...authenticatorOptions, ...overrides },
    });
    authenticatorId = result.authenticatorId;
    return authenticatorId;
  };

  await add();
  return {
    get authenticatorId() {
      return authenticatorId;
    },
    async replace(overrides = {}) {
      if (authenticatorId) {
        await cdp.send("WebAuthn.removeVirtualAuthenticator", { authenticatorId });
        authenticatorId = undefined;
      }
      return add(overrides);
    },
    async dispose() {
      if (authenticatorId) {
        await cdp.send("WebAuthn.removeVirtualAuthenticator", { authenticatorId });
        authenticatorId = undefined;
      }
    },
  };
}


function withFastPasskeyAuthenticator(baseTest, options = {}) {
  return baseTest.extend({
    fastPasskeyAuthenticator: async ({ context, page }, use) => {
      const authenticator = await createVirtualAuthenticator(context, page, options);
      try {
        await use(authenticator);
      } finally {
        await authenticator.dispose();
      }
    },
  });
}


export {
  DEFAULT_AUTHENTICATOR_OPTIONS,
  createVirtualAuthenticator,
  withFastPasskeyAuthenticator,
};
