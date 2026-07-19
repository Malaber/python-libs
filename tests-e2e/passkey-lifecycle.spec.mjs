import { expect, test } from "playwright/test";


test("registers, manages, deletes, signs in, and consumes an add link", async ({ page, context }) => {
  const cdp = await context.newCDPSession(page);
  await cdp.send("WebAuthn.enable");
  const addAuthenticator = () => cdp.send("WebAuthn.addVirtualAuthenticator", {
    options: {
      protocol: "ctap2",
      transport: "internal",
      hasResidentKey: true,
      hasUserVerification: true,
      isUserVerified: true,
      automaticPresenceSimulation: true,
    },
  });
  const firstAuthenticator = await addAuthenticator();

  await page.goto("/login");
  await page.locator('[data-auth-tab-trigger="signup"]').click();
  await page.locator('[name="display_name"]').fill("E2E Owner");
  await page.locator('[name="email"]').fill("owner-e2e@example.com");
  await page.locator("[data-passkey-register-button]").click();
  await expect(page).toHaveURL(/\/settings$/);
  await expect(page.locator(".passkey-row")).toHaveCount(1);
  await expect(page.locator(".passkey-row strong")).toHaveText("Passkey 1");

  await cdp.send("WebAuthn.removeVirtualAuthenticator", {
    authenticatorId: firstAuthenticator.authenticatorId,
  });
  await addAuthenticator();
  await page.locator("[data-passkey-add]").click();
  await page.locator("[data-passkey-name-input]").fill("Laptop");
  await page.locator("[data-passkey-name-submit]").click();
  await expect(page.locator(".passkey-row")).toHaveCount(2);
  await expect(page.locator(".passkey-row strong")).toHaveText(["Passkey 1", "Laptop"]);

  await page.locator("[data-passkey-rename]").nth(1).click();
  await page.locator("[data-passkey-name-input]").fill("Travel key");
  await page.locator("[data-passkey-name-submit]").click();
  await expect(page.locator(".passkey-row strong")).toHaveText(["Passkey 1", "Travel key"]);
  await expect(page.locator("[data-passkey-success]")).toContainText("renamed");

  await page.locator("[data-passkey-delete]").first().click();
  await expect(page.locator("[data-passkey-delete-panel]")).toBeVisible();
  await expect(page.locator("[data-passkey-delete-copy]")).toContainText("another");
  await page.locator("[data-passkey-delete-confirm]").click();
  await expect(page.locator(".passkey-row")).toHaveCount(1);
  await expect(page.locator(".passkey-row strong")).toHaveText("Travel key");
  await expect(page.locator("[data-passkey-delete]")).toBeDisabled();

  await page.evaluate(async () => {
    await fetch("/auth/logout", { method: "POST" });
  });
  await page.goto("/login");
  await page.locator("[data-passkey-login-button]").click();
  await expect(page).toHaveURL(/\/settings$/);
  await expect(page.locator(".passkey-row strong")).toHaveText("Travel key");

  await page.evaluate(async () => {
    await fetch("/auth/logout", { method: "POST" });
  });
  await page.goto("/add/e2e-token");
  await page.locator("[data-passkey-add-link-button]").click();
  await expect(page).toHaveURL(/\/settings$/);
  await expect(page.locator(".passkey-row")).toHaveCount(2);
  await expect(page.locator(".passkey-row strong")).toHaveText(["Travel key", "Passkey 2"]);

  await page.goto("/add/e2e-token");
  await expect(page.locator("body")).toContainText("Not Found");
});
