let client = {
  apiBase: "/api/v1/auth",
  locale: () => globalThis.navigator?.language || "en",
  navigate: (url) => globalThis.location?.assign(url),
  translate: (_key, _values, fallback) => fallback,
};

function configureFastPasskey(options = {}) {
  client = { ...client, ...options };
}

function t(key, values = {}, fallback = key) {
  return client.translate(key, values, fallback);
}

function base64UrlToBytes(value) {
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  const padded = normalized + "=".repeat((4 - (normalized.length % 4)) % 4);
  const decoded = atob(padded);
  return Uint8Array.from(decoded, (char) => char.charCodeAt(0));
}

function bytesToBase64Url(value) {
  const bytes = value instanceof Uint8Array ? value : new Uint8Array(value);
  let binary = "";
  bytes.forEach((byte) => {
    binary += String.fromCharCode(byte);
  });
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function publicKeyFromJSON(publicKey) {
  const parsed = { ...publicKey, challenge: base64UrlToBytes(publicKey.challenge) };
  if (parsed.user?.id) {
    parsed.user = { ...parsed.user, id: base64UrlToBytes(parsed.user.id) };
  }
  for (const key of ["excludeCredentials", "allowCredentials"]) {
    if (Array.isArray(parsed[key])) {
      parsed[key] = parsed[key].map((credential) => ({
        ...credential,
        id: base64UrlToBytes(credential.id),
      }));
    }
  }
  return parsed;
}

function credentialToJSON(value) {
  if (value instanceof ArrayBuffer) {
    return bytesToBase64Url(value);
  }
  if (ArrayBuffer.isView(value)) {
    return bytesToBase64Url(
      value.buffer.slice(value.byteOffset, value.byteOffset + value.byteLength)
    );
  }
  if (Array.isArray(value)) {
    return value.map(credentialToJSON);
  }
  if (value && typeof value.toJSON === "function") {
    return credentialToJSON(value.toJSON());
  }
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value).map(([key, inner]) => [key, credentialToJSON(inner)])
    );
  }
  return value;
}

async function requestJson(path, payload) {
  const response = await fetch(`${client.apiBase}${path}`, {
    method: payload === undefined ? "GET" : "POST",
    headers: payload === undefined ? undefined : { "Content-Type": "application/json" },
    body: payload === undefined ? undefined : JSON.stringify(payload),
  });
  if (response.status === 401) {
    client.navigate("/login");
    throw new Error(t("common.errors.unauthorized", {}, "Unauthorized"));
  }
  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(
      typeof data.detail === "string"
        ? data.detail
        : t("common.errors.passkey_request_failed", {}, "Passkey request failed.")
    );
  }
  return data;
}

function setMessage(root, type, message, scope = "auth") {
  const errorNode = root.querySelector(`[data-${scope}-error]`);
  const successNode = root.querySelector(`[data-${scope}-success]`);
  if (!errorNode || !successNode) {
    return;
  }
  errorNode.hidden = true;
  successNode.hidden = true;
  errorNode.textContent = "";
  successNode.textContent = "";
  if (!message) {
    return;
  }
  const target = type === "error" ? errorNode : successNode;
  target.hidden = false;
  target.textContent = message;
}

function toggleButtons(root, disabled) {
  root.querySelectorAll("button").forEach((button) => {
    const locked = button.getAttribute("data-passkey-locked") === "true";
    button.disabled = disabled || locked;
  });
}

async function registerWithPasskey(root, form) {
  const formData = new FormData(form);
  const options = await requestJson("/register/options", {
    email: formData.get("email"),
    display_name: formData.get("display_name"),
  });
  const credential = await navigator.credentials.create({ publicKey: publicKeyFromJSON(options) });
  await requestJson("/register/verify", { credential: credentialToJSON(credential) });
  setMessage(
    root,
    "success",
    t("auth.login.created_redirect", {}, "Passkey created. Redirecting to your dashboard...")
  );
  client.navigate(root.getAttribute("data-next-url") || "/");
}

async function loginWithPasskey(root) {
  const options = await requestJson("/login/options", {});
  const credential = await navigator.credentials.get({ publicKey: publicKeyFromJSON(options) });
  await requestJson("/login/verify", { credential: credentialToJSON(credential) });
  setMessage(
    root,
    "success",
    t("auth.login.accepted_redirect", {}, "Passkey accepted. Redirecting to your dashboard...")
  );
  client.navigate(root.getAttribute("data-next-url") || "/");
}

function transitionAuthPanels(root, updatePanels) {
  const panelGroup = root.querySelector("[data-auth-panels]");
  if (!panelGroup) {
    updatePanels();
    return;
  }
  const beforeHeight = panelGroup.getBoundingClientRect().height;
  updatePanels();
  const afterHeight = panelGroup.scrollHeight;
  if (!beforeHeight || !afterHeight || beforeHeight === afterHeight) {
    return;
  }
  panelGroup.style.height = `${beforeHeight}px`;
  panelGroup.style.overflow = "hidden";
  panelGroup.getBoundingClientRect();
  panelGroup.style.height = `${afterHeight}px`;
  const settle = () => {
    panelGroup.style.height = "";
    panelGroup.style.overflow = "";
    panelGroup.removeEventListener("transitionend", settle);
  };
  panelGroup.addEventListener("transitionend", settle, { once: true });
  window.setTimeout(settle, 240);
}

function setAuthTab(root, tab) {
  const panels = root.querySelectorAll("[data-auth-tab-panel]");
  const triggers = root.querySelectorAll("[data-auth-tab-trigger]");
  if (!panels.length || !triggers.length) {
    return;
  }
  transitionAuthPanels(root, () => {
    panels.forEach((panel) => {
      panel.hidden = panel.getAttribute("data-auth-tab-panel") !== tab;
    });
  });
  triggers.forEach((trigger) => {
    trigger.setAttribute(
      "aria-selected",
      trigger.getAttribute("data-auth-tab-trigger") === tab ? "true" : "false"
    );
  });
  if (tab === "signup") {
    root.querySelector('[data-passkey-register] input[name="display_name"]')?.focus();
  }
}

function passkeysSupported() {
  return Boolean(window.PublicKeyCredential && navigator.credentials);
}

function unsupported(root, scope = "auth") {
  setMessage(
    root,
    "error",
    t(
      "common.errors.unsupported_passkeys",
      {},
      "This browser does not support passkeys."
    ),
    scope
  );
  toggleButtons(root, true);
}

function initPasskeyAuth() {
  const root = document.querySelector("[data-passkey-auth]");
  if (!root) {
    return;
  }
  if (!passkeysSupported()) {
    unsupported(root);
    return;
  }
  const registerForm = root.querySelector("[data-passkey-register]");
  root.querySelectorAll("[data-auth-tab-trigger]").forEach((trigger) => {
    trigger.addEventListener("click", () => {
      setAuthTab(root, trigger.getAttribute("data-auth-tab-trigger"));
    });
  });
  registerForm?.addEventListener("submit", async (event) => {
    event.preventDefault();
    toggleButtons(root, true);
    try {
      await registerWithPasskey(root, registerForm);
    } catch (error) {
      setMessage(
        root,
        "error",
        error instanceof Error
          ? error.message
          : t("auth.login.registration_failed", {}, "Passkey registration failed.")
      );
    } finally {
      toggleButtons(root, false);
    }
  });
  root.querySelector("[data-passkey-login-button]")?.addEventListener("click", async () => {
    toggleButtons(root, true);
    try {
      await loginWithPasskey(root);
    } catch (error) {
      setMessage(
        root,
        "error",
        error instanceof Error
          ? error.message
          : t("auth.login.login_failed", {}, "Passkey login failed.")
      );
    } finally {
      toggleButtons(root, false);
    }
  });
}

async function addPasskeyWithLink(root) {
  const token = root.getAttribute("data-passkey-add-token");
  if (!token) {
    throw new Error(t("auth.passkey_add.missing_token", {}, "Passkey add link is missing."));
  }
  const options = await requestJson(`/passkey-add/${token}/options`, {});
  const credential = await navigator.credentials.create({ publicKey: publicKeyFromJSON(options) });
  await requestJson(`/passkey-add/${token}/verify`, {
    credential: credentialToJSON(credential),
  });
  setMessage(
    root,
    "success",
    t(
      "auth.passkey_add.created_redirect",
      {},
      "Additional passkey created. Redirecting to your dashboard..."
    )
  );
  client.navigate("/");
}

function initPasskeyAddLink() {
  const root = document.querySelector("[data-passkey-add-link]");
  if (!root) {
    return;
  }
  if (!passkeysSupported()) {
    unsupported(root);
    return;
  }
  root.querySelector("[data-passkey-add-link-button]")?.addEventListener("click", async () => {
    toggleButtons(root, true);
    try {
      await addPasskeyWithLink(root);
    } catch (error) {
      setMessage(
        root,
        "error",
        error instanceof Error
          ? error.message
          : t("auth.passkey_add.failed", {}, "Passkey add failed.")
      );
    } finally {
      toggleButtons(root, false);
    }
  });
}

function formatPasskeyDate(value) {
  if (!value) {
    return t("settings.never_used", {}, "Never used yet");
  }
  return new Date(value).toLocaleString(client.locale(), {
    dateStyle: "medium",
    timeStyle: "short",
  });
}

function renderPasskeys(root, passkeys) {
  const container = root.querySelector("[data-passkey-list]");
  const emptyState = root.querySelector("[data-passkey-empty]");
  if (!container || !emptyState) {
    return;
  }
  container.innerHTML = "";
  emptyState.hidden = passkeys.length > 0;
  emptyState.style.display = passkeys.length > 0 ? "none" : "";
  passkeys.forEach((passkey) => {
    const row = document.createElement("article");
    row.className = "passkey-row";
    row.innerHTML = `
      <div class="passkey-copy">
        <strong>${passkey.name}</strong>
        <span>${t("settings.added_on", { date: formatPasskeyDate(passkey.created_at) }, "Added {date}")}</span>
        <span>${t("settings.last_used", { date: formatPasskeyDate(passkey.last_used_at) }, "Last used {date}")}</span>
      </div>
      <div class="passkey-actions">
        <button type="button" class="secondary-button" data-passkey-rename="${passkey.id}" data-passkey-current-name="${passkey.name}">${t("settings.rename", {}, "Rename")}</button>
        <button type="button" class="danger-button" data-passkey-delete="${passkey.id}" data-passkey-locked="${passkeys.length <= 1}" ${passkeys.length <= 1 ? "disabled" : ""}>${t("common.delete", {}, "Delete")}</button>
      </div>`;
    container.appendChild(row);
  });
}

function setPasskeyNameFormState(root, state) {
  const form = root.querySelector("[data-passkey-name-form]");
  const input = root.querySelector("[data-passkey-name-input]");
  const addButton = root.querySelector("[data-passkey-add]");
  const title = root.querySelector("[data-passkey-name-title]");
  const submitButton = root.querySelector("[data-passkey-name-submit]");
  if (!form || !input || !title || !submitButton) {
    return;
  }
  form.hidden = !state;
  if (addButton) {
    addButton.hidden = Boolean(state);
  }
  if (!state) {
    form.dataset.mode = "";
    form.dataset.passkeyId = "";
    form.reset();
    return;
  }
  form.dataset.mode = state.mode;
  form.dataset.passkeyId = state.passkeyId || "";
  title.textContent = state.title;
  submitButton.textContent = state.submitLabel;
  input.value = state.name;
  window.setTimeout(() => {
    input.focus();
    input.select();
  }, 0);
}

function setDeleteState(root, state) {
  const overlay = root.querySelector("[data-passkey-delete-overlay]");
  const panel = root.querySelector("[data-passkey-delete-panel]");
  const confirm = root.querySelector("[data-passkey-delete-confirm]");
  const copy = root.querySelector("[data-passkey-delete-copy]");
  if (!overlay || !panel || !confirm) {
    return;
  }
  overlay.hidden = !state;
  panel.hidden = !state;
  confirm.dataset.passkeyId = state?.passkeyId || "";
  if (copy && state) {
    copy.textContent = t(
      "settings.delete_help_prefix",
      { name: state.name },
      `To delete ${state.name}, authenticate with another passkey.`
    );
  }
  document.body.classList.toggle("has-list-modal-open", Boolean(state));
  if (state) {
    window.setTimeout(() => confirm.focus(), 0);
  }
}

async function addPasskey(name) {
  const options = await requestJson("/passkeys/register/options", { name });
  const credential = await navigator.credentials.create({ publicKey: publicKeyFromJSON(options) });
  return requestJson("/passkeys/register/verify", { credential: credentialToJSON(credential) });
}

async function renamePasskey(passkeyId, name) {
  const options = await requestJson(`/passkeys/${passkeyId}/rename/options`, { name });
  const credential = await navigator.credentials.get({ publicKey: publicKeyFromJSON(options) });
  return requestJson(`/passkeys/${passkeyId}/rename/verify`, {
    credential: credentialToJSON(credential),
  });
}

async function deletePasskey(passkeyId) {
  const options = await requestJson(`/passkeys/${passkeyId}/delete/options`, {});
  const credential = await navigator.credentials.get({ publicKey: publicKeyFromJSON(options) });
  return requestJson(`/passkeys/${passkeyId}/delete/verify`, {
    credential: credentialToJSON(credential),
  });
}

function initPasskeyManagement() {
  const root = document.querySelector("[data-passkey-management]")?.closest("[data-user-settings]")
    || document.querySelector("[data-passkey-management]");
  if (!root) {
    return;
  }
  if (!passkeysSupported()) {
    unsupported(root, "passkey");
    return;
  }
  const refresh = async () => {
    setMessage(root, "", "", "passkey");
    renderPasskeys(root, await requestJson("/passkeys"));
  };
  root.addEventListener("click", async (event) => {
    const add = event.target.closest("[data-passkey-add]");
    if (add) {
      setPasskeyNameFormState(root, {
        mode: "add",
        name: t(
          "settings.suggested_name",
          { number: root.querySelectorAll(".passkey-row").length + 1 },
          `Passkey ${root.querySelectorAll(".passkey-row").length + 1}`
        ),
        title: t("settings.name_this_passkey", {}, "Name this passkey"),
        submitLabel: t("common.continue", {}, "Continue"),
      });
      return;
    }
    if (event.target.closest("[data-passkey-name-cancel]")) {
      setPasskeyNameFormState(root, null);
      return;
    }
    const rename = event.target.closest("[data-passkey-rename]");
    if (rename) {
      setPasskeyNameFormState(root, {
        mode: "rename",
        passkeyId: rename.dataset.passkeyRename,
        name: rename.dataset.passkeyCurrentName || "",
        title: t("settings.rename_this_passkey", {}, "Rename this passkey"),
        submitLabel: t("settings.save_and_verify", {}, "Save and verify"),
      });
      return;
    }
    const remove = event.target.closest("[data-passkey-delete]");
    if (remove) {
      setDeleteState(root, {
        passkeyId: remove.dataset.passkeyDelete,
        name: remove.closest(".passkey-row")?.querySelector("strong")?.textContent || "passkey",
      });
      return;
    }
    if (event.target.closest("[data-passkey-delete-close]")) {
      setDeleteState(root, null);
      return;
    }
    const confirm = event.target.closest("[data-passkey-delete-confirm]");
    if (confirm) {
      toggleButtons(root, true);
      try {
        await deletePasskey(confirm.dataset.passkeyId);
        setDeleteState(root, null);
        await refresh();
        setMessage(root, "success", t("settings.deleted_success", {}, "Passkey deleted."), "passkey");
      } catch (error) {
        setMessage(root, "error", error.message, "passkey");
      } finally {
        toggleButtons(root, false);
      }
    }
  });
  root.querySelector("[data-passkey-name-form]")?.addEventListener("submit", async (event) => {
    event.preventDefault();
    const form = event.currentTarget;
    const name = String(new FormData(form).get("name") || "").trim();
    if (!name) {
      setMessage(root, "error", t("settings.name_required", {}, "Passkey name is required."), "passkey");
      return;
    }
    toggleButtons(root, true);
    try {
      const isRename = form.dataset.mode === "rename";
      if (isRename) {
        await renamePasskey(form.dataset.passkeyId, name);
      } else {
        await addPasskey(name);
      }
      setPasskeyNameFormState(root, null);
      await refresh();
      setMessage(
        root,
        "success",
        isRename
          ? t(
              "settings.renamed_success",
              {},
              "Passkey renamed after confirming it still works."
            )
          : t("settings.added_success", {}, "Another passkey is ready to use."),
        "passkey"
      );
    } catch (error) {
      setMessage(root, "error", error.message, "passkey");
    } finally {
      toggleButtons(root, false);
    }
  });
  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape") {
      setDeleteState(root, null);
    }
  });
  return refresh().catch((error) => {
    setMessage(root, "error", error.message, "passkey");
  });
}

function initFastPasskey(options = {}) {
  configureFastPasskey(options);
  initPasskeyAuth();
  initPasskeyAddLink();
  initPasskeyManagement();
}

export {
  addPasskey,
  addPasskeyWithLink,
  base64UrlToBytes,
  bytesToBase64Url,
  configureFastPasskey,
  credentialToJSON,
  deletePasskey,
  formatPasskeyDate,
  initFastPasskey,
  initPasskeyAddLink,
  initPasskeyAuth,
  initPasskeyManagement,
  loginWithPasskey,
  publicKeyFromJSON,
  registerWithPasskey,
  renamePasskey,
  renderPasskeys,
  requestJson,
  setAuthTab,
  setPasskeyNameFormState,
  transitionAuthPanels,
};
