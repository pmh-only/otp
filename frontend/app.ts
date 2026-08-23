interface OtpItem { id: string; code: string; source: "sms" | "mail" | "bitwarden"; sender: string; title: string; receivedAt: string; expiresAt?: string; }
interface SourceStatus { ok: boolean; checkedAt: string | null; error?: string; requiresUnlock?: boolean; }
interface Snapshot { items: OtpItem[]; sources: Record<string, SourceStatus>; refreshedAt: string; privacyLocked: boolean; passkeyEnabled: boolean; passkeyConfigured: boolean; }

const receivedCodes = element<HTMLElement>("#received-codes");
const receivedEmpty = element<HTMLElement>("#received-empty");
const receivedCount = element<HTMLElement>("#received-count");
const totpCodes = element<HTMLElement>("#totp-codes");
const totpEmpty = element<HTMLElement>("#totp-empty");
const totpCount = element<HTMLElement>("#totp-count");
const allCount = element<HTMLElement>("#all-count");
const navReceivedCount = element<HTMLElement>("#nav-received-count");
const navTotpCount = element<HTMLElement>("#nav-totp-count");
const sources = element<HTMLElement>("#sources");
const refresh = element<HTMLButtonElement>("#refresh");
const template = element<HTMLTemplateElement>("#code-template");
const unlockOverlay = element<HTMLElement>("#unlock-overlay");
const passkeyLogin = element<HTMLButtonElement>("#passkey-login");
const passkeySetup = element<HTMLFormElement>("#passkey-setup");
const setupToken = element<HTMLInputElement>("#setup-token");
const bitwardenLogin = element<HTMLFormElement>("#bitwarden-login");
const loginMasterPassword = element<HTMLInputElement>("#login-master-password");
const loginDivider = element<HTMLElement>("#login-divider");
const unlockError = element<HTMLElement>("#unlock-error");
const vaultUnlock = element<HTMLFormElement>("#vault-unlock");
const vaultMasterPassword = element<HTMLInputElement>("#vault-master-password");
const vaultUnlockError = element<HTMLElement>("#vault-unlock-error");
const search = element<HTMLInputElement>("#search");
const sourceFilter = element<HTMLSelectElement>("#source-filter");
const receivedPane = element<HTMLElement>("#received-pane");
const totpPane = element<HTMLElement>("#totp-pane");
const sessionTime = element<HTMLElement>("#session-time");
const toast = element<HTMLElement>("#toast");
const themeToggle = element<HTMLButtonElement>("#theme-toggle");
const browserSession = sessionStorage.getItem("otp-session") || crypto.randomUUID();
sessionStorage.setItem("otp-session", browserSession);

let snapshot: Snapshot = { items: [], sources: {}, refreshedAt: new Date().toISOString(), privacyLocked: false, passkeyEnabled: false, passkeyConfigured: false };
let activeView = "all";
let lastActivitySent = Date.now();
let sessionDeadline = Date.now() + 300_000;
let toastTimer = 0;
let theme: "dark" | "light" = matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark";

refresh.addEventListener("click", () => void load(true));
themeToggle.addEventListener("click", () => setTheme(theme === "dark" ? "light" : "dark"));
search.addEventListener("input", render);
sourceFilter.addEventListener("change", render);
passkeyLogin.addEventListener("click", () => void loginWithPasskey());
passkeySetup.addEventListener("submit", event => { event.preventDefault(); void registerPasskey(); });
bitwardenLogin.addEventListener("submit", event => { event.preventDefault(); void unlockBitwarden(bitwardenLogin, loginMasterPassword, unlockError); });
vaultUnlock.addEventListener("submit", event => { event.preventDefault(); void unlockBitwarden(vaultUnlock, vaultMasterPassword, vaultUnlockError); });
for (const button of document.querySelectorAll<HTMLButtonElement>(".nav-item")) {
  button.addEventListener("click", () => setView(button.dataset.view || "all"));
}
document.addEventListener("keydown", event => {
  if (event.key === "/" && !(document.activeElement instanceof HTMLInputElement)) { event.preventDefault(); search.focus(); }
  if (event.key === "Escape") { search.value = ""; search.blur(); render(); }
});
for (const eventName of ["pointerdown", "keydown", "touchstart", "scroll"] as const) window.addEventListener(eventName, reportActivity, { passive: true });

void load();
setTheme(theme);
setInterval(() => void load(), 15_000);
setInterval(renderSessionTimer, 1_000);
void streamEvents();

async function load(force = false): Promise<void> {
  refresh.disabled = true;
  try {
    const response = await apiFetch(force ? "/api/refresh" : "/api/otps", { method: force ? "POST" : "GET", cache: "no-store" });
    if (!response.ok) throw new Error("Unable to load codes");
    snapshot = await response.json() as Snapshot;
    render();
  } catch (error) { sources.textContent = error instanceof Error ? error.message : "Unable to load codes"; }
  finally { refresh.disabled = false; }
}

function render(): void {
  const query = search.value.trim().toLocaleLowerCase();
  const matches = (item: OtpItem) => !query || `${item.title} ${item.sender} ${item.code}`.toLocaleLowerCase().includes(query);
  const receivedAll = snapshot.items.filter(item => item.source !== "bitwarden");
  const totpAll = snapshot.items.filter(item => item.source === "bitwarden");
  const received = receivedAll.filter(item => (sourceFilter.value === "all" || item.source === sourceFilter.value) && matches(item));
  const totp = totpAll.filter(matches);
  receivedCount.textContent = String(received.length); navReceivedCount.textContent = String(receivedAll.length);
  totpCount.textContent = String(totp.length); navTotpCount.textContent = String(totpAll.length); allCount.textContent = String(snapshot.items.length);
  receivedEmpty.hidden = received.length !== 0; receivedCodes.replaceChildren(...received.map(renderCode));
  totpEmpty.hidden = totp.length !== 0; totpCodes.replaceChildren(...totp.map(renderCode));
  element<HTMLElement>("#received-empty h3").textContent = snapshot.privacyLocked ? "Workspace locked" : "No received codes";
  element<HTMLElement>("#received-empty p").textContent = snapshot.privacyLocked ? "Sign in to view received SMS and mail codes." : "New verification codes from SMS and mail will appear here automatically.";
  sources.replaceChildren(...Object.entries(snapshot.sources).map(([name, status]) => {
    const badge = document.createElement("span"); badge.className = status.ok ? "online" : "offline";
    badge.textContent = `${name} ${status.ok ? "connected" : status.requiresUnlock ? "locked" : "offline"}`;
    badge.title = status.error || `Last checked ${relativeTime(status.checkedAt)}`; return badge;
  }));
  const requiresUnlock = snapshot.sources.bitwarden?.requiresUnlock === true;
  const hasBitwarden = "bitwarden" in snapshot.sources;
  unlockOverlay.hidden = !snapshot.privacyLocked;
  passkeyLogin.hidden = !snapshot.passkeyEnabled || !snapshot.passkeyConfigured;
  passkeySetup.hidden = !snapshot.passkeyEnabled || snapshot.passkeyConfigured;
  bitwardenLogin.hidden = !hasBitwarden;
  loginDivider.hidden = !hasBitwarden || (!snapshot.passkeyConfigured && !snapshot.passkeyEnabled);
  element<HTMLElement>("#unlock-copy").textContent = snapshot.passkeyConfigured ? "Use your passkey or Bitwarden master password to open the workspace." : snapshot.passkeyEnabled ? "Register the first passkey with the server setup token. You can also sign in with Bitwarden." : "Enter your Bitwarden master password to open the workspace.";
  vaultUnlock.hidden = snapshot.privacyLocked || !requiresUnlock;
  totpEmpty.hidden = requiresUnlock || totp.length !== 0;
  if (snapshot.privacyLocked && document.activeElement === document.body) queueMicrotask(() => snapshot.passkeyConfigured ? passkeyLogin.focus() : snapshot.passkeyEnabled ? setupToken.focus() : loginMasterPassword.focus());
}

function setView(view: string): void {
  activeView = view;
  for (const button of document.querySelectorAll<HTMLButtonElement>(".nav-item")) button.classList.toggle("active", button.dataset.view === view);
  receivedPane.hidden = view === "totp"; totpPane.hidden = view === "received";
  document.querySelector(".boards")?.classList.toggle("single", view !== "all");
  if (activeView !== "all") element<HTMLElement>(activeView === "received" ? "#received-heading" : "#totp-heading").scrollIntoView({ behavior: "smooth", block: "start" });
}

async function unlockBitwarden(form: HTMLFormElement, input: HTMLInputElement, errorElement: HTMLElement): Promise<void> {
  const button = element<HTMLButtonElement>("button[type='submit']", form); button.disabled = true; errorElement.textContent = "";
  try {
    const response = await apiFetch("/api/bitwarden/unlock", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ password: input.value }) });
    input.value = "";
    if (!response.ok) throw new Error("Unable to unlock vault. Check your master password.");
    snapshot = await response.json() as Snapshot; sessionDeadline = Date.now() + 300_000; render();
  } catch (error) { input.value = ""; errorElement.textContent = error instanceof Error ? error.message : "Unable to unlock vault"; input.focus(); }
  finally { button.disabled = false; }
}

async function registerPasskey(): Promise<void> {
  const button = element<HTMLButtonElement>("button[type='submit']", passkeySetup); button.disabled = true; unlockError.textContent = "";
  try {
    const start = await apiFetch("/api/passkeys/register/start", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ setupToken: setupToken.value }) });
    setupToken.value = "";
    if (!start.ok) throw new Error(await responseError(start, "Unable to start passkey setup"));
    const credential = await navigator.credentials.create(creationOptions(await start.json()));
    if (!(credential instanceof PublicKeyCredential) || !(credential.response instanceof AuthenticatorAttestationResponse)) throw new Error("Passkey creation was cancelled");
    const finish = await apiFetch("/api/passkeys/register/finish", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(registrationResponse(credential)) });
    if (!finish.ok) throw new Error(await responseError(finish, "Unable to register passkey"));
    snapshot = await finish.json() as Snapshot; sessionDeadline = Date.now() + 300_000; render();
  } catch (error) { setupToken.value = ""; unlockError.textContent = error instanceof Error ? error.message : "Unable to register passkey"; setupToken.focus(); }
  finally { button.disabled = false; }
}

async function loginWithPasskey(): Promise<void> {
  passkeyLogin.disabled = true; unlockError.textContent = "";
  try {
    const start = await apiFetch("/api/passkeys/login/start", { method: "POST" });
    if (!start.ok) throw new Error(await responseError(start, "Unable to start passkey login"));
    const credential = await navigator.credentials.get(requestOptions(await start.json()));
    if (!(credential instanceof PublicKeyCredential) || !(credential.response instanceof AuthenticatorAssertionResponse)) throw new Error("Passkey login was cancelled");
    const finish = await apiFetch("/api/passkeys/login/finish", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(authenticationResponse(credential)) });
    if (!finish.ok) throw new Error(await responseError(finish, "Unable to verify passkey"));
    snapshot = await finish.json() as Snapshot; sessionDeadline = Date.now() + 300_000; render();
  } catch (error) { unlockError.textContent = error instanceof Error ? error.message : "Unable to sign in with passkey"; passkeyLogin.focus(); }
  finally { passkeyLogin.disabled = false; }
}

function creationOptions(value: { publicKey: PublicKeyCredentialCreationOptionsJSON }): CredentialCreationOptions {
  const options = value.publicKey;
  return { publicKey: { ...options, challenge: decodeBase64URL(options.challenge), user: { ...options.user, id: decodeBase64URL(options.user.id) }, excludeCredentials: options.excludeCredentials?.map(item => ({ ...item, id: decodeBase64URL(item.id) })) } as PublicKeyCredentialCreationOptions };
}
function requestOptions(value: { publicKey: PublicKeyCredentialRequestOptionsJSON }): CredentialRequestOptions {
  const options = value.publicKey;
  return { publicKey: { ...options, challenge: decodeBase64URL(options.challenge), allowCredentials: options.allowCredentials?.map(item => ({ ...item, id: decodeBase64URL(item.id) })) } as PublicKeyCredentialRequestOptions };
}
function registrationResponse(credential: PublicKeyCredential): object {
  const response = credential.response as AuthenticatorAttestationResponse;
  const publicKey = response.getPublicKey();
  return { id: credential.id, rawId: encodeBase64URL(credential.rawId), type: credential.type, response: { clientDataJSON: encodeBase64URL(response.clientDataJSON), attestationObject: encodeBase64URL(response.attestationObject), authenticatorData: encodeBase64URL(response.getAuthenticatorData()), publicKey: publicKey ? encodeBase64URL(publicKey) : "", publicKeyAlgorithm: response.getPublicKeyAlgorithm(), transports: response.getTransports() }, clientExtensionResults: credential.getClientExtensionResults(), authenticatorAttachment: credential.authenticatorAttachment };
}
function authenticationResponse(credential: PublicKeyCredential): object {
  const response = credential.response as AuthenticatorAssertionResponse;
  return { id: credential.id, rawId: encodeBase64URL(credential.rawId), type: credential.type, response: { clientDataJSON: encodeBase64URL(response.clientDataJSON), authenticatorData: encodeBase64URL(response.authenticatorData), signature: encodeBase64URL(response.signature), userHandle: response.userHandle ? encodeBase64URL(response.userHandle) : null }, clientExtensionResults: credential.getClientExtensionResults(), authenticatorAttachment: credential.authenticatorAttachment };
}
function decodeBase64URL(value: string): ArrayBuffer { const base64 = value.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(value.length / 4) * 4, "="); const bytes = Uint8Array.from(atob(base64), character => character.charCodeAt(0)); return bytes.buffer; }
function encodeBase64URL(value: ArrayBuffer): string { const bytes = new Uint8Array(value); let binary = ""; for (const byte of bytes) binary += String.fromCharCode(byte); return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, ""); }
async function responseError(response: Response, fallback: string): Promise<string> { try { const body = await response.json() as { error?: string }; return body.error || fallback; } catch { return fallback; } }

function renderCode(item: OtpItem): Element {
  const card = template.content.firstElementChild?.cloneNode(true); if (!(card instanceof HTMLElement)) throw new Error("Invalid code template");
  element<HTMLElement>(".source", card).textContent = item.source; const time = element<HTMLTimeElement>("time", card); time.dateTime = item.receivedAt; time.textContent = item.expiresAt ? countdown(item.expiresAt) : relativeTime(item.receivedAt);
  element<HTMLElement>("h3", card).textContent = item.title; element<HTMLElement>(".sender", card).textContent = item.sender; element<HTMLElement>(".code-value", card).textContent = item.code;
  const copy = async () => { await navigator.clipboard.writeText(item.code); showToast(`${item.code} copied`); };
  element<HTMLButtonElement>(".code", card).addEventListener("click", copy); element<HTMLButtonElement>(".copy-button", card).addEventListener("click", copy); return card;
}

function reportActivity(): void { const now = Date.now(); sessionDeadline = now + 300_000; if (now - lastActivitySent < 30_000) return; lastActivitySent = now; void apiFetch("/api/activity", { method: "POST", keepalive: true }); }
async function apiFetch(path: string, options: RequestInit = {}): Promise<Response> { const headers = new Headers(options.headers); headers.set("X-OTP-Session", browserSession); return fetch(path, { ...options, headers }); }
async function streamEvents(): Promise<void> { for (;;) { try { const response = await apiFetch("/api/events", { cache: "no-store" }); if (!response.ok || !response.body) throw new Error("Stream unavailable"); const reader = response.body.pipeThrough(new TextDecoderStream()).getReader(); let buffer = ""; for (;;) { const { value, done } = await reader.read(); if (done) break; buffer += value; const messages = buffer.split("\n\n"); buffer = messages.pop() || ""; for (const message of messages) { const line = message.split("\n").find(value => value.startsWith("data: ")); if (line) { snapshot = JSON.parse(line.slice(6)) as Snapshot; render(); } } } } catch { await new Promise(resolve => setTimeout(resolve, 2_000)); } } }
function renderSessionTimer(): void { const seconds = Math.max(0, Math.ceil((sessionDeadline - Date.now()) / 1000)); sessionTime.textContent = `${Math.floor(seconds / 60)}:${String(seconds % 60).padStart(2, "0")}`; }
function showToast(message: string): void { toast.textContent = message; toast.classList.add("visible"); clearTimeout(toastTimer); toastTimer = window.setTimeout(() => toast.classList.remove("visible"), 1500); }
function setTheme(next: "dark" | "light"): void { theme = next; document.documentElement.dataset.theme = next; const label = `Switch to ${next === "dark" ? "light" : "dark"} theme`; themeToggle.title = label; themeToggle.setAttribute("aria-label", label); }
function countdown(value: string): string { return `${Math.max(0, Math.ceil((Date.parse(value) - Date.now()) / 1000))}s`; }
function relativeTime(value: string | null): string { if (!value) return "never"; const seconds = Math.round((Date.parse(value) - Date.now()) / 1000); const formatter = new Intl.RelativeTimeFormat(undefined, { numeric: "auto" }); if (Math.abs(seconds) < 60) return formatter.format(seconds, "second"); const minutes = Math.round(seconds / 60); if (Math.abs(minutes) < 60) return formatter.format(minutes, "minute"); const hours = Math.round(minutes / 60); if (Math.abs(hours) < 24) return formatter.format(hours, "hour"); return formatter.format(Math.round(hours / 24), "day"); }
function element<T extends Element>(selector: string, root: ParentNode = document): T { const value = root.querySelector(selector); if (!value) throw new Error(`Missing element: ${selector}`); return value as T; }
