const statusElement = document.getElementById("service-status");
const logBody = document.getElementById("log-body");
const logTable = document.getElementById("log-table");
const POLL_INTERVAL_MS = 10000;
const MOBILE_NAV_BREAKPOINT = 900;
const macaroonStatusEl = document.getElementById("macaroon-status");
const macaroonForm = document.getElementById("macaroon-form");
const macaroonInput = document.getElementById("macaroon-input");
const macaroonFeedback = document.getElementById("macaroon-feedback");
const macaroonFormWrapper = document.getElementById("macaroon-form-wrapper");
const macaroonRevealBtn = document.getElementById("macaroon-reveal");
const clearLogsBtn = document.getElementById("logs-clear");
const lnurlToggleBtn = document.getElementById("lnurl-toggle");
const lnurlInstructions = document.getElementById("lnurl-instructions");
const lnurlModal = document.getElementById("lnurl-modal");
const lnurlModalCloseBtn = document.getElementById("lnurl-modal-close");
const copyrightYearEl = document.getElementById("copyright-year");
const envSettingsCard = document.getElementById("env-settings-card");
const envSettingsGroupsEl = document.getElementById("env-settings-groups");
const envSettingsSaveBtn = document.getElementById("env-settings-save");
const envSettingsFeedback = document.getElementById("env-settings-feedback");
const detailsModal = document.getElementById("details-modal");
const detailsJsonEl = document.getElementById("details-json");
const detailsCloseBtn = document.getElementById("details-close");
const logsSearchInput = document.getElementById("logs-search");
const logsPrevBtn = document.getElementById("logs-prev");
const logsNextBtn = document.getElementById("logs-next");
const logsPageIndicator = document.getElementById("logs-page-indicator");
const LOG_COLUMN_COUNT = logTable ? logTable.querySelectorAll("thead th").length : 0;
const metricDomainsValue = document.getElementById("metric-domains");
const metricRequestsValue = document.getElementById("metric-requests");
const liquidityMaxValueEl = document.getElementById("liquidity-max-value");
const liquidityMaxLabelEl = document.getElementById("liquidity-max-label");
const liquidityTotalEl = document.getElementById("liquidity-total");
const liquidityTableBody = document.getElementById("liquidity-table-body");
const LIQUIDITY_TABLE_COLUMNS = 5;
const sidebarToggleBtn = document.getElementById("sidebar-toggle");
const sidebarOverlay = document.getElementById("sidebar-overlay");
const identityTableBody = document.getElementById("identity-table-body");
const identityTablePlaceholder = document.getElementById("identity-table-placeholder");
const identityNewBtn = document.getElementById("identity-new-btn");
const identityForm = document.getElementById("identity-form");
const identityFormTitle = document.getElementById("identity-form-title");
const identityFormEyebrow = document.getElementById("identity-form-eyebrow");
const identityFormSubmit = document.getElementById("identity-form-submit");
const identityFormCancel = document.getElementById("identity-form-cancel");
const identityFormFeedback = document.getElementById("identity-form-feedback");
const identityLocalInput = document.getElementById("identity-local-part");
const identityDomainInput = document.getElementById("identity-domain");
const identityNpubInput = document.getElementById("identity-npub");
const identityRelaysInput = document.getElementById("identity-relays");
const identitySearchInput = document.getElementById("identity-search");
const identityModal = document.getElementById("identity-modal");
const identityModalCloseBtn = document.getElementById("identity-modal-close");
const identityDeleteModal = document.getElementById("identity-delete-modal");
const identityDeleteMessage = document.getElementById("identity-delete-message");
const identityDeleteConfirmBtn = document.getElementById("identity-delete-confirm");
const identityDeleteCancelBtn = document.getElementById("identity-delete-cancel");
const identityDeleteCloseBtn = document.getElementById("identity-delete-close");
const logsConfirmModal = document.getElementById("logs-confirm-modal");
const logsConfirmMessage = document.getElementById("logs-confirm-message");
const logsConfirmConfirmBtn = document.getElementById("logs-confirm-confirm");
const logsConfirmCancelBtn = document.getElementById("logs-confirm-cancel");
const logsConfirmCloseBtn = document.getElementById("logs-confirm-close");
const envSettingsDirty = new Map();
let envSettingsInitialValues = {};
const LOG_PAGE_SIZE = 10;
const assetBaseUrl = new URL(".", import.meta.url);
const TIMESTAMP_BASE_OPTIONS = { dateStyle: "medium", timeStyle: "short" };
const TIMESTAMP_WITH_TZ = { ...TIMESTAMP_BASE_OPTIONS, timeZoneName: "short" };
let logPage = 1;
let logTotalPages = 0;
let logTotalItems = 0;
let logQuery = "";
let logsFetchToken = 0;
let logSearchDebounceId;
let activeDetailsEntry = null;
let macaroonFormManuallyOpen = false;
let macaroonConfigured = false;
let lnurlDetailsOpen = false;
const identityState = {
  items: [],
  editingId: null,
  formVisible: false,
  searchQuery: "",
  pendingDeleteId: null,
};
const SETTINGS_ROUTE = "/settings";
const SETTINGS_URL = "/settings/";
const NAV_KEYS_BY_PATH = new Map([
  ["/", "dashboard"],
  ["/index.html", "dashboard"],
  ["/liquidity", "liquidity"],
  ["/liquidity/index.html", "liquidity"],
  ["/identities", "identities"],
  ["/identities/index.html", "identities"],
  ["/logs", "requests"],
  ["/logs/index.html", "requests"],
  [SETTINGS_ROUTE, "settings"],
  [`${SETTINGS_ROUTE}/index.html`, "settings"],
]);

function normalizePathname(pathname) {
  if (!pathname || pathname === "/") {
    return "/";
  }
  return pathname.replace(/\/+$/, "") || "/";
}

function isOnSettingsPage() {
  return normalizePathname(window.location.pathname) === SETTINGS_ROUTE;
}

function enforceSettingsRedirect(configured) {
  if (configured || isOnSettingsPage()) {
    return;
  }
  window.location.replace(SETTINGS_URL);
}

function resolveNavKey() {
  const normalized = normalizePathname(window.location.pathname);
  if (NAV_KEYS_BY_PATH.has(normalized)) {
    return NAV_KEYS_BY_PATH.get(normalized);
  }
  return "requests";
}

function refreshSidebarNav() {
  const key = resolveNavKey();
  const links = document.querySelectorAll("[data-nav-item]");
  links.forEach((link) => {
    if (!(link instanceof HTMLElement)) {
      return;
    }
    const navKey = link.dataset.navItem;
    const isActive = navKey === key;
    link.classList.toggle("active", Boolean(isActive));
    link.setAttribute("aria-current", isActive ? "page" : "false");
  });
}

function buildApiUrl(path) {
  const normalized = path.startsWith("/") ? path.slice(1) : path;
  return new URL(normalized, assetBaseUrl).toString();
}

async function updateStatus() {
  try {
    const response = await fetch(buildApiUrl("api/health"));
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }
    const data = await response.json();
    statusElement.textContent = data.status === "ok" ? "Online" : "Degraded";
    statusElement.classList.remove("error");
    statusElement.classList.add("ok");
  } catch (error) {
    statusElement.textContent = "Offline";
    statusElement.classList.remove("ok");
    statusElement.classList.add("error");
  }
}

function formatTimestamp(value) {
  if (!value) return null;
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return null;
  const iso = date.toISOString();
  try {
    return {
      display: date.toLocaleString(undefined, TIMESTAMP_WITH_TZ),
      iso,
    };
  } catch (error) {
    try {
      return {
        display: date.toLocaleString(undefined, TIMESTAMP_BASE_OPTIONS),
        iso,
      };
    } catch {
      return { display: iso, iso };
    }
  }
}

function createTimestampCell(value) {
  const cell = document.createElement("td");
  const formatted = formatTimestamp(value);
  if (!formatted) {
    cell.textContent = value ?? "—";
    return cell;
  }
  cell.textContent = formatted.display;
  cell.title = `${formatted.iso} (UTC)`;
  return cell;
}

function formatIp(value) {
  if (typeof value !== "string") {
    return value;
  }
  const trimmed = value.trim();
  if (!trimmed) {
    return trimmed;
  }
  if (trimmed.includes(":")) {
    const prefixLength = 6;
    const suffixLength = 6;
    if (trimmed.length > prefixLength + suffixLength + 3) {
      return `${trimmed.slice(0, prefixLength)}....${trimmed.slice(-suffixLength)}`;
    }
  }
  return trimmed;
}

function formatMetricNumber(value) {
  return typeof value === "number" && Number.isFinite(value)
    ? value.toLocaleString()
    : "—";
}

function formatSatAmount(value) {
  if (typeof value !== "number" || !Number.isFinite(value)) {
    return "—";
  }
  return `${value.toLocaleString()} sats`;
}

function shortenPubkey(value) {
  if (typeof value !== "string") {
    return "—";
  }
  const trimmed = value.trim();
  if (!trimmed) {
    return "—";
  }
  if (trimmed.length <= 18) {
    return trimmed;
  }
  return `${trimmed.slice(0, 8)}…${trimmed.slice(-6)}`;
}

function getPeerAlias(channel) {
  if (!channel || typeof channel.peer_alias !== "string") {
    return "";
  }
  return channel.peer_alias.trim();
}

function getPeerLabel(channel) {
  const alias = getPeerAlias(channel);
  if (alias) {
    return alias;
  }
  return shortenPubkey(channel?.remote_pubkey);
}

function getRemotePubkey(channel) {
  if (!channel || typeof channel.remote_pubkey !== "string") {
    return "";
  }
  return channel.remote_pubkey.trim();
}

function getChannelIdentifier(channel) {
  const id = typeof channel?.channel_id === "string" ? channel.channel_id.trim() : "";
  if (id) {
    return id;
  }
  const point =
    typeof channel?.channel_point === "string" ? channel.channel_point.trim() : "";
  if (point) {
    return point;
  }
  if (typeof channel?.remote_pubkey === "string") {
    const pubkey = channel.remote_pubkey.trim();
    if (pubkey) {
      return pubkey;
    }
  }
  return "—";
}

function getSendableBalance(channel) {
  const explicit = channel?.sendable_balance_sat;
  if (typeof explicit === "number" && Number.isFinite(explicit)) {
    return explicit;
  }
  const local = Number(channel?.local_balance_sat);
  const reserve = Number(channel?.local_chan_reserve_sat);
  if (Number.isFinite(local)) {
    const reserveValue = Number.isFinite(reserve) ? reserve : 0;
    return Math.max(local - reserveValue, 0);
  }
  return null;
}

function getReceivableBalance(channel) {
  const explicit = channel?.receiving_capacity_sat;
  if (typeof explicit === "number" && Number.isFinite(explicit)) {
    return explicit;
  }
  const remote = Number(channel?.remote_balance_sat);
  const reserve = Number(channel?.remote_chan_reserve_sat);
  if (Number.isFinite(remote)) {
    const reserveValue = Number.isFinite(reserve) ? reserve : 0;
    return Math.max(remote - reserveValue, 0);
  }
  return null;
}

function getTotalReserve(channel) {
  const localReserve = Number(channel?.local_chan_reserve_sat);
  const remoteReserve = Number(channel?.remote_chan_reserve_sat);
  const total =
    (Number.isFinite(localReserve) ? localReserve : 0) +
    (Number.isFinite(remoteReserve) ? remoteReserve : 0);
  return total > 0 ? total : 0;
}

function setMetricValue(target, value) {
  if (!target) return;
  target.textContent = value;
}

function isMobileNav() {
  return window.innerWidth <= MOBILE_NAV_BREAKPOINT;
}

function setSidebarOpen(open) {
  document.body.classList.toggle("sidebar-open", open);
  if (sidebarToggleBtn) {
    sidebarToggleBtn.setAttribute("aria-expanded", String(open));
  }
}

function updateBodyModalState() {
  const anyVisibleModal = Boolean(document.querySelector(".modal.visible"));
  document.body.classList.toggle("modal-open", anyVisibleModal);
}

async function fetchDashboardMetrics() {
  if (!metricDomainsValue && !metricRequestsValue) {
    return;
  }
  try {
    const response = await fetch(buildApiUrl("api/stats/summary"));
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }
    const data = await response.json();
    setMetricValue(metricDomainsValue, formatMetricNumber(data.connected_domains));
    setMetricValue(metricRequestsValue, formatMetricNumber(data.requests_24h));
  } catch (error) {
    console.error("Failed to load dashboard metrics", error);
    setMetricValue(metricDomainsValue, "—");
    setMetricValue(metricRequestsValue, "—");
  }
}

function sortIdentityItems(items) {
  if (!Array.isArray(items)) {
    return [];
  }
  return items
    .slice()
    .sort((a, b) => {
      const domainCompare = (a.domain || "").localeCompare(b.domain || "");
      if (domainCompare !== 0) {
        return domainCompare;
      }
      return (a.local_part || "").localeCompare(b.local_part || "");
    });
}

function getIdentityIdentifier(item) {
  if (!item) return "";
  if (item.identifier) {
    return item.identifier;
  }
  return `${item.local_part}@${item.domain}`;
}

function renderIdentityPlaceholder(message) {
  if (!identityTableBody) return;
  const row = document.createElement("tr");
  const cell = document.createElement("td");
  const colCount = identityTableBody?.closest("table")?.querySelectorAll("thead th").length || 3;
  cell.colSpan = colCount;
  cell.className = "placeholder";
  cell.textContent = message;
  row.appendChild(cell);
  identityTableBody.innerHTML = "";
  identityTableBody.appendChild(row);
}

function createIdentityHandleCell(item) {
  const cell = document.createElement("td");
  const wrapper = document.createElement("div");
  wrapper.className = "identity-handle";
  const label = document.createElement("p");
  label.className = "identity-handle-label";
  label.textContent = getIdentityIdentifier(item);
  wrapper.appendChild(label);
  const npubLine = document.createElement("p");
  npubLine.className = "identity-npub";
  const npub = item.npub || "—";
  npubLine.textContent = npub;
  npubLine.title = npub;
  wrapper.appendChild(npubLine);
  cell.appendChild(wrapper);
  return cell;
}

function createIdentityRelaysCell(item) {
  const cell = document.createElement("td");
  const relays = Array.isArray(item.relays) ? item.relays.filter(Boolean) : [];
  if (!relays.length) {
    const empty = document.createElement("span");
    empty.className = "identity-relay-empty";
    empty.textContent = "No relay hints";
    cell.appendChild(empty);
    return cell;
  }
  const wrapper = document.createElement("div");
  wrapper.className = "identity-relays";
  relays.forEach((relay) => {
    const chip = document.createElement("span");
    chip.className = "identity-relay-chip";
    chip.textContent = relay;
    chip.title = relay;
    wrapper.appendChild(chip);
  });
  cell.appendChild(wrapper);
  return cell;
}

function createIdentityActionsCell(item) {
  const cell = document.createElement("td");
  cell.className = "identity-actions-col";
  const editBtn = document.createElement("button");
  editBtn.type = "button";
  editBtn.className = "identity-action-btn";
  editBtn.textContent = "Edit";
  editBtn.addEventListener("click", () => handleIdentityEdit(item.id));
  const deleteBtn = document.createElement("button");
  deleteBtn.type = "button";
  deleteBtn.className = "identity-action-btn";
  deleteBtn.textContent = "Delete";
  deleteBtn.addEventListener("click", () => handleIdentityDelete(item.id));
  cell.appendChild(editBtn);
  cell.appendChild(deleteBtn);
  return cell;
}

function getDisplayIdentityItems() {
  const items = Array.isArray(identityState.items) ? identityState.items : [];
  const query = (identityState.searchQuery || "").trim().toLowerCase();
  if (!query) {
    return sortIdentityItems(items);
  }
  const filtered = items.filter((item) => {
    const identifier = getIdentityIdentifier(item).toLowerCase();
    const domain = (item.domain || "").toLowerCase();
    const npub = (item.npub || "").toLowerCase();
    const relays = Array.isArray(item.relays) ? item.relays.join(" ").toLowerCase() : "";
    return (
      identifier.includes(query) ||
      domain.includes(query) ||
      npub.includes(query) ||
      relays.includes(query)
    );
  });
  return sortIdentityItems(filtered);
}

function renderIdentityTable() {
  if (!identityTableBody) return;
  const rows = getDisplayIdentityItems();
  if (!rows.length) {
    const emptyMessage = identityState.searchQuery
      ? "No mappings match your search."
      : "No mappings yet. Click “Add mapping” to publish your first identity.";
    renderIdentityPlaceholder(emptyMessage);
    return;
  }
  identityTableBody.innerHTML = "";
  rows.forEach((item) => {
    const row = document.createElement("tr");
    row.appendChild(createIdentityHandleCell(item));
    row.appendChild(createIdentityRelaysCell(item));
    row.appendChild(createIdentityActionsCell(item));
    identityTableBody.appendChild(row);
  });
}

function setIdentityFormFeedback(message, isError = false) {
  if (!identityFormFeedback) return;
  identityFormFeedback.textContent = message || "";
  identityFormFeedback.style.color = isError ? "#f87171" : "#34d399";
}

function setIdentityFormVisible(visible) {
  identityState.formVisible = Boolean(visible);
  if (!identityModal) return;
  identityModal.classList.toggle("hidden", !visible);
  identityModal.classList.toggle("visible", visible);
  if (!visible) {
    identityState.editingId = null;
    setIdentityFormFeedback("");
    identityForm?.reset();
  } else {
    focusIdentityLocalField();
  }
  updateBodyModalState();
}

function focusIdentityLocalField() {
  if (identityLocalInput) {
    identityLocalInput.focus();
  }
}

function openIdentityCreateForm() {
  if (identityFormTitle) {
    identityFormTitle.textContent = "Add Nostr mapping";
  }
  if (identityFormEyebrow) {
    identityFormEyebrow.textContent = "Create";
  }
  if (identityFormSubmit) {
    identityFormSubmit.textContent = "Create mapping";
    identityFormSubmit.disabled = false;
  }
  identityState.editingId = null;
  identityForm?.reset();
  setIdentityFormFeedback("");
  setIdentityFormVisible(true);
}

function openIdentityEditForm(item) {
  if (!item) return;
  identityState.editingId = item.id;
  if (identityFormTitle) {
    identityFormTitle.textContent = `Edit ${getIdentityIdentifier(item)}`;
  }
  if (identityFormEyebrow) {
    identityFormEyebrow.textContent = "Edit";
  }
  if (identityFormSubmit) {
    identityFormSubmit.textContent = "Save changes";
    identityFormSubmit.disabled = false;
  }
  if (identityLocalInput) {
    identityLocalInput.value = item.local_part || "";
  }
  if (identityDomainInput) {
    identityDomainInput.value = item.domain || "";
  }
  if (identityNpubInput) {
    identityNpubInput.value = item.npub || item.pubkey_hex || "";
  }
  if (identityRelaysInput) {
    const relays = Array.isArray(item.relays) ? item.relays.join("\n") : "";
    identityRelaysInput.value = relays;
  }
  setIdentityFormFeedback("");
  setIdentityFormVisible(true);
}

function normalizeDomainInput(value) {
  if (typeof value !== "string") return "";
  let normalized = value.trim().toLowerCase();
  normalized = normalized.replace(/^https?:\/\//, "");
  normalized = normalized.split("/")[0] || "";
  normalized = normalized.split(":")[0] || "";
  return normalized;
}

function collectIdentityFormData() {
  const localPart = identityLocalInput?.value.trim().toLowerCase() || "";
  const domain = normalizeDomainInput(identityDomainInput?.value || "");
  const npub = identityNpubInput?.value.trim() || "";
  const relaysRaw = identityRelaysInput?.value || "";
  const relays = relaysRaw
    .split(/[\r\n,]+/)
    .map((relay) => relay.trim())
    .filter((relay) => relay.length > 0);
  if (!localPart || !domain || !npub) {
    setIdentityFormFeedback("Local-part, domain, and npub are required.", true);
    return null;
  }
  return {
    local_part: localPart,
    domain,
    npub,
    relays,
  };
}

async function loadIdentityMappings() {
  if (!identityTableBody) {
    return;
  }
  if (identityTablePlaceholder) {
    identityTablePlaceholder.textContent = "Loading mappings…";
  }
  try {
    const response = await fetch(buildApiUrl("api/nip05/identities"));
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }
    const data = await response.json();
    const items = Array.isArray(data.items) ? data.items : [];
    identityState.items = sortIdentityItems(items);
    renderIdentityTable();
  } catch (error) {
    console.error("Failed to load NIP-05 identities", error);
    renderIdentityPlaceholder("Unable to load mappings right now.");
  }
}

function upsertIdentityLocal(item) {
  const items = Array.isArray(identityState.items) ? identityState.items.slice() : [];
  const index = items.findIndex((entry) => entry.id === item.id);
  if (index >= 0) {
    items[index] = item;
  } else {
    items.push(item);
  }
  identityState.items = sortIdentityItems(items);
  renderIdentityTable();
}

function removeIdentityLocal(id) {
  identityState.items = identityState.items.filter((item) => item.id !== id);
  renderIdentityTable();
}

function setIdentityFormPending(pending) {
  if (!identityFormSubmit) return;
  const isEdit = Boolean(identityState.editingId);
  if (pending) {
    identityFormSubmit.disabled = true;
    identityFormSubmit.textContent = isEdit ? "Saving…" : "Creating…";
  } else {
    identityFormSubmit.disabled = false;
    identityFormSubmit.textContent = isEdit ? "Save changes" : "Create mapping";
  }
}

async function submitIdentityForm(event) {
  event.preventDefault();
  if (!identityForm) return;
  const payload = collectIdentityFormData();
  if (!payload) {
    return;
  }
  const editingId = identityState.editingId;
  const method = editingId ? "PUT" : "POST";
  const endpoint = editingId ? `api/nip05/identities/${editingId}` : "api/nip05/identities";
  setIdentityFormPending(true);
  setIdentityFormFeedback("");
  try {
    const response = await fetch(buildApiUrl(endpoint), {
      method,
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = data.detail || "Unable to save mapping.";
      throw new Error(detail);
    }
    const item = data.item;
    if (item) {
      upsertIdentityLocal(item);
    }
    setIdentityFormFeedback(editingId ? "Mapping updated." : "Mapping created.");
    setIdentityFormVisible(false);
  } catch (error) {
    setIdentityFormFeedback(error.message || "Failed to save mapping.", true);
  } finally {
    setIdentityFormPending(false);
  }
}

function handleIdentityEdit(identityId) {
  if (!identityTableBody) return;
  const entry = identityState.items.find((item) => item.id === identityId);
  if (!entry) {
    return;
  }
  openIdentityEditForm(entry);
}

function handleIdentityDelete(identityId) {
  const entry = identityState.items.find((item) => item.id === identityId);
  if (!entry) return;
  openIdentityDeleteModal(entry);
}

function setIdentityDeleteVisible(visible) {
  if (!identityDeleteModal) return;
  identityDeleteModal.classList.toggle("hidden", !visible);
  identityDeleteModal.classList.toggle("visible", visible);
  if (!visible) {
    identityState.pendingDeleteId = null;
    if (identityDeleteConfirmBtn) {
      const defaultText = identityDeleteConfirmBtn.dataset.defaultText || "Delete mapping";
      identityDeleteConfirmBtn.textContent = defaultText;
      identityDeleteConfirmBtn.disabled = false;
    }
  }
  updateBodyModalState();
}

function openIdentityDeleteModal(entry) {
  identityState.pendingDeleteId = entry.id;
  if (identityDeleteMessage) {
    identityDeleteMessage.textContent = `Delete mapping ${getIdentityIdentifier(entry)}? This cannot be undone.`;
  }
  if (identityDeleteConfirmBtn) {
    const defaultText = identityDeleteConfirmBtn.dataset.defaultText || "Delete mapping";
    identityDeleteConfirmBtn.textContent = defaultText;
    identityDeleteConfirmBtn.disabled = false;
  }
  setIdentityDeleteVisible(true);
}

async function confirmIdentityDelete() {
  const identityId = identityState.pendingDeleteId;
  if (!identityId) {
    return;
  }
  if (identityDeleteConfirmBtn) {
    identityDeleteConfirmBtn.disabled = true;
    identityDeleteConfirmBtn.textContent = "Deleting…";
  }
  try {
    const response = await fetch(buildApiUrl(`api/nip05/identities/${identityId}`), {
      method: "DELETE",
    });
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }
    removeIdentityLocal(identityId);
    if (identityState.editingId === identityId) {
      setIdentityFormVisible(false);
    }
    setIdentityDeleteVisible(false);
  } catch (error) {
    window.alert("Failed to delete mapping. Please retry.");
    if (identityDeleteConfirmBtn) {
      const defaultText = identityDeleteConfirmBtn.dataset.defaultText || "Delete mapping";
      identityDeleteConfirmBtn.textContent = defaultText;
      identityDeleteConfirmBtn.disabled = false;
    }
  }
}

function setLogsConfirmVisible(visible) {
  if (!logsConfirmModal) return;
  logsConfirmModal.classList.toggle("hidden", !visible);
  logsConfirmModal.classList.toggle("visible", visible);
  if (!visible && logsConfirmConfirmBtn) {
    const defaultText = logsConfirmConfirmBtn.dataset.defaultText || "Clear logs";
    logsConfirmConfirmBtn.textContent = defaultText;
    logsConfirmConfirmBtn.disabled = false;
  }
  updateBodyModalState();
}

function openLogsConfirmModal() {
  if (logsConfirmMessage) {
    logsConfirmMessage.textContent = "Remove all stored LNURL request logs? This cannot be undone.";
  }
  if (logsConfirmConfirmBtn) {
    const defaultText = logsConfirmConfirmBtn.dataset.defaultText || "Clear logs";
    logsConfirmConfirmBtn.textContent = defaultText;
    logsConfirmConfirmBtn.disabled = false;
  }
  setLogsConfirmVisible(true);
}

async function confirmLogsClear() {
  if (!logsConfirmConfirmBtn) {
    return;
  }
  const defaultConfirmText = logsConfirmConfirmBtn.dataset.defaultText || "Clear logs";
  logsConfirmConfirmBtn.disabled = true;
  logsConfirmConfirmBtn.textContent = "Clearing…";
  try {
    const response = await fetch(buildApiUrl("api/logs/recent"), { method: "DELETE" });
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }
    logPage = 1;
    await refreshLogs();
    setLogsConfirmVisible(false);
    if (clearLogsBtn) {
      clearLogsBtn.textContent = "Cleared";
      clearLogsBtn.disabled = true;
      setTimeout(() => {
        if (!clearLogsBtn) return;
        clearLogsBtn.textContent = defaultConfirmText;
        clearLogsBtn.disabled = false;
      }, 1500);
    }
  } catch (error) {
    window.alert("Failed to clear logs. Please retry.");
    logsConfirmConfirmBtn.disabled = false;
    logsConfirmConfirmBtn.textContent = defaultConfirmText;
  }
}

function handleIdentitySearchInput(event) {
  const target = event.target;
  if (!(target instanceof HTMLInputElement)) {
    return;
  }
  identityState.searchQuery = target.value || "";
  renderIdentityTable();
}

function renderEnvSettings(settings) {
  if (!envSettingsGroupsEl) return;
  envSettingsGroupsEl.innerHTML = "";
  envSettingsInitialValues = {};
  envSettingsDirty.clear();
  if (envSettingsFeedback) {
    envSettingsFeedback.textContent = "";
  }

  const groups = settings.reduce((acc, item) => {
    const group = item.category || "General";
    if (!acc[group]) acc[group] = [];
    acc[group].push(item);
    return acc;
  }, {});

  Object.entries(groups).forEach(([category, fields]) => {
    const wrapper = document.createElement("section");
    wrapper.className = "env-settings-category";

    const title = document.createElement("h3");
    title.className = "env-settings-category-title";
    title.textContent = category;
    wrapper.appendChild(title);

    const grid = document.createElement("div");
    grid.className = "env-settings-grid";

    fields.forEach((field) => {
      const fieldWrapper = document.createElement("div");
      fieldWrapper.className = "env-setting-field";
      if (!field.editable) {
        fieldWrapper.classList.add("readonly");
      }

      const label = document.createElement("label");
      label.className = "env-setting-label";
      label.setAttribute("for", `env-${field.key}`);
      label.textContent = field.label;
      fieldWrapper.appendChild(label);

      const input = field.type === "textarea" ? document.createElement("textarea") : document.createElement("input");
      input.id = `env-${field.key}`;
      input.dataset.key = field.key;
      input.className = "input env-setting-input";
      if (field.type === "number") {
        input.type = "number";
      } else if (field.type !== "textarea") {
        input.type = "text";
      }
      if (field.type === "textarea") {
        input.rows = 3;
      }
      input.value = field.value ?? "";
      envSettingsInitialValues[field.key] = input.value;
      if (!field.editable) {
        input.readOnly = true;
      } else {
        input.addEventListener("input", handleEnvSettingInput);
      }
      fieldWrapper.appendChild(input);

      let hintParagraph = null;
      if (field.description) {
        hintParagraph = document.createElement("p");
        hintParagraph.className = "env-setting-hint";
        hintParagraph.textContent = field.description;
        fieldWrapper.appendChild(hintParagraph);
      }

      if (field.hint_link && field.hint_link.href) {
        const link = document.createElement("a");
        link.className = "env-setting-hint-link";
        link.href = field.hint_link.href;
        link.textContent = field.hint_link.label || "Open";
        if (hintParagraph) {
          hintParagraph.appendChild(document.createTextNode(" "));
          hintParagraph.appendChild(link);
          if (!hintParagraph.textContent.trim().endsWith(".")) {
            hintParagraph.appendChild(document.createTextNode("."));
          }
        } else {
          const standaloneHint = document.createElement("p");
          standaloneHint.className = "env-setting-hint";
          standaloneHint.appendChild(link);
          standaloneHint.appendChild(document.createTextNode("."));
          fieldWrapper.appendChild(standaloneHint);
        }
      }

      grid.appendChild(fieldWrapper);
    });

    wrapper.appendChild(grid);
    envSettingsGroupsEl.appendChild(wrapper);
  });

  updateEnvSettingsSaveState();
}

function handleEnvSettingInput(event) {
  const target = event.target;
  const key = target.dataset.key;
  if (!key) return;
  const original = envSettingsInitialValues[key] ?? "";
  if (target.value !== original) {
    envSettingsDirty.set(key, target.value);
  } else {
    envSettingsDirty.delete(key);
  }
  updateEnvSettingsSaveState();
}

function updateEnvSettingsSaveState() {
  if (!envSettingsSaveBtn) return;
  envSettingsSaveBtn.disabled = envSettingsDirty.size === 0;
}

async function loadEnvSettings() {
  if (!envSettingsCard || !envSettingsGroupsEl) return;
  envSettingsGroupsEl.innerHTML = "<p class='muted'>Loading settings…</p>";
  try {
    const response = await fetch(buildApiUrl("api/settings/env"));
    if (!response.ok) {
      throw new Error("Unable to load settings");
    }
    const data = await response.json();
    renderEnvSettings(data.settings || []);
  } catch (error) {
    envSettingsGroupsEl.innerHTML = "<p class='feedback'>Failed to load settings.</p>";
    console.error(error);
  }
}

async function saveEnvSettings() {
  if (!envSettingsSaveBtn || envSettingsDirty.size === 0) return;
  envSettingsSaveBtn.disabled = true;
  envSettingsSaveBtn.textContent = "Saving…";
  if (envSettingsFeedback) {
    envSettingsFeedback.textContent = "";
  }
  const payload = {};
  envSettingsDirty.forEach((value, key) => {
    payload[key] = value;
  });
  try {
    const response = await fetch(buildApiUrl("api/settings/env"), {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ values: payload }),
    });
    if (!response.ok) {
      const err = await response.json().catch(() => ({}));
      throw new Error(err.detail || "Failed to save settings");
    }
    envSettingsDirty.clear();
    envSettingsSaveBtn.textContent = "Saved";
    await loadEnvSettings();
  } catch (error) {
    if (envSettingsFeedback) {
      envSettingsFeedback.textContent = error.message || "Unable to save settings.";
    }
    envSettingsSaveBtn.textContent = "Save failed";
    console.error(error);
  } finally {
    setTimeout(() => {
      if (envSettingsSaveBtn) {
        envSettingsSaveBtn.textContent = "Save changes";
        updateEnvSettingsSaveState();
      }
    }, 1500);
  }
}

function extractSettled(details) {
  if (!details || typeof details !== "object") {
    return null;
  }
  if (typeof details.settled === "boolean") {
    return details.settled;
  }
  const response = details.response;
  if (response && typeof response === "object" && typeof response.settled === "boolean") {
    return response.settled;
  }
  const invoice = details.invoice;
  if (invoice && typeof invoice === "object" && typeof invoice.settled === "boolean") {
    return invoice.settled;
  }
  return null;
}

function resolvePaymentStatus(entry) {
  const settled = extractSettled(entry.details);
  if (typeof settled === "boolean") {
    return { label: settled ? "Paid" : "Pending", tone: settled ? "paid" : "pending" };
  }
  if (entry.event === "invoice" && entry.status === "ok") {
    return { label: "Pending", tone: "pending" };
  }
  if (entry.status && entry.status !== "ok") {
    return { label: "Failed", tone: "failed" };
  }
  return { label: "—", tone: "unknown" };
}

function createPaymentCell(entry) {
  const cell = document.createElement("td");
  const payment = resolvePaymentStatus(entry);
  cell.textContent = payment.label;
  cell.classList.add("payment-status");
  if (payment.tone !== "unknown") {
    cell.classList.add(`payment-status-${payment.tone}`);
  }
  return cell;
}

function updateLogPagination(meta) {
  if (!logsPageIndicator) return;
  const totalItems = Math.max(0, meta?.total_items ?? 0);
  const totalPages = Math.max(0, meta?.total_pages ?? 0);
  const currentPage = totalPages > 0 ? Math.max(1, meta?.page ?? 1) : 1;
  logTotalItems = totalItems;
  logTotalPages = totalPages;
  logPage = totalPages > 0 ? currentPage : 1;

  let summaryText;
  if (totalItems === 0) {
    summaryText = logQuery ? "No matches" : "No logs yet";
  } else if (totalPages <= 1) {
    summaryText = `${totalItems} log${totalItems === 1 ? "" : "s"}`;
  } else if (totalPages > 1) {
    summaryText = `Page ${logPage} of ${totalPages} • ${totalItems} logs`;
  }

  logsPageIndicator.textContent = summaryText;
  if (logsPrevBtn) {
    logsPrevBtn.disabled = totalPages === 0 || logPage <= 1;
  }
  if (logsNextBtn) {
    logsNextBtn.disabled = totalPages === 0 || logPage >= totalPages;
  }
}

function renderLogs(items, emptyMessage = "No activity yet.") {
  if (!logBody) return;
  const rows = Array.isArray(items) ? items : [];
  logBody.innerHTML = "";

  if (!rows.length) {
    const row = document.createElement("tr");
    const cell = document.createElement("td");
    cell.colSpan = LOG_COLUMN_COUNT || 1;
    cell.className = "placeholder";
    cell.textContent = emptyMessage;
    row.appendChild(cell);
    logBody.appendChild(row);
    return;
  }

  for (const entry of rows) {
    const row = document.createElement("tr");
    const amountSat =
      typeof entry.amount_msat === "number"
        ? Math.round(entry.amount_msat / 1000)
        : "—";

    row.appendChild(createTimestampCell(entry.timestamp));
    row.appendChild(createCell(entry.username));
    row.appendChild(createCell(entry.domain));
    row.appendChild(createCell(amountSat));
    row.appendChild(createPaymentCell(entry));
    row.appendChild(createCell(formatIp(entry.ip)));
    row.appendChild(createCell(entry.status));
    row.appendChild(createCell(entry.event));
    row.appendChild(createDetailsCell(entry));
    logBody.appendChild(row);

    const messageText = typeof entry.message === "string" ? entry.message.trim() : "";
    if (messageText) {
      row.classList.add("log-entry-row");
      const messageRow = document.createElement("tr");
      messageRow.classList.add("log-message-row");
      const messageCell = document.createElement("td");
      messageCell.colSpan = LOG_COLUMN_COUNT || row.children.length;
      messageCell.classList.add("log-message-cell");

      const label = document.createElement("span");
      label.classList.add("log-message-label");
      label.textContent = "Message";

      const text = document.createElement("span");
      text.classList.add("log-message-text");
      text.textContent = messageText;

      messageCell.appendChild(label);
      messageCell.appendChild(text);
      messageRow.appendChild(messageCell);
      logBody.appendChild(messageRow);
    }
  }
}

function renderLiquidityPlaceholder(message) {
  if (!liquidityTableBody) return;
  liquidityTableBody.innerHTML = "";
  const row = document.createElement("tr");
  const cell = document.createElement("td");
  cell.colSpan = LIQUIDITY_TABLE_COLUMNS;
  cell.className = "placeholder";
  cell.textContent = message;
  row.appendChild(cell);
  liquidityTableBody.appendChild(row);
}

function createLiquidityStatusCell(channel) {
  const cell = document.createElement("td");
  const wrapper = document.createElement("span");
  wrapper.className = "liquidity-status";
  const dot = document.createElement("span");
  dot.className = "liquidity-status-dot";
  if (channel.active) {
    dot.classList.add("active");
  }
  const label = document.createElement("span");
  label.textContent = channel.active ? "Active" : "Inactive";
  wrapper.appendChild(dot);
  wrapper.appendChild(label);
  cell.appendChild(wrapper);
  return cell;
}

function createPeerCell(channel) {
  const cell = document.createElement("td");
  cell.className = "liquidity-peer-cell";
  const wrapper = document.createElement("div");
  wrapper.className = "liquidity-peer";
  const alias = getPeerAlias(channel);
  if (alias) {
    const aliasEl = document.createElement("span");
    aliasEl.className = "liquidity-peer-alias";
    aliasEl.textContent = alias;
    wrapper.appendChild(aliasEl);
  }
  const identifierText = getChannelIdentifier(channel);
  const remotePubkey = getRemotePubkey(channel);
  if (remotePubkey) {
    const link = document.createElement("a");
    link.className = "liquidity-peer-id liquidity-peer-id-link";
    link.href = `https://amboss.space/node/${encodeURIComponent(remotePubkey)}`;
    link.target = "_blank";
    link.rel = "noopener noreferrer";
    link.textContent = identifierText;
    wrapper.appendChild(link);
  } else {
    const idEl = document.createElement("span");
    idEl.className = "liquidity-peer-id";
    idEl.textContent = identifierText;
    wrapper.appendChild(idEl);
  }
  cell.appendChild(wrapper);
  return cell;
}

function createCapacityCell(channel) {
  const cell = document.createElement("td");
  cell.className = "liquidity-capacity";
  const valueEl = document.createElement("span");
  valueEl.className = "liquidity-capacity-value";
  valueEl.textContent = formatSatAmount(channel.capacity_sat);
  cell.appendChild(valueEl);
  const totalReserve = getTotalReserve(channel);
  if (totalReserve > 0) {
    const reserveEl = document.createElement("span");
    reserveEl.className = "liquidity-capacity-reserve";
    reserveEl.textContent = `${totalReserve.toLocaleString()} sats reserved`;
    cell.appendChild(reserveEl);
  }
  return cell;
}

function renderLiquidityTable(channels) {
  if (!liquidityTableBody) return;
  const rows = Array.isArray(channels) ? channels : [];
  if (!rows.length) {
    renderLiquidityPlaceholder("No channels found. Open a channel to receive sats.");
    return;
  }
  liquidityTableBody.innerHTML = "";
  rows
    .slice()
    .sort((a, b) => (b?.receiving_capacity_sat || 0) - (a?.receiving_capacity_sat || 0))
    .forEach((channel) => {
      const row = document.createElement("tr");
      row.appendChild(createPeerCell(channel));
      row.appendChild(createLiquidityStatusCell(channel));
      row.appendChild(createCapacityCell(channel));
      const sendable = getSendableBalance(channel);
      row.appendChild(createCell(formatSatAmount(sendable ?? channel.local_balance_sat)));
      const receivable = getReceivableBalance(channel);
      row.appendChild(createCell(formatSatAmount(receivable ?? channel.remote_balance_sat)));
      liquidityTableBody.appendChild(row);
    });
}

async function fetchLiquidity() {
  const needsLiquidity =
    liquidityTableBody || liquidityMaxValueEl || liquidityMaxLabelEl || liquidityTotalEl;
  if (!needsLiquidity) {
    return;
  }
  try {
    if (liquidityMaxLabelEl) {
      liquidityMaxLabelEl.textContent = "Refreshing channel data…";
    }
    const response = await fetch(buildApiUrl("api/channels/public"));
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }
    const data = await response.json();
    const channels = Array.isArray(data.channels) ? data.channels : [];
    const totalInbound = Number(data.total_receiving_capacity_sat) || 0;
    if (liquidityTotalEl) {
      liquidityTotalEl.textContent = formatSatAmount(totalInbound);
    }
    if (liquidityMaxValueEl) {
      const sorted = channels.slice().sort(
        (a, b) => (b?.receiving_capacity_sat || 0) - (a?.receiving_capacity_sat || 0),
      );
      const maxChannel = sorted[0];
      if (maxChannel && typeof maxChannel.receiving_capacity_sat === "number") {
        liquidityMaxValueEl.textContent = formatSatAmount(maxChannel.receiving_capacity_sat);
        if (liquidityMaxLabelEl) {
          liquidityMaxLabelEl.textContent = `via ${getPeerLabel(maxChannel)}`;
        }
      } else {
        liquidityMaxValueEl.textContent = "0 sats";
        if (liquidityMaxLabelEl) {
          liquidityMaxLabelEl.textContent = "Add a channel to receive sats.";
        }
      }
    }
    renderLiquidityTable(channels);
  } catch (error) {
    console.error("Failed to load liquidity data", error);
    if (liquidityMaxValueEl) {
      liquidityMaxValueEl.textContent = "—";
    }
    if (liquidityMaxLabelEl) {
      liquidityMaxLabelEl.textContent = "Unable to load channel data.";
    }
    if (liquidityTotalEl) {
      liquidityTotalEl.textContent = "—";
    }
    renderLiquidityPlaceholder("Unable to load channels.");
  }
}

function createCell(value, className) {
  const cell = document.createElement("td");
  cell.textContent = value ?? "—";
  if (className) {
    cell.classList.add(className);
  }
  return cell;
}

function createDetailsCell(entry) {
  const cell = document.createElement("td");
  cell.classList.add("details-cell");

  const details = entry.details ?? null;
  const button = document.createElement("button");
  button.type = "button";
  button.className = "details-btn";
  if (!details || (typeof details === "object" && !Object.keys(details).length)) {
    button.textContent = "—";
    button.disabled = true;
  } else {
    button.textContent = "View";
    button.addEventListener("click", () => openDetails(details));
  }
  cell.appendChild(button);

  return cell;
}

async function refreshLogs() {
  const requestToken = ++logsFetchToken;
  if (logsPageIndicator) {
    logsPageIndicator.textContent = logQuery ? "Searching…" : "Loading…";
  }
  try {
    const params = new URLSearchParams({
      page: String(logPage),
      page_size: String(LOG_PAGE_SIZE),
    });
    if (logQuery) {
      params.set("q", logQuery);
    }
    const response = await fetch(buildApiUrl(`api/logs/recent?${params.toString()}`));
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }
    const data = await response.json();
    if (requestToken !== logsFetchToken) {
      return;
    }
    const items = data.items || [];
    const emptyMessage = logQuery ? "No logs match your search." : "No activity yet.";
    renderLogs(items, emptyMessage);
    updateLogPagination(data);
  } catch (error) {
    console.error("Failed to load logs", error);
    if (requestToken !== logsFetchToken) {
      return;
    }
    renderLogs([], "Unable to load logs.");
    updateLogPagination({ page: 1, total_pages: 0, total_items: 0 });
    if (logsPageIndicator) {
      logsPageIndicator.textContent = "Unable to load logs";
    }
  }
}

function startPolling() {
  updateStatus();
  const shouldPollLogs = Boolean(logBody);
  const shouldPollMetrics = Boolean(metricDomainsValue || metricRequestsValue);
  const shouldFetchLiquidity = Boolean(liquidityTableBody || liquidityMaxValueEl || liquidityTotalEl);
  if (shouldPollLogs) {
    refreshLogs();
  }
  if (shouldPollMetrics) {
    fetchDashboardMetrics();
  }
  if (shouldFetchLiquidity) {
    fetchLiquidity();
  }
  fetchMacaroonStatus();
  setInterval(updateStatus, POLL_INTERVAL_MS);
  if (shouldPollLogs) {
    setInterval(refreshLogs, POLL_INTERVAL_MS);
  }
  if (shouldPollMetrics) {
    setInterval(fetchDashboardMetrics, POLL_INTERVAL_MS);
  }
  if (shouldFetchLiquidity) {
    setInterval(fetchLiquidity, POLL_INTERVAL_MS);
  }
  setInterval(fetchMacaroonStatus, POLL_INTERVAL_MS);
}

function setCopyrightYear() {
  if (!copyrightYearEl) return;
  copyrightYearEl.textContent = String(new Date().getFullYear());
}

function openDetails(details) {
  if (!detailsModal || !detailsJsonEl) return;
  activeDetailsEntry = details;
  try {
    detailsJsonEl.textContent = JSON.stringify(details, null, 2);
  } catch (error) {
    detailsJsonEl.textContent = String(details);
  }
  detailsModal.classList.remove("hidden");
  detailsModal.classList.add("visible");
  updateBodyModalState();
}

function closeDetails() {
  if (!detailsModal) return;
  activeDetailsEntry = null;
  detailsModal.classList.remove("visible");
  detailsModal.classList.add("hidden");
  updateBodyModalState();
}

function handleLogsSearchInput(event) {
  const target = event.target;
  if (!(target instanceof HTMLInputElement)) {
    return;
  }
  if (logSearchDebounceId) {
    window.clearTimeout(logSearchDebounceId);
  }
  logSearchDebounceId = window.setTimeout(() => {
    const normalized = target.value.trim();
    if (normalized === logQuery) {
      return;
    }
    logQuery = normalized;
    logPage = 1;
    refreshLogs();
  }, 250);
}

document.addEventListener("DOMContentLoaded", () => {
  setCopyrightYear();
  refreshMacaroonUI();
  refreshLnurlInstructions();
  refreshSidebarNav();
  if (clearLogsBtn) {
    clearLogsBtn.addEventListener("click", handleClearLogs);
  }
  if (identityTableBody) {
    loadIdentityMappings();
  }
  if (identityNewBtn) {
    identityNewBtn.addEventListener("click", openIdentityCreateForm);
  }
  if (identitySearchInput) {
    identitySearchInput.addEventListener("input", handleIdentitySearchInput);
  }
  if (identityForm) {
    identityForm.addEventListener("submit", submitIdentityForm);
  }
  if (identityFormCancel) {
    identityFormCancel.addEventListener("click", () => setIdentityFormVisible(false));
  }
  if (identityModalCloseBtn) {
    identityModalCloseBtn.addEventListener("click", () => setIdentityFormVisible(false));
  }
  if (identityModal) {
    identityModal.addEventListener("click", (event) => {
      if (event.target instanceof HTMLElement && event.target.dataset.close === "identity-modal") {
        setIdentityFormVisible(false);
      }
    });
  }
  if (identityDeleteCancelBtn) {
    identityDeleteCancelBtn.addEventListener("click", () => setIdentityDeleteVisible(false));
  }
  if (identityDeleteCloseBtn) {
    identityDeleteCloseBtn.addEventListener("click", () => setIdentityDeleteVisible(false));
  }
  if (identityDeleteModal) {
    identityDeleteModal.addEventListener("click", (event) => {
      if (event.target instanceof HTMLElement && event.target.dataset.close === "identity-delete") {
        setIdentityDeleteVisible(false);
      }
    });
  }
  if (identityDeleteConfirmBtn) {
    identityDeleteConfirmBtn.addEventListener("click", confirmIdentityDelete);
  }
  if (logsConfirmCancelBtn) {
    logsConfirmCancelBtn.addEventListener("click", () => setLogsConfirmVisible(false));
  }
  if (logsConfirmCloseBtn) {
    logsConfirmCloseBtn.addEventListener("click", () => setLogsConfirmVisible(false));
  }
  if (logsConfirmModal) {
    logsConfirmModal.addEventListener("click", (event) => {
      if (event.target instanceof HTMLElement && event.target.dataset.close === "logs-confirm") {
        setLogsConfirmVisible(false);
      }
    });
  }
  if (logsConfirmConfirmBtn) {
    logsConfirmConfirmBtn.addEventListener("click", confirmLogsClear);
  }
  if (lnurlToggleBtn) {
    lnurlToggleBtn.addEventListener("click", () => {
      lnurlDetailsOpen = true;
      refreshLnurlInstructions();
      if (lnurlModal) {
        lnurlModal.classList.remove("hidden");
        lnurlModal.classList.add("visible");
      }
      updateBodyModalState();
    });
  }
  if (lnurlModalCloseBtn) {
    lnurlModalCloseBtn.addEventListener("click", () => {
      lnurlDetailsOpen = false;
      refreshLnurlInstructions();
      if (lnurlModal) {
        lnurlModal.classList.add("hidden");
        lnurlModal.classList.remove("visible");
      }
      updateBodyModalState();
    });
  }
  if (lnurlModal) {
    lnurlModal.addEventListener("click", (event) => {
      if (event.target instanceof HTMLElement && event.target.dataset.close === "lnurl-modal") {
        lnurlDetailsOpen = false;
        refreshLnurlInstructions();
        lnurlModal.classList.add("hidden");
        lnurlModal.classList.remove("visible");
        updateBodyModalState();
      }
    });
  }
  if (detailsCloseBtn) {
    detailsCloseBtn.addEventListener("click", closeDetails);
  }
  if (detailsModal) {
    detailsModal.addEventListener("click", (event) => {
      if (event.target instanceof HTMLElement && event.target.dataset.close === "true") {
        closeDetails();
      }
    });
  }
document.addEventListener("keydown", (event) => {
  if (event.key === "Escape") {
    if (lnurlModal?.classList.contains("visible")) {
      lnurlModal.classList.add("hidden");
      lnurlModal.classList.remove("visible");
      lnurlDetailsOpen = false;
      refreshLnurlInstructions();
      updateBodyModalState();
      return;
    }
    if (logsConfirmModal?.classList.contains("visible")) {
      setLogsConfirmVisible(false);
      return;
    }
    if (identityDeleteModal?.classList.contains("visible")) {
      setIdentityDeleteVisible(false);
      return;
    }
    if (identityModal?.classList.contains("visible")) {
      setIdentityFormVisible(false);
      return;
    }
    if (detailsModal?.classList.contains("visible")) {
      closeDetails();
    }
  }
});
  if (logsSearchInput) {
    logsSearchInput.addEventListener("input", handleLogsSearchInput);
  }
  if (logsPrevBtn) {
    logsPrevBtn.addEventListener("click", () => {
      if (logPage <= 1) {
        return;
      }
      logPage -= 1;
      refreshLogs();
    });
    logsPrevBtn.disabled = true;
  }
  if (logsNextBtn) {
    logsNextBtn.addEventListener("click", () => {
      if (logTotalPages === 0 || logPage >= logTotalPages) {
        return;
      }
      logPage += 1;
      refreshLogs();
    });
    logsNextBtn.disabled = true;
  }

  if (envSettingsCard) {
    loadEnvSettings();
    if (envSettingsSaveBtn) {
      envSettingsSaveBtn.addEventListener("click", saveEnvSettings);
    }
  }

  if (sidebarToggleBtn) {
    sidebarToggleBtn.addEventListener("click", () => {
      setSidebarOpen(!document.body.classList.contains("sidebar-open"));
    });
  }
  if (sidebarOverlay) {
    sidebarOverlay.addEventListener("click", () => setSidebarOpen(false));
  }
  document.querySelectorAll(".sidebar-link").forEach((link) => {
    link.addEventListener("click", () => {
      if (isMobileNav()) {
        setSidebarOpen(false);
      }
    });
  });
  window.addEventListener("resize", () => {
    if (!isMobileNav()) {
      setSidebarOpen(false);
    }
  });
  startPolling();
});

function setMacaroonStatus(configured, options = {}) {
  const { enforceRedirect = true } = options;
  macaroonConfigured = configured;
  if (!configured) {
    macaroonFormManuallyOpen = false;
  }
  if (enforceRedirect) {
    enforceSettingsRedirect(configured);
  }
  refreshMacaroonUI();
  if (!macaroonStatusEl) return;
  macaroonStatusEl.textContent = configured ? "Configured" : "Not configured";
  macaroonStatusEl.classList.toggle("badge-ok", configured);
  macaroonStatusEl.classList.toggle("badge-warn", !configured);
}

async function fetchMacaroonStatus() {
  try {
    const response = await fetch(buildApiUrl("api/auth/status"));
    if (!response.ok) throw new Error("status error");
    const data = await response.json();
    setMacaroonStatus(Boolean(data.configured));
  } catch (error) {
    setMacaroonStatus(false, { enforceRedirect: false });
  }
}

function setMacaroonFeedback(message, isError = false) {
  if (!macaroonFeedback) return;
  macaroonFeedback.textContent = message;
  macaroonFeedback.style.color = isError ? "#f87171" : "#34d399";
}

function setMacaroonFormVisibility(show) {
  if (!macaroonFormWrapper) return;
  macaroonFormWrapper.classList.toggle("collapsed", !show);
}

function refreshMacaroonUI() {
  const shouldShowForm = macaroonFormManuallyOpen || !macaroonConfigured;
  setMacaroonFormVisibility(shouldShowForm);
  if (!macaroonRevealBtn) return;
  macaroonRevealBtn.classList.toggle("hidden", !macaroonConfigured);
  macaroonRevealBtn.classList.toggle("active", macaroonFormManuallyOpen);
  macaroonRevealBtn.textContent = macaroonFormManuallyOpen ? "Cancel" : "Replace macaroon";
  macaroonRevealBtn.classList.toggle("ghost-btn-danger", macaroonFormManuallyOpen);
}

function refreshLnurlInstructions() {
  if (!lnurlToggleBtn) return;
  lnurlToggleBtn.setAttribute("aria-expanded", String(lnurlDetailsOpen));
  const label = lnurlToggleBtn.querySelector(".toggle-label");
  if (label) {
    label.textContent = lnurlDetailsOpen ? "Hide setup details" : "Show setup details";
  }
}

if (macaroonRevealBtn) {
  macaroonRevealBtn.addEventListener("click", () => {
    macaroonFormManuallyOpen = !macaroonFormManuallyOpen;
    refreshMacaroonUI();
    if (macaroonFormManuallyOpen) {
      macaroonInput?.focus();
    } else {
      if (macaroonFeedback) {
        macaroonFeedback.textContent = "";
      }
    }
  });
}

if (macaroonForm) {
  macaroonForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    const value = macaroonInput?.value.trim();
    if (!value) {
      setMacaroonFeedback("Please paste a macaroon in hex.", true);
      return;
    }
    try {
      const response = await fetch(buildApiUrl("api/auth/macaroon"), {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ macaroon: value }),
      });
      const data = await response.json().catch(() => ({}));
      if (!response.ok) {
        const detail = data.detail || "Failed to save macaroon.";
        throw new Error(detail);
      }
      setMacaroonFeedback("Macaroon saved successfully.");
      macaroonFormManuallyOpen = false;
      macaroonConfigured = true;
      refreshMacaroonUI();
      if (macaroonInput) {
        macaroonInput.value = "";
      }
      fetchMacaroonStatus();
    } catch (error) {
      setMacaroonFeedback(error.message, true);
    }
  });
}

async function handleClearLogs() {
  if (!clearLogsBtn) return;
  openLogsConfirmModal();
}
