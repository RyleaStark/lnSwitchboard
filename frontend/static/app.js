const statusElement = document.getElementById("service-status");
const logBody = document.getElementById("log-body");
const logTable = document.getElementById("log-table");
const POLL_INTERVAL_MS = 10000;
const MOBILE_NAV_BREAKPOINT = 1100;
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
const footerCopyEls = document.querySelectorAll("[data-footer-copy]");
const envSettingsCard = document.getElementById("env-settings-card");
const envSettingsGroupsEl = document.getElementById("env-settings-groups");
const envSettingsSaveBtn = document.getElementById("env-settings-save");
const envSettingsFeedback = document.getElementById("env-settings-feedback");
const detailsModal = document.getElementById("details-modal");
const detailsJsonEl = document.getElementById("details-json");
const detailsCloseBtn = document.getElementById("details-close");
const invoiceDetailsModal = document.getElementById("invoice-details-modal");
const invoiceDetailsCloseBtn = document.getElementById("invoice-details-close");
const invoiceDetailsTitleEl = document.getElementById("invoice-details-title");
const invoiceDetailsUsernameEl = document.getElementById("invoice-details-username");
const invoiceDetailsRecipientEl = document.getElementById("invoice-details-recipient");
const invoiceDetailsStatusEl = document.getElementById("invoice-details-status");
const invoiceDetailsAmountEl = document.getElementById("invoice-details-amount");
const invoiceDetailsCreatedEl = document.getElementById("invoice-details-created");
const invoiceDetailsExpiresEl = document.getElementById("invoice-details-expires");
const invoiceDetailsNextCheckEl = document.getElementById("invoice-details-next-check");
const invoiceDetailsLastCheckedEl = document.getElementById("invoice-details-last-checked");
const invoiceDetailsSettledAtEl = document.getElementById("invoice-details-settled-at");
const invoiceDetailsHashEl = document.getElementById("invoice-details-hash");
const invoiceDetailsRequestEl = document.getElementById("invoice-details-request");
const logsSearchInput = document.getElementById("logs-search");
const logsPrevBtn = document.getElementById("logs-prev");
const logsNextBtn = document.getElementById("logs-next");
const logsPageIndicator = document.getElementById("logs-page-indicator");
const LOG_COLUMN_COUNT = logTable ? logTable.querySelectorAll("thead th").length : 0;
const LOG_COLUMN_LABELS = logTable
  ? Array.from(logTable.querySelectorAll("thead th")).map((th) => th.textContent.trim())
  : [];
const invoiceTableBody = document.getElementById("invoice-table-body");
const invoiceTable = invoiceTableBody ? invoiceTableBody.closest("table") : null;
const invoiceSearchInput = document.getElementById("invoices-search");
const invoicePrevBtn = document.getElementById("invoices-prev");
const invoiceNextBtn = document.getElementById("invoices-next");
const invoicePageIndicator = document.getElementById("invoice-page-indicator");
const INVOICE_COLUMN_LABELS = invoiceTable
  ? Array.from(invoiceTable.querySelectorAll("thead th")).map((th) => th.textContent.trim())
  : [];
const INVOICE_COLUMN_COUNT = INVOICE_COLUMN_LABELS.length || 1;
const metricDomainsValue = document.getElementById("metric-domains");
const metricRequestsValue = document.getElementById("metric-requests");
const metricRequests7dValue = document.getElementById("metric-requests-7d");
const metricInvoicesTotalValue = document.getElementById("metric-invoices-total");
const metricInvoicesPaidValue = document.getElementById("metric-invoices-paid");
const metricInvoicesPaid24Value = document.getElementById("metric-invoices-paid24");
const metricSatsTotalValue = document.getElementById("metric-sats-total");
const metricSats7dValue = document.getElementById("metric-sats-7d");
const mixedChartCanvas = document.getElementById("mixed-chart");
const mixedChartEmpty = document.getElementById("mixed-chart-empty");
const liquidityMaxValueEl = document.getElementById("liquidity-max-value");
const liquidityMaxLabelEl = document.getElementById("liquidity-max-label");
const liquidityTotalEl = document.getElementById("liquidity-total");
const liquidityTable = document.getElementById("liquidity-table");
const liquidityTableBody = document.getElementById("liquidity-table-body");
const LIQUIDITY_COLUMN_LABELS = liquidityTable
  ? Array.from(liquidityTable.querySelectorAll("thead th")).map((th) => th.textContent.trim())
  : [];
const LIQUIDITY_COLUMN_COUNT = LIQUIDITY_COLUMN_LABELS.length || 1;
const sidebarToggleBtn = document.getElementById("sidebar-toggle");
const sidebarOverlay = document.getElementById("sidebar-overlay");
const identityTableBody = document.getElementById("identity-table-body");
const identityTable = identityTableBody ? identityTableBody.closest("table") : null;
const IDENTITY_COLUMN_LABELS = identityTable
  ? Array.from(identityTable.querySelectorAll("thead th")).map((th) => th.textContent.trim())
  : [];
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
const addressTableBody = document.getElementById("address-table-body");
const addressTablePlaceholder = document.getElementById("address-table-placeholder");
const addressNewBtn = document.getElementById("address-new-btn");
const addressSearchInput = document.getElementById("address-search");
const addressModal = document.getElementById("address-modal");
const addressModalCloseBtn = document.getElementById("address-modal-close");
const addressForm = document.getElementById("address-form");
const addressFormTitle = document.getElementById("address-form-title");
const addressFormEyebrow = document.getElementById("address-form-eyebrow");
const addressFormSubmit = document.getElementById("address-form-submit");
const addressFormCancel = document.getElementById("address-form-cancel");
const addressFormFeedback = document.getElementById("address-form-feedback");
const addressLocalInput = document.getElementById("address-local-part");
const addressDomainInput = document.getElementById("address-domain");
const addressMinInput = document.getElementById("address-min-sats");
const addressMaxInput = document.getElementById("address-max-sats");
const addressMetadataInput = document.getElementById("address-metadata-template");
const addressSuccessInput = document.getElementById("address-success-template");
const addressWebhookInput = document.getElementById("address-webhook-urls");
const addressDeleteModal = document.getElementById("address-delete-modal");
const addressDeleteMessage = document.getElementById("address-delete-message");
const addressDeleteConfirmBtn = document.getElementById("address-delete-confirm");
const addressDeleteCancelBtn = document.getElementById("address-delete-cancel");
const addressDeleteCloseBtn = document.getElementById("address-delete-close");
const addressTable = addressTableBody ? addressTableBody.closest("table") : null;
const ADDRESS_COLUMN_LABELS = addressTable
  ? Array.from(addressTable.querySelectorAll("thead th")).map((th) => th.textContent.trim())
  : [];
const ADDRESS_COLUMN_COUNT = ADDRESS_COLUMN_LABELS.length || 4;
const logsConfirmModal = document.getElementById("logs-confirm-modal");
const logsConfirmMessage = document.getElementById("logs-confirm-message");
const logsConfirmConfirmBtn = document.getElementById("logs-confirm-confirm");
const logsConfirmCancelBtn = document.getElementById("logs-confirm-cancel");
const logsConfirmCloseBtn = document.getElementById("logs-confirm-close");
const envSettingsDirty = new Map();
let envSettingsInitialValues = {};
const tooltipContainers = Array.from(document.querySelectorAll("[data-tooltip]")).filter(
  (el) => el instanceof HTMLElement
);
const LOG_PAGE_SIZE = 10;
const INVOICE_PAGE_SIZE = 10;
const assetBaseUrl = new URL(".", import.meta.url);
const TIMESTAMP_BASE_OPTIONS = { dateStyle: "medium", timeStyle: "short" };
const TIMESTAMP_WITH_TZ = { ...TIMESTAMP_BASE_OPTIONS, timeZoneName: "short" };
let logPage = 1;
let logTotalPages = 0;
let logTotalItems = 0;
let logQuery = "";
let logsFetchToken = 0;
let logSearchDebounceId;
let invoicePage = 1;
let invoiceTotalPages = 0;
let invoiceTotalItems = 0;
let invoiceQuery = "";
let invoicesFetchToken = 0;
let invoiceSearchDebounceId;
let activeDetailsEntry = null;
let macaroonFormManuallyOpen = false;
let macaroonConfigured = false;
let lnurlDetailsOpen = false;
let mixedChartInstance = null;
const identityState = {
  items: [],
  editingId: null,
  formVisible: false,
  searchQuery: "",
  pendingDeleteId: null,
};
let identityDataFetched = false;
const addressState = {
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
  ["/addresses", "ln-addresses"],
  ["/addresses/index.html", "ln-addresses"],
  ["/identities", "identities"],
  ["/identities/index.html", "identities"],
  ["/logs", "requests"],
  ["/logs/index.html", "requests"],
  ["/invoices", "invoices"],
  ["/invoices/index.html", "invoices"],
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

function setupTooltips() {
  if (!tooltipContainers.length) {
    return;
  }
  const coarsePointerMedia = window.matchMedia("(hover: none), (pointer: coarse)");
  const isCoarsePointer = coarsePointerMedia.matches;
  tooltipContainers.forEach((container) => {
    const trigger = container.querySelector("button, [data-tooltip-trigger]");
    if (trigger instanceof HTMLElement && !trigger.hasAttribute("aria-expanded")) {
      trigger.setAttribute("aria-expanded", "false");
    }
  });
  if (!isCoarsePointer) {
    tooltipContainers.forEach((container) => {
      const trigger = container.querySelector("button, [data-tooltip-trigger]");
      if (!(trigger instanceof HTMLElement)) {
        return;
      }
      trigger.addEventListener("focus", () => trigger.setAttribute("aria-expanded", "true"));
      trigger.addEventListener("blur", () => trigger.setAttribute("aria-expanded", "false"));
    });
    return;
  }
  let openContainer = null;
  const setTooltipState = (container, isOpen) => {
    if (!container) {
      return;
    }
    const trigger = container.querySelector("button, [data-tooltip-trigger]");
    container.classList.toggle("tooltip-open", isOpen);
    if (trigger instanceof HTMLElement) {
      trigger.setAttribute("aria-expanded", String(isOpen));
    }
    if (isOpen) {
      openContainer = container;
    } else if (openContainer === container) {
      openContainer = null;
    }
  };
  tooltipContainers.forEach((container) => {
    const trigger = container.querySelector("button, [data-tooltip-trigger]");
    if (!(trigger instanceof HTMLElement)) {
      return;
    }
    trigger.addEventListener("click", (event) => {
      event.preventDefault();
      event.stopPropagation();
      const isAlreadyOpen = container.classList.contains("tooltip-open");
      if (openContainer && openContainer !== container) {
        setTooltipState(openContainer, false);
      }
      setTooltipState(container, !isAlreadyOpen);
    });
  });
  const handlePointerDown = (event) => {
    if (!openContainer) {
      return;
    }
    const target = event.target;
    if (target instanceof Node && openContainer.contains(target)) {
      return;
    }
    setTooltipState(openContainer, false);
  };
  const handleKeyDown = (event) => {
    if (event.key === "Escape" && openContainer) {
      setTooltipState(openContainer, false);
    }
  };
  document.addEventListener("pointerdown", handlePointerDown);
  document.addEventListener("keydown", handleKeyDown);
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

const numberFormatter = typeof Intl !== "undefined" && Intl.NumberFormat ? new Intl.NumberFormat() : null;

function formatNumber(value) {
  if (typeof value !== "number" || Number.isNaN(value)) {
    return value === null || value === undefined ? "" : String(value);
  }
  return numberFormatter ? numberFormatter.format(value) : String(value);
}

function normalizeApiErrorDetail(detail) {
  if (!detail) {
    return null;
  }
  if (typeof detail === "string") {
    return detail;
  }
  if (Array.isArray(detail)) {
    const messages = detail
      .map((entry) => {
        if (!entry) {
          return null;
        }
        if (typeof entry === "string") {
          return entry;
        }
        if (typeof entry.msg === "string") {
          return entry.msg;
        }
        if (typeof entry.message === "string") {
          return entry.message;
        }
        if (typeof entry.detail === "string") {
          return entry.detail;
        }
        return null;
      })
      .filter(Boolean);
    if (messages.length) {
      return messages.join("; ");
    }
  }
  if (typeof detail === "object") {
    if (typeof detail.message === "string") {
      return detail.message;
    }
    if (typeof detail.detail === "string") {
      return detail.detail;
    }
  }
  try {
    return JSON.stringify(detail);
  } catch {
    return String(detail);
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

function createLogTimestampCell(entry) {
  const cell = document.createElement("td");
  const wrapper = document.createElement("div");
  wrapper.className = "log-timestamp";
  const primary = document.createElement("span");
  primary.className = "log-timestamp-primary";
  const formatted = formatTimestamp(entry?.timestamp);
  if (formatted) {
    primary.textContent = formatted.display;
    cell.title = `${formatted.iso} (UTC)`;
  } else if (entry && entry.timestamp) {
    primary.textContent = String(entry.timestamp);
  } else {
    primary.textContent = "—";
  }
  wrapper.appendChild(primary);
  const rawIp = typeof entry?.ip === "string" ? entry.ip.trim() : "";
  if (rawIp) {
    const meta = document.createElement("span");
    meta.className = "log-timestamp-meta";
    meta.textContent = formatIp(rawIp);
    wrapper.appendChild(meta);
  }
  cell.appendChild(wrapper);
  return cell;
}

function createLogRecipientCell(entry) {
  const cell = document.createElement("td");
  const wrapper = document.createElement("div");
  wrapper.className = "log-recipient";
  const username = typeof entry?.username === "string" ? entry.username.trim() : "";
  const domain = typeof entry?.domain === "string" ? entry.domain.trim() : "";
  const primary = document.createElement("span");
  primary.className = "log-recipient-primary";
  primary.textContent = username || domain || "—";
  wrapper.appendChild(primary);
  if (domain) {
    const secondary = document.createElement("span");
    secondary.className = "log-recipient-secondary";
    secondary.textContent = username ? `@${domain}` : domain;
    wrapper.appendChild(secondary);
  }
  cell.appendChild(wrapper);
  return cell;
}

function getLogAmountSat(entry) {
  if (!entry) {
    return null;
  }
  if (typeof entry.amount_sat === "number" && Number.isFinite(entry.amount_sat)) {
    return entry.amount_sat;
  }
  if (typeof entry.amount_msat === "number" && Number.isFinite(entry.amount_msat)) {
    return Math.round(entry.amount_msat / 1000);
  }
  return null;
}

function createLogAmountCell(entry) {
  const cell = document.createElement("td");
  const wrapper = document.createElement("div");
  wrapper.className = "log-amount";
  const payment = resolvePaymentStatus(entry);
  const tone = payment?.tone || "unknown";
  const pill = document.createElement("span");
  pill.className = `status-pill log-amount-status status-pill-${tone}`;
  pill.textContent = payment?.label ?? "—";
  wrapper.appendChild(pill);
  const shouldShowAmount = !["verify", "discovery"].includes(
    normalizeLogEventKey(entry?.event),
  );
  if (shouldShowAmount) {
    const amountSat = getLogAmountSat(entry);
    const amountValue = document.createElement("span");
    amountValue.className = "log-amount-value";
    amountValue.textContent =
      typeof amountSat === "number" && Number.isFinite(amountSat)
        ? formatSatAmount(amountSat)
        : "—";
    wrapper.appendChild(amountValue);
  }
  cell.appendChild(wrapper);
  return cell;
}

function normalizeLogEventKey(value) {
  if (typeof value !== "string") {
    return "unknown";
  }
  const trimmed = value.trim().toLowerCase();
  if (!trimmed) {
    return "unknown";
  }
  return trimmed.replace(/[^a-z0-9_-]+/g, "-");
}

function formatLogEventLabel(value) {
  if (typeof value !== "string") {
    return "—";
  }
  const trimmed = value.trim();
  if (!trimmed) {
    return "—";
  }
  return trimmed
    .replace(/[_-]+/g, " ")
    .split(/\s+/)
    .filter(Boolean)
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(" ");
}

function createLogEventCell(entry) {
  const cell = document.createElement("td");
  const pill = document.createElement("span");
  const normalized = normalizeLogEventKey(entry?.event);
  const label = formatLogEventLabel(entry?.event);
  pill.className = `log-event-pill log-event-pill-${normalized}`;
  pill.textContent = label;
  cell.appendChild(pill);
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

function ensureMixedChart() {
  if (!mixedChartCanvas || typeof Chart === "undefined") {
    return null;
  }
  if (mixedChartInstance) {
    return mixedChartInstance;
  }
  mixedChartInstance = new Chart(mixedChartCanvas, {
    data: {
      labels: [],
      datasets: [
        {
          type: "bar",
          label: "Invoices paid",
          data: [],
          backgroundColor: "rgba(122, 147, 255, 0.28)",
          borderColor: "rgba(122, 147, 255, 0.65)",
          borderWidth: 1,
          borderRadius: 8,
          borderSkipped: false,
          order: 0,
          yAxisID: "y",
        },
        {
          type: "line",
          label: "Sats stacked",
          data: [],
          fill: false,
          borderColor: "#f7931a",
          pointBackgroundColor: "#f7931a",
          pointBorderColor: "#f7931a",
          borderWidth: 2,
          tension: 0.25,
          pointRadius: 3,
          order: 10,
          yAxisID: "y1",
        },
      ],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      interaction: { intersect: false, mode: "index" },
      plugins: {
        legend: {
          display: true,
          labels: {
            color: "#ffffff",
          },
        },
        tooltip: {
          callbacks: {
            label(context) {
              const value = context.parsed.y || 0;
              if (context.dataset.type === "line") {
                return `${context.dataset.label}: ${value.toLocaleString()} sats`;
              }
              return `${context.dataset.label}: ${value.toLocaleString()}`;
            },
          },
        },
      },
      scales: {
        y: {
          beginAtZero: true,
          ticks: { precision: 0, color: "#ffffff" },
          grid: { color: "rgba(148, 163, 184, 0.25)" },
          title: { display: true, text: "Invoices", color: "#ffffff" },
        },
        y1: {
          beginAtZero: true,
          position: "right",
          ticks: { precision: 0, color: "#ffffff" },
          grid: { drawOnChartArea: false },
          title: { display: true, text: "Sats", color: "#ffffff" },
        },
        x: {
          grid: { display: false },
          ticks: {
            color: "#ffffff",
            maxRotation: 0,
            autoSkip: true,
            maxTicksLimit: 6,
          },
        },
      },
    },
  });
  return mixedChartInstance;
}

function renderMixedChart(series) {
  const chart = ensureMixedChart();
  if (!chart) return;
  const items = Array.isArray(series) ? series.slice(-14) : [];
  const labels = items.map((item) => formatChartDateLabel(item?.date));
  const satsData = items.map((item) => Number(item?.sats) || 0);
  const paidData = items.map((item) => Number(item?.paid) || 0);
  chart.data.labels = labels;
  chart.data.datasets[0].data = paidData;
  chart.data.datasets[1].data = satsData;
  chart.data.datasets.sort((a, b) => (a.order ?? 0) - (b.order ?? 0));
  chart.update();
  const hasData = satsData.some((value) => value > 0) || paidData.some((value) => value > 0);
  if (mixedChartEmpty) {
    mixedChartEmpty.classList.toggle("visible", !hasData);
  }
}

function formatChartDateLabel(dateStr) {
  if (!dateStr) return "--";
  const parts = dateStr.split("-");
  if (parts.length !== 3) return dateStr;
  return `${parts[1]}/${parts[2]}`;
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

function setSatMetricValue(target, value) {
  if (!target) return;
  if (typeof value === "number" && Number.isFinite(value)) {
    target.textContent = formatSatAmount(value);
  } else {
    target.textContent = "—";
  }
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
  const needsMetrics =
    metricDomainsValue ||
    metricRequestsValue ||
    metricRequests7dValue ||
    metricInvoicesTotalValue ||
    metricInvoicesPaidValue ||
    metricInvoicesPaid24Value ||
    metricSatsTotalValue ||
    metricSats7dValue;
  if (!needsMetrics) {
    return;
  }
  try {
    const summaryUrl = new URL(buildApiUrl("api/stats/summary"));
    summaryUrl.searchParams.set("tz_offset_minutes", String(new Date().getTimezoneOffset()));
    const response = await fetch(summaryUrl);
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }
    const data = await response.json();
    setMetricValue(metricDomainsValue, formatMetricNumber(data.connected_domains));
    setMetricValue(metricRequestsValue, formatMetricNumber(data.requests_24h));
    setMetricValue(metricRequests7dValue, formatMetricNumber(data.requests_7d));
    setMetricValue(metricInvoicesTotalValue, formatMetricNumber(data.invoices_total));
    setMetricValue(metricInvoicesPaidValue, formatMetricNumber(data.invoices_paid));
    setMetricValue(metricInvoicesPaid24Value, formatMetricNumber(data.invoices_paid_24h));
    setSatMetricValue(metricSatsTotalValue, data.total_sats_routed);
    setSatMetricValue(metricSats7dValue, data.sats_routed_7d);
    renderMixedChart(data.invoice_activity || []);
  } catch (error) {
    console.error("Failed to load dashboard metrics", error);
    setMetricValue(metricDomainsValue, "—");
    setMetricValue(metricRequestsValue, "—");
    setMetricValue(metricRequests7dValue, "—");
    setMetricValue(metricInvoicesTotalValue, "—");
    setMetricValue(metricInvoicesPaidValue, "—");
    setMetricValue(metricInvoicesPaid24Value, "—");
    setSatMetricValue(metricSatsTotalValue, NaN);
    setSatMetricValue(metricSats7dValue, NaN);
    renderMixedChart([]);
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
  const wrapper = document.createElement("div");
  wrapper.className = "identity-actions";
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
  wrapper.appendChild(editBtn);
  wrapper.appendChild(deleteBtn);
  cell.appendChild(wrapper);
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
    const cells = [
      createIdentityHandleCell(item),
      createIdentityRelaysCell(item),
      createIdentityActionsCell(item),
    ];
    cells.forEach((cell, index) => {
      applyStackableLabel(cell, IDENTITY_COLUMN_LABELS[index]);
      row.appendChild(cell);
    });
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
  if (identityTablePlaceholder) {
    identityTablePlaceholder.textContent = "Loading mappings…";
  }
  try {
    await fetchIdentityItems(true);
    renderIdentityTable();
  } catch (error) {
    console.error("Failed to load NIP-05 identities", error);
    if (identityTableBody) {
      renderIdentityPlaceholder("Unable to load mappings right now.");
    }
  }
}

async function fetchIdentityItems(force = false) {
  if (identityDataFetched && !force) {
    return identityState.items;
  }
  try {
    const response = await fetch(buildApiUrl("api/nip05/identities"));
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }
    const data = await response.json();
    const items = Array.isArray(data.items) ? data.items : [];
    identityState.items = sortIdentityItems(items);
    identityDataFetched = true;
    if (addressTableBody) {
      renderAddressTable();
    }
    return identityState.items;
  } catch (error) {
    identityDataFetched = false;
    throw error;
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
  if (addressTableBody) {
    renderAddressTable();
  }
}

function removeIdentityLocal(id) {
  identityState.items = identityState.items.filter((item) => item.id !== id);
  renderIdentityTable();
  if (addressTableBody) {
    renderAddressTable();
  }
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

function sortAddressItems(items) {
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

function getAddressIdentifier(item) {
  if (!item) return "";
  if (item.identifier) {
    return item.identifier;
  }
  return `${item.local_part || ""}@${item.domain || ""}`;
}

function hasIdentityForAddress(localPart, domain) {
  if (!localPart || !domain) return false;
  const normalizedLocal = localPart.trim().toLowerCase();
  const normalizedDomain = domain.trim().toLowerCase();
  return identityState.items.some(
    (identity) =>
      identity &&
      (identity.local_part || "").toLowerCase() === normalizedLocal &&
      (identity.domain || "").toLowerCase() === normalizedDomain
  );
}

function renderAddressPlaceholder(message) {
  if (!addressTableBody) return;
  const row = document.createElement("tr");
  const cell = document.createElement("td");
  cell.colSpan = ADDRESS_COLUMN_COUNT;
  cell.className = "placeholder";
  cell.textContent = message;
  row.appendChild(cell);
  addressTableBody.innerHTML = "";
  addressTableBody.appendChild(row);
}

function createAddressHandleCell(item) {
  const cell = document.createElement("td");
  const wrapper = document.createElement("div");
  wrapper.className = "address-handle";
  const label = document.createElement("p");
  label.className = "address-handle-label";
  label.textContent = getAddressIdentifier(item);
  wrapper.appendChild(label);
  if (hasIdentityForAddress(item.local_part, item.domain)) {
    const badge = document.createElement("span");
    badge.className = "address-badge";
    badge.textContent = "Nostr identity linked";
    wrapper.appendChild(badge);
  }
  if (Array.isArray(item.webhook_urls) && item.webhook_urls.length) {
    const badge = document.createElement("span");
    badge.className = "address-badge";
    badge.textContent = item.webhook_urls.length === 1 ? "Webhook configured" : "Webhooks configured";
    wrapper.appendChild(badge);
  }
  if (item.tag) {
    const tagLine = document.createElement("p");
    tagLine.className = "address-handle-domain";
    tagLine.textContent = `Tag: ${item.tag}`;
    wrapper.appendChild(tagLine);
  }
  cell.appendChild(wrapper);
  return cell;
}

function createAddressLimitsCell(item) {
  const cell = document.createElement("td");
  const wrapper = document.createElement("div");
  wrapper.className = "address-limits";
  const minLine = document.createElement("span");
  const minValue = typeof item.min_sats === "number" ? `${formatNumber(item.min_sats)} sats` : "Global minimum";
  minLine.innerHTML = `<span class="address-limit-label">Min:</span> <span class="address-limit-highlight">${minValue}</span>`;
  wrapper.appendChild(minLine);
  const maxLine = document.createElement("span");
  const maxValue = typeof item.max_sats === "number" ? `${formatNumber(item.max_sats)} sats` : "Channel max";
  maxLine.innerHTML = `<span class="address-limit-label">Max:</span> <span class="address-limit-highlight">${maxValue}</span>`;
  wrapper.appendChild(maxLine);
  cell.appendChild(wrapper);
  return cell;
}

function summarizeTemplate(value) {
  const normalized = typeof value === "string" ? value.trim() : "";
  return normalized || "Inherits global default";
}

function createAddressTemplatesCell(item) {
  const cell = document.createElement("td");
  const wrapper = document.createElement("div");
  wrapper.className = "address-templates";
  const metadataLine = document.createElement("div");
  metadataLine.className = "address-template-line";
  const metadataLabel = document.createElement("span");
  metadataLabel.className = "address-template-label";
  metadataLabel.textContent = "Metadata";
  const metadataValue = document.createElement("span");
  metadataValue.className = "address-template-value";
  metadataValue.textContent = summarizeTemplate(item.metadata_description);
  metadataLine.appendChild(metadataLabel);
  metadataLine.appendChild(metadataValue);
  const successLine = document.createElement("div");
  successLine.className = "address-template-line";
  const successLabel = document.createElement("span");
  successLabel.className = "address-template-label";
  successLabel.textContent = "Success";
  const successValue = document.createElement("span");
  successValue.className = "address-template-value";
  successValue.textContent = summarizeTemplate(item.success_message);
  successLine.appendChild(successLabel);
  successLine.appendChild(successValue);
  wrapper.appendChild(metadataLine);
  wrapper.appendChild(successLine);
  cell.appendChild(wrapper);
  return cell;
}

function createAddressActionsCell(item) {
  const cell = document.createElement("td");
  cell.className = "address-actions-col";
  const wrapper = document.createElement("div");
  wrapper.className = "address-actions";
  const editBtn = document.createElement("button");
  editBtn.type = "button";
  editBtn.className = "address-action-btn";
  editBtn.textContent = "Edit";
  editBtn.addEventListener("click", () => handleAddressEdit(item.id));
  const deleteBtn = document.createElement("button");
  deleteBtn.type = "button";
  deleteBtn.className = "address-action-btn";
  deleteBtn.textContent = "Delete";
  deleteBtn.addEventListener("click", () => handleAddressDelete(item.id));
  wrapper.appendChild(editBtn);
  wrapper.appendChild(deleteBtn);
  cell.appendChild(wrapper);
  return cell;
}

function getDisplayAddressItems() {
  const items = Array.isArray(addressState.items) ? addressState.items : [];
  const query = (addressState.searchQuery || "").trim().toLowerCase();
  if (!query) {
    return sortAddressItems(items);
  }
  const filtered = items.filter((item) => {
    const identifier = getAddressIdentifier(item).toLowerCase();
    const domain = (item.domain || "").toLowerCase();
    const metadata = (item.metadata_description || "").toLowerCase();
    const success = (item.success_message || "").toLowerCase();
    const webhook = Array.isArray(item.webhook_urls) ? item.webhook_urls.join(" ").toLowerCase() : "";
    const min = typeof item.min_sats === "number" ? String(item.min_sats) : "";
    const max = typeof item.max_sats === "number" ? String(item.max_sats) : "";
    return (
      identifier.includes(query) ||
      domain.includes(query) ||
      metadata.includes(query) ||
      success.includes(query) ||
      webhook.includes(query) ||
      min.includes(query) ||
      max.includes(query)
    );
  });
  return sortAddressItems(filtered);
}

function renderAddressTable() {
  if (!addressTableBody) return;
  const rows = getDisplayAddressItems();
  if (!rows.length) {
    const emptyMessage = addressState.searchQuery
      ? "No LN Addresses match your search."
      : "No LN Addresses yet. Click “Add Address” to create your first one.";
    renderAddressPlaceholder(emptyMessage);
    return;
  }
  addressTableBody.innerHTML = "";
  rows.forEach((item) => {
    const row = document.createElement("tr");
    const cells = [
      createAddressHandleCell(item),
      createAddressLimitsCell(item),
      createAddressTemplatesCell(item),
      createAddressActionsCell(item),
    ];
    cells.forEach((cell, index) => {
      applyStackableLabel(cell, ADDRESS_COLUMN_LABELS[index]);
      row.appendChild(cell);
    });
    addressTableBody.appendChild(row);
  });
}

function setAddressFormFeedback(message, isError = false) {
  if (!addressFormFeedback) return;
  addressFormFeedback.textContent = message || "";
  addressFormFeedback.style.color = isError ? "#f87171" : "#34d399";
}

function sanitizeAddressLocal(value) {
  if (typeof value !== "string") return "";
  return value.trim().toLowerCase();
}

function resetAddressForm() {
  addressForm?.reset();
}

function setAddressFormVisible(visible) {
  addressState.formVisible = Boolean(visible);
  if (!addressModal) return;
  addressModal.classList.toggle("hidden", !visible);
  addressModal.classList.toggle("visible", visible);
  if (!visible) {
    addressState.editingId = null;
    setAddressFormFeedback("");
    resetAddressForm();
  } else if (addressLocalInput) {
    addressLocalInput.focus();
  }
  updateBodyModalState();
}

function openAddressCreateForm() {
  if (addressFormTitle) {
    addressFormTitle.textContent = "Add LN address";
  }
  if (addressFormEyebrow) {
    addressFormEyebrow.textContent = "Create";
  }
  if (addressFormSubmit) {
    addressFormSubmit.textContent = "Create Override";
    addressFormSubmit.disabled = false;
  }
  addressState.editingId = null;
  resetAddressForm();
  setAddressFormFeedback("");
  setAddressFormVisible(true);
}

function openAddressEditForm(item) {
  if (!item) return;
  addressState.editingId = item.id;
  if (addressFormTitle) {
    addressFormTitle.textContent = `Edit ${getAddressIdentifier(item)}`;
  }
  if (addressFormEyebrow) {
    addressFormEyebrow.textContent = "Edit";
  }
  if (addressFormSubmit) {
    addressFormSubmit.textContent = "Save changes";
    addressFormSubmit.disabled = false;
  }
  if (addressLocalInput) {
    addressLocalInput.value = item.local_part || "";
  }
  if (addressDomainInput) {
    addressDomainInput.value = item.domain || "";
  }
  if (addressMinInput) {
    addressMinInput.value = typeof item.min_sats === "number" ? String(item.min_sats) : "";
  }
  if (addressMaxInput) {
    addressMaxInput.value = typeof item.max_sats === "number" ? String(item.max_sats) : "";
  }
  if (addressMetadataInput) {
    addressMetadataInput.value = item.metadata_description || "";
  }
  if (addressSuccessInput) {
    addressSuccessInput.value = item.success_message || "";
  }
  if (addressWebhookInput) {
    const urls = Array.isArray(item.webhook_urls) ? item.webhook_urls.join("\n") : "";
    addressWebhookInput.value = urls;
  }
  setAddressFormFeedback("");
  setAddressFormVisible(true);
}

function collectAddressFormData() {
  const localPart = sanitizeAddressLocal(addressLocalInput?.value || "");
  const domain = normalizeDomainInput(addressDomainInput?.value || "");
  const minRaw = addressMinInput?.value.trim() || "";
  const maxRaw = addressMaxInput?.value.trim() || "";
  const metadata = addressMetadataInput?.value.trim() || "";
  const success = addressSuccessInput?.value.trim() || "";
  const webhookRaw = addressWebhookInput?.value || "";
  if (!localPart || !domain) {
    setAddressFormFeedback("Local-part and domain are required.", true);
    return null;
  }
  let minSats = null;
  let maxSats = null;
  if (minRaw) {
    const parsed = Number(minRaw);
    if (!Number.isFinite(parsed) || parsed <= 0) {
      setAddressFormFeedback("Minimum sats must be a positive number.", true);
      return null;
    }
    minSats = Math.floor(parsed);
  }
  if (maxRaw) {
    const parsed = Number(maxRaw);
    if (!Number.isFinite(parsed) || parsed <= 0) {
      setAddressFormFeedback("Maximum sats must be a positive number.", true);
      return null;
    }
    maxSats = Math.floor(parsed);
  }
  if (minSats !== null && maxSats !== null && maxSats < minSats) {
    setAddressFormFeedback("Maximum sats must be greater than or equal to the minimum.", true);
    return null;
  }
  const webhookUrls = [];
  if (webhookRaw) {
    const entries = webhookRaw
      .split(/\r?\n/)
      .map((line) => line.trim())
      .filter(Boolean);
    for (const entry of entries) {
      let parsed;
      try {
        parsed = new URL(entry);
      } catch (error) {
        setAddressFormFeedback("Each webhook URL must be a valid http(s) address.", true);
        return null;
      }
      if (!/^https?:$/i.test(parsed.protocol) || !parsed.hostname) {
        setAddressFormFeedback("Webhook URLs must start with http(s):// and include a host.", true);
        return null;
      }
      const normalized = parsed.toString();
      if (!webhookUrls.includes(normalized)) {
        webhookUrls.push(normalized);
      }
    }
  }
  return {
    local_part: localPart,
    domain,
    min_sats: minSats,
    max_sats: maxSats,
    metadata_description: metadata || null,
    success_message: success || null,
    webhook_urls: webhookUrls,
  };
}

function setAddressFormPending(pending) {
  if (!addressFormSubmit) return;
  const isEdit = Boolean(addressState.editingId);
  if (pending) {
    addressFormSubmit.disabled = true;
    addressFormSubmit.textContent = isEdit ? "Saving…" : "Creating…";
  } else {
    addressFormSubmit.disabled = false;
    addressFormSubmit.textContent = isEdit ? "Save changes" : "Create Override";
  }
}

async function submitAddressForm(event) {
  event.preventDefault();
  if (!addressForm) return;
  const payload = collectAddressFormData();
  if (!payload) {
    return;
  }
  const editingId = addressState.editingId;
  const method = editingId ? "PUT" : "POST";
  const endpoint = editingId ? `api/lnaddresses/${editingId}` : "api/lnaddresses";
  setAddressFormPending(true);
  setAddressFormFeedback("");
  try {
    const response = await fetch(buildApiUrl(endpoint), {
      method,
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = normalizeApiErrorDetail(data.detail) || "Unable to save LN address.";
      throw new Error(detail);
    }
    if (data.item) {
      upsertAddressLocal(data.item);
    }
    setAddressFormVisible(false);
  } catch (error) {
    setAddressFormFeedback(error.message || "Failed to save LN address.", true);
  } finally {
    setAddressFormPending(false);
  }
}

async function fetchAddresses() {
  if (!addressTableBody) {
    return;
  }
  if (addressTablePlaceholder) {
    addressTablePlaceholder.textContent = "Loading addresses…";
  }
  try {
    const response = await fetch(buildApiUrl("api/lnaddresses"));
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }
    const data = await response.json();
    const items = Array.isArray(data.items) ? data.items : [];
    addressState.items = sortAddressItems(items);
    renderAddressTable();
  } catch (error) {
    console.error("Failed to load LN addresses", error);
    renderAddressPlaceholder("Unable to load LN addresses right now.");
  }
}

function upsertAddressLocal(item) {
  const items = Array.isArray(addressState.items) ? addressState.items.slice() : [];
  const index = items.findIndex((entry) => entry.id === item.id);
  if (index >= 0) {
    items[index] = item;
  } else {
    items.push(item);
  }
  addressState.items = sortAddressItems(items);
  renderAddressTable();
}

function removeAddressLocal(id) {
  addressState.items = addressState.items.filter((item) => item.id !== id);
  renderAddressTable();
}

function handleAddressEdit(addressId) {
  const entry = addressState.items.find((item) => item.id === addressId);
  if (!entry) return;
  openAddressEditForm(entry);
}

function handleAddressDelete(addressId) {
  const entry = addressState.items.find((item) => item.id === addressId);
  if (!entry) return;
  openAddressDeleteModal(entry);
}

function setAddressDeleteVisible(visible) {
  if (!addressDeleteModal) return;
  addressDeleteModal.classList.toggle("hidden", !visible);
  addressDeleteModal.classList.toggle("visible", visible);
  if (!visible) {
    addressState.pendingDeleteId = null;
    if (addressDeleteConfirmBtn) {
      const defaultText = addressDeleteConfirmBtn.dataset.defaultText || "Delete LN Address";
      addressDeleteConfirmBtn.textContent = defaultText;
      addressDeleteConfirmBtn.disabled = false;
    }
  }
  updateBodyModalState();
}

function openAddressDeleteModal(entry) {
  addressState.pendingDeleteId = entry.id;
  if (addressDeleteMessage) {
    addressDeleteMessage.textContent = `Remove ${getAddressIdentifier(entry)} from LN Addresses? This stops any custom limits, templates, or webhook automation.`;
  }
  if (addressDeleteConfirmBtn) {
    const defaultText = addressDeleteConfirmBtn.dataset.defaultText || "Delete LN Address";
    addressDeleteConfirmBtn.textContent = defaultText;
    addressDeleteConfirmBtn.disabled = false;
  }
  setAddressDeleteVisible(true);
}

async function confirmAddressDelete() {
  const addressId = addressState.pendingDeleteId;
  if (!addressId) {
    return;
  }
  if (addressDeleteConfirmBtn) {
    addressDeleteConfirmBtn.disabled = true;
    addressDeleteConfirmBtn.textContent = "Deleting…";
  }
  try {
    const response = await fetch(buildApiUrl(`api/lnaddresses/${addressId}`), {
      method: "DELETE",
    });
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }
    removeAddressLocal(addressId);
    setAddressDeleteVisible(false);
  } catch (error) {
    window.alert("Failed to delete LN address. Please retry.");
    if (addressDeleteConfirmBtn) {
      const defaultText = addressDeleteConfirmBtn.dataset.defaultText || "Delete LN Address";
      addressDeleteConfirmBtn.textContent = defaultText;
      addressDeleteConfirmBtn.disabled = false;
    }
  }
}

function handleAddressSearchInput(event) {
  const target = event.currentTarget;
  if (!(target instanceof HTMLInputElement)) {
    return;
  }
  addressState.searchQuery = target.value || "";
  renderAddressTable();
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

function extractInvoice(details) {
  if (!details || typeof details !== "object") {
    return null;
  }
  const invoice = details.invoice;
  if (invoice && typeof invoice === "object") {
    return invoice;
  }
  return null;
}

function isInvoiceExpired(details) {
  const invoice = extractInvoice(details);
  if (!invoice) {
    return null;
  }
  if (typeof invoice.is_expired === "boolean") {
    return invoice.is_expired;
  }
  if (typeof invoice.expires_at === "string") {
    const expiresAt = new Date(invoice.expires_at);
    if (!Number.isNaN(expiresAt.getTime())) {
      return expiresAt.getTime() <= Date.now();
    }
  }
  if (typeof invoice.state === "string") {
    const normalized = invoice.state.trim().toUpperCase();
    if (normalized === "CANCELED") {
      if (typeof invoice.settled === "boolean") {
        return invoice.settled === false;
      }
      return true;
    }
  }
  return null;
}

function resolvePaymentStatus(entry) {
  const expired = isInvoiceExpired(entry.details);
  if (expired === true) {
    return { label: "Expired", tone: "expired" };
  }
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
    const cells = [
      createLogTimestampCell(entry),
      createLogRecipientCell(entry),
      createLogAmountCell(entry),
      createLogEventCell(entry),
      createDetailsCell(entry),
    ];
    cells.forEach((cell, index) => {
      applyStackableLabel(cell, LOG_COLUMN_LABELS[index]);
      row.appendChild(cell);
    });
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

function shortenHash(value, prefix = 8, suffix = 6) {
  if (typeof value !== "string") {
    return "—";
  }
  const trimmed = value.trim();
  if (trimmed.length <= prefix + suffix + 3) {
    return trimmed;
  }
  return `${trimmed.slice(0, prefix)}…${trimmed.slice(-suffix)}`;
}

function createHashCell(value) {
  const cell = document.createElement("td");
  if (!value) {
    cell.textContent = "—";
    return cell;
  }
  const code = document.createElement("code");
  code.className = "hash-value";
  code.textContent = shortenHash(value);
  code.title = value;
  cell.appendChild(code);
  return cell;
}

function getInvoiceStatus(invoice) {
  if (typeof invoice.status === "string" && invoice.status) {
    return invoice.status.toLowerCase();
  }
  if (invoice.settled) {
    return "settled";
  }
  if (invoice.expired) {
    return "expired";
  }
  return "pending";
}

function createInvoiceStatusPill(invoice) {
  const status = getInvoiceStatus(invoice);
  const normalized = normalizeInvoiceStatus(status);
  const pill = document.createElement("span");
  pill.className = `status-pill status-pill-${normalized}`;
  pill.textContent = formatInvoiceStatusLabel(status);
  return pill;
}

function createInvoiceAmountCell(invoice, amountText) {
  const cell = document.createElement("td");
  const wrapper = document.createElement("div");
  wrapper.className = "invoice-amount";
  const pill = createInvoiceStatusPill(invoice);
  pill.classList.add("invoice-amount-status");
  const amountValue = document.createElement("span");
  amountValue.className = "invoice-amount-value";
  amountValue.textContent = amountText;
  wrapper.appendChild(pill);
  wrapper.appendChild(amountValue);
  cell.appendChild(wrapper);
  return cell;
}

function normalizeInvoiceStatus(status) {
  if (typeof status !== "string") {
    return "unknown";
  }
  const normalized = status.toLowerCase();
  return ["settled", "pending", "expired"].includes(normalized) ? normalized : "unknown";
}

function formatInvoiceStatusLabel(status) {
  const normalized = normalizeInvoiceStatus(status);
  return normalized.charAt(0).toUpperCase() + normalized.slice(1);
}

function getInvoiceAmountSat(invoice) {
  if (!invoice) {
    return null;
  }
  if (typeof invoice.amount_sat === "number" && Number.isFinite(invoice.amount_sat)) {
    return invoice.amount_sat;
  }
  if (typeof invoice.amount_msat === "number" && Number.isFinite(invoice.amount_msat)) {
    return Math.round(invoice.amount_msat / 1000);
  }
  return null;
}

function formatInvoiceRecipient(invoice) {
  if (!invoice) {
    return "—";
  }
  const username = typeof invoice.username === "string" ? invoice.username.trim() : "";
  const domain = typeof invoice.domain === "string" ? invoice.domain.trim() : "";
  if (username && domain) {
    return `${username}@${domain}`;
  }
  if (username) {
    return username;
  }
  if (domain) {
    return domain;
  }
  return "—";
}

function createRecipientCell(invoice) {
  const cell = document.createElement("td");
  const username = typeof invoice?.username === "string" ? invoice.username.trim() : "";
  const domain = typeof invoice?.domain === "string" ? invoice.domain.trim() : "";
  const wrapper = document.createElement("div");
  wrapper.className = "invoice-recipient";
  const primary = document.createElement("span");
  primary.className = "invoice-recipient-primary";
  primary.textContent = username || domain || "—";
  wrapper.appendChild(primary);
  if (domain) {
    const secondary = document.createElement("span");
    secondary.className = "invoice-recipient-secondary";
    secondary.textContent = username ? `@${domain}` : domain;
    wrapper.appendChild(secondary);
  }
  cell.appendChild(wrapper);
  return cell;
}

function createInvoiceDetailsCell(invoice) {
  const cell = document.createElement("td");
  cell.classList.add("details-cell");
  const button = document.createElement("button");
  button.type = "button";
  button.className = "details-btn";
  button.textContent = "View";
  button.addEventListener("click", () => openInvoiceDetails(invoice));
  cell.appendChild(button);
  return cell;
}

function setInvoiceDetailsTimestamp(target, value, fallback = "—") {
  if (!target) return;
  const formatted = formatTimestamp(value);
  if (formatted) {
    target.textContent = formatted.display;
    target.title = `${formatted.iso} (UTC)`;
  } else {
    target.textContent = fallback;
    target.removeAttribute("title");
  }
}

function applyInvoiceDetailsStatus(invoice) {
  if (!invoiceDetailsStatusEl) return;
  const status = getInvoiceStatus(invoice);
  const normalized = normalizeInvoiceStatus(status);
  invoiceDetailsStatusEl.textContent = formatInvoiceStatusLabel(status);
  invoiceDetailsStatusEl.className = `status-pill status-pill-${normalized}`;
}

function populateInvoiceDetails(invoice) {
  if (!invoice) {
    return;
  }
  const recipient = formatInvoiceRecipient(invoice);
  if (invoiceDetailsTitleEl) {
    invoiceDetailsTitleEl.textContent =
      recipient && recipient !== "—" ? `Invoice for ${recipient}` : "Invoice details";
  }
  if (invoiceDetailsUsernameEl) {
    const username = typeof invoice.username === "string" ? invoice.username.trim() : "";
    const domain = typeof invoice.domain === "string" ? invoice.domain.trim() : "";
    invoiceDetailsUsernameEl.textContent = username ? `@${username}` : domain || "Invoice";
  }
  if (invoiceDetailsRecipientEl) {
    invoiceDetailsRecipientEl.textContent = recipient;
  }
  applyInvoiceDetailsStatus(invoice);
  if (invoiceDetailsAmountEl) {
    const amountSat = getInvoiceAmountSat(invoice);
    const amountMsat =
      typeof invoice.amount_msat === "number" && Number.isFinite(invoice.amount_msat)
        ? invoice.amount_msat
        : null;
    if (typeof amountSat === "number" && Number.isFinite(amountSat)) {
      const formatted = formatSatAmount(amountSat);
      invoiceDetailsAmountEl.textContent = amountMsat
        ? `${formatted} (${amountMsat.toLocaleString()} msat)`
        : formatted;
    } else if (amountMsat !== null) {
      invoiceDetailsAmountEl.textContent = `${amountMsat.toLocaleString()} msat`;
    } else {
      invoiceDetailsAmountEl.textContent = "—";
    }
  }
  setInvoiceDetailsTimestamp(invoiceDetailsCreatedEl, invoice.created_at);
  setInvoiceDetailsTimestamp(invoiceDetailsNextCheckEl, invoice.next_check_at);
  setInvoiceDetailsTimestamp(invoiceDetailsLastCheckedEl, invoice.last_checked_at);
  if (invoiceDetailsSettledAtEl) {
    const fallback = invoice.settled ? "Unknown" : "—";
    setInvoiceDetailsTimestamp(invoiceDetailsSettledAtEl, invoice.settled_at, fallback);
  }
  if (invoiceDetailsExpiresEl) {
    if (invoice.settled) {
      invoiceDetailsExpiresEl.textContent = "Settled";
      invoiceDetailsExpiresEl.removeAttribute("title");
    } else if (invoice.expired) {
      if (invoice.expires_at) {
        setInvoiceDetailsTimestamp(invoiceDetailsExpiresEl, invoice.expires_at, "Expired");
        const current = invoiceDetailsExpiresEl.textContent || "";
        if (!current.toLowerCase().includes("expired")) {
          invoiceDetailsExpiresEl.textContent = `${current} (expired)`;
        }
      } else {
        invoiceDetailsExpiresEl.textContent = "Expired";
        invoiceDetailsExpiresEl.removeAttribute("title");
      }
    } else {
      setInvoiceDetailsTimestamp(invoiceDetailsExpiresEl, invoice.expires_at);
    }
  }
  if (invoiceDetailsHashEl) {
    const hash = typeof invoice.payment_hash === "string" ? invoice.payment_hash.trim() : "";
    invoiceDetailsHashEl.textContent = hash || "—";
    if (hash) {
      invoiceDetailsHashEl.title = hash;
    } else {
      invoiceDetailsHashEl.removeAttribute("title");
    }
  }
  if (invoiceDetailsRequestEl) {
    const request =
      typeof invoice.payment_request === "string" ? invoice.payment_request.trim() : "";
    invoiceDetailsRequestEl.textContent = request || "—";
    if (request) {
      invoiceDetailsRequestEl.title = request;
    } else {
      invoiceDetailsRequestEl.removeAttribute("title");
    }
  }
}

function openInvoiceDetails(invoice) {
  if (!invoiceDetailsModal) {
    return;
  }
  populateInvoiceDetails(invoice);
  invoiceDetailsModal.classList.remove("hidden");
  invoiceDetailsModal.classList.add("visible");
  updateBodyModalState();
}

function closeInvoiceDetails() {
  if (!invoiceDetailsModal) {
    return;
  }
  invoiceDetailsModal.classList.add("hidden");
  invoiceDetailsModal.classList.remove("visible");
  updateBodyModalState();
}

function renderInvoices(items, emptyMessage = "No invoices yet.") {
  if (!invoiceTableBody) return;
  const rows = Array.isArray(items) ? items : [];
  invoiceTableBody.innerHTML = "";

  if (!rows.length) {
    const row = document.createElement("tr");
    const cell = document.createElement("td");
    cell.colSpan = INVOICE_COLUMN_COUNT || 1;
    cell.className = "placeholder";
    cell.textContent = emptyMessage;
    row.appendChild(cell);
    invoiceTableBody.appendChild(row);
    return;
  }

  for (const invoice of rows) {
    const row = document.createElement("tr");
    const amountSat = getInvoiceAmountSat(invoice);
    const amountText =
      typeof amountSat === "number" && Number.isFinite(amountSat)
        ? formatSatAmount(amountSat)
        : "—";
    const cells = [
      createTimestampCell(invoice.created_at),
      createRecipientCell(invoice),
      createInvoiceAmountCell(invoice, amountText),
      createHashCell(invoice.payment_hash),
      createInvoiceDetailsCell(invoice),
    ];
    cells.forEach((cell, index) => {
      applyStackableLabel(cell, INVOICE_COLUMN_LABELS[index]);
      row.appendChild(cell);
    });
    invoiceTableBody.appendChild(row);
  }
}

function updateInvoicePagination(meta) {
  if (!invoicePageIndicator) return;
  const totalItems = Math.max(0, meta?.total_items ?? 0);
  const totalPages = Math.max(0, meta?.total_pages ?? 0);
  const currentPage = totalPages > 0 ? Math.max(1, meta?.page ?? 1) : 1;
  invoiceTotalItems = totalItems;
  invoiceTotalPages = totalPages;
  invoicePage = totalPages > 0 ? currentPage : 1;

  let summary;
  if (totalItems === 0) {
    summary = invoiceQuery ? "No matches" : "No invoices yet";
  } else if (totalPages <= 1) {
    summary = `${totalItems} invoice${totalItems === 1 ? "" : "s"}`;
  } else {
    summary = `Page ${invoicePage} of ${totalPages} • ${totalItems} invoices`;
  }

  invoicePageIndicator.textContent = summary;
  if (invoicePrevBtn) {
    invoicePrevBtn.disabled = totalPages === 0 || invoicePage <= 1;
  }
  if (invoiceNextBtn) {
    invoiceNextBtn.disabled = totalPages === 0 || invoicePage >= totalPages;
  }
}

function renderLiquidityPlaceholder(message) {
  if (!liquidityTableBody) return;
  liquidityTableBody.innerHTML = "";
  const row = document.createElement("tr");
  const cell = document.createElement("td");
  cell.colSpan = LIQUIDITY_COLUMN_COUNT;
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
      const sendable = getSendableBalance(channel);
      const receivable = getReceivableBalance(channel);
      const cells = [
        createPeerCell(channel),
        createLiquidityStatusCell(channel),
        createCapacityCell(channel),
        createCell(formatSatAmount(sendable ?? channel.local_balance_sat)),
        createCell(formatSatAmount(receivable ?? channel.remote_balance_sat)),
      ];
      cells.forEach((cell, index) => {
        applyStackableLabel(cell, LIQUIDITY_COLUMN_LABELS[index]);
        row.appendChild(cell);
      });
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

function applyStackableLabel(cell, label) {
  if (!(cell instanceof HTMLElement)) {
    return;
  }
  if (typeof label === "string" && label.trim()) {
    cell.dataset.label = label.trim();
  }
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

async function refreshInvoices() {
  if (!invoiceTableBody) {
    return;
  }
  const requestToken = ++invoicesFetchToken;
  if (invoicePageIndicator) {
    invoicePageIndicator.textContent = invoiceQuery ? "Searching…" : "Loading…";
  }
  try {
    const params = new URLSearchParams({
      page: String(invoicePage),
      page_size: String(INVOICE_PAGE_SIZE),
    });
    if (invoiceQuery) {
      params.set("q", invoiceQuery);
    }
    const response = await fetch(buildApiUrl(`api/invoices?${params.toString()}`));
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }
    const payload = await response.json();
    if (requestToken !== invoicesFetchToken) {
      return;
    }
    const items = Array.isArray(payload.items) ? payload.items : [];
    const emptyMessage = invoiceQuery ? "No invoices match your search." : "No invoices yet.";
    renderInvoices(items, emptyMessage);
    updateInvoicePagination(payload);
  } catch (error) {
    console.error("Failed to load invoices", error);
    if (requestToken !== invoicesFetchToken) {
      return;
    }
    renderInvoices([], "Unable to load invoices.");
    updateInvoicePagination({ page: 1, total_pages: 0, total_items: 0 });
    if (invoicePageIndicator) {
      invoicePageIndicator.textContent = "Unable to load invoices";
    }
  }
}

function startPolling() {
  updateStatus();
  const shouldPollLogs = Boolean(logBody);
  const shouldPollMetrics = Boolean(
    metricDomainsValue ||
    metricRequestsValue ||
    metricInvoicesTotalValue ||
    metricInvoicesPaidValue ||
    metricInvoicesPaid24Value ||
    metricSatsTotalValue ||
    metricSats7dValue,
  );
  const shouldFetchLiquidity = Boolean(liquidityTableBody || liquidityMaxValueEl || liquidityTotalEl);
  const shouldPollInvoices = Boolean(invoiceTableBody);
  if (shouldPollLogs) {
    refreshLogs();
  }
  if (shouldPollInvoices) {
    refreshInvoices();
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
  if (shouldPollInvoices) {
    setInterval(refreshInvoices, POLL_INTERVAL_MS);
  }
  if (shouldPollMetrics) {
    setInterval(fetchDashboardMetrics, POLL_INTERVAL_MS);
  }
  if (shouldFetchLiquidity) {
    setInterval(fetchLiquidity, POLL_INTERVAL_MS);
  }
  setInterval(fetchMacaroonStatus, POLL_INTERVAL_MS);
}

async function populateFooterCopy() {
  if (!footerCopyEls.length) return;
  const currentYear = new Date().getFullYear();
  let version = "0.0.0";
  try {
    const response = await fetch(buildApiUrl("api/version"));
    if (response.ok) {
      const data = await response.json();
      if (data && typeof data.version === "string" && data.version.trim()) {
        version = data.version.trim();
      }
    }
  } catch (error) {
    console.warn("Failed to load version info", error);
  }
  const footerHtml = `© ${currentYear} <a href="https://github.com/RyleaStark" target="_blank" rel="noopener noreferrer">Rylea Stark</a> · <a href="https://github.com/RyleaStark/lnSwitchboard" target="_blank" rel="noopener noreferrer">lnSwitchboard v${version}</a> · Tip sats ❤️ <a href="lnurlp://lnswitchboard+tips@bigbones.net">lnswitchboard+tips@bigbones.net</a>`;
  footerCopyEls.forEach((el) => {
    el.innerHTML = footerHtml;
  });
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

function handleInvoicesSearchInput(event) {
  const target = event.target;
  if (!(target instanceof HTMLInputElement)) {
    return;
  }
  if (invoiceSearchDebounceId) {
    window.clearTimeout(invoiceSearchDebounceId);
  }
  invoiceSearchDebounceId = window.setTimeout(() => {
    const normalized = target.value.trim();
    if (normalized === invoiceQuery) {
      return;
    }
    invoiceQuery = normalized;
    invoicePage = 1;
    refreshInvoices();
  }, 250);
}

document.addEventListener("DOMContentLoaded", () => {
  populateFooterCopy();
  refreshMacaroonUI();
  refreshLnurlInstructions();
  refreshSidebarNav();
  setupTooltips();
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
  if (addressTableBody) {
    fetchAddresses();
    fetchIdentityItems()
      .then(() => {
        renderAddressTable();
      })
      .catch((error) => {
        console.error("Failed to fetch identity data for LN Addresses", error);
      });
  }
  if (addressNewBtn) {
    addressNewBtn.addEventListener("click", openAddressCreateForm);
  }
  if (addressSearchInput) {
    addressSearchInput.addEventListener("input", handleAddressSearchInput);
  }
  if (addressForm) {
    addressForm.addEventListener("submit", submitAddressForm);
  }
  if (addressFormCancel) {
    addressFormCancel.addEventListener("click", () => setAddressFormVisible(false));
  }
  if (addressModalCloseBtn) {
    addressModalCloseBtn.addEventListener("click", () => setAddressFormVisible(false));
  }
  if (addressModal) {
    addressModal.addEventListener("click", (event) => {
      if (event.target instanceof HTMLElement && event.target.dataset.close === "address-modal") {
        setAddressFormVisible(false);
      }
    });
  }
  if (addressDeleteCancelBtn) {
    addressDeleteCancelBtn.addEventListener("click", () => setAddressDeleteVisible(false));
  }
  if (addressDeleteCloseBtn) {
    addressDeleteCloseBtn.addEventListener("click", () => setAddressDeleteVisible(false));
  }
  if (addressDeleteModal) {
    addressDeleteModal.addEventListener("click", (event) => {
      if (event.target instanceof HTMLElement && event.target.dataset.close === "address-delete") {
        setAddressDeleteVisible(false);
      }
    });
  }
  if (addressDeleteConfirmBtn) {
    addressDeleteConfirmBtn.addEventListener("click", confirmAddressDelete);
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
  if (invoiceDetailsCloseBtn) {
    invoiceDetailsCloseBtn.addEventListener("click", closeInvoiceDetails);
  }
  if (invoiceDetailsModal) {
    invoiceDetailsModal.addEventListener("click", (event) => {
      if (event.target instanceof HTMLElement && event.target.dataset.close === "invoice-details") {
        closeInvoiceDetails();
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
    if (addressDeleteModal?.classList.contains("visible")) {
      setAddressDeleteVisible(false);
      return;
    }
    if (addressModal?.classList.contains("visible")) {
      setAddressFormVisible(false);
      return;
    }
    if (invoiceDetailsModal?.classList.contains("visible")) {
      closeInvoiceDetails();
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

  if (invoiceSearchInput) {
    invoiceSearchInput.addEventListener("input", handleInvoicesSearchInput);
  }
  if (invoicePrevBtn) {
    invoicePrevBtn.addEventListener("click", () => {
      if (invoicePage <= 1) {
        return;
      }
      invoicePage -= 1;
      refreshInvoices();
    });
    invoicePrevBtn.disabled = true;
  }
  if (invoiceNextBtn) {
    invoiceNextBtn.addEventListener("click", () => {
      if (invoiceTotalPages === 0 || invoicePage >= invoiceTotalPages) {
        return;
      }
      invoicePage += 1;
      refreshInvoices();
    });
    invoiceNextBtn.disabled = true;
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
