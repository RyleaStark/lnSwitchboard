const statusElement = document.getElementById("service-status");
const logBody = document.getElementById("log-body");
const POLL_INTERVAL_MS = 10000;
const macaroonStatusEl = document.getElementById("macaroon-status");
const macaroonForm = document.getElementById("macaroon-form");
const macaroonInput = document.getElementById("macaroon-input");
const macaroonFeedback = document.getElementById("macaroon-feedback");
const macaroonFormWrapper = document.getElementById("macaroon-form-wrapper");
const macaroonRevealBtn = document.getElementById("macaroon-reveal");
const clearLogsBtn = document.getElementById("logs-clear");
const lnurlToggleBtn = document.getElementById("lnurl-toggle");
const lnurlInstructions = document.getElementById("lnurl-instructions");
const copyrightYearEl = document.getElementById("copyright-year");
const detailsModal = document.getElementById("details-modal");
const detailsJsonEl = document.getElementById("details-json");
const detailsCloseBtn = document.getElementById("details-close");
const logsSearchInput = document.getElementById("logs-search");
const logsPrevBtn = document.getElementById("logs-prev");
const logsNextBtn = document.getElementById("logs-next");
const logsPageIndicator = document.getElementById("logs-page-indicator");
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
    cell.colSpan = 10;
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
    row.appendChild(createCell(entry.ip));
    row.appendChild(createCell(entry.status));
    row.appendChild(createCell(entry.event));
    row.appendChild(createCell(entry.message || "—", "message-cell"));
    row.appendChild(createDetailsCell(entry));
    logBody.appendChild(row);
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
  refreshLogs();
  fetchMacaroonStatus();
  setInterval(updateStatus, POLL_INTERVAL_MS);
  setInterval(refreshLogs, POLL_INTERVAL_MS);
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
  document.body.classList.add("modal-open");
}

function closeDetails() {
  if (!detailsModal) return;
  activeDetailsEntry = null;
  detailsModal.classList.remove("visible");
  detailsModal.classList.add("hidden");
  document.body.classList.remove("modal-open");
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
  if (clearLogsBtn) {
    clearLogsBtn.addEventListener("click", handleClearLogs);
  }
  if (lnurlToggleBtn) {
    lnurlToggleBtn.addEventListener("click", () => {
      lnurlDetailsOpen = !lnurlDetailsOpen;
      refreshLnurlInstructions();
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
    if (event.key === "Escape" && detailsModal?.classList.contains("visible")) {
      closeDetails();
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
  startPolling();
});

function setMacaroonStatus(configured) {
  if (!macaroonStatusEl) return;
  macaroonConfigured = configured;
  macaroonStatusEl.textContent = configured ? "Configured" : "Not configured";
  macaroonStatusEl.classList.toggle("badge-ok", configured);
  macaroonStatusEl.classList.toggle("badge-warn", !configured);
  if (!configured) {
    macaroonFormManuallyOpen = false;
  }
  refreshMacaroonUI();
}

async function fetchMacaroonStatus() {
  if (!macaroonStatusEl) return;
  try {
    const response = await fetch(buildApiUrl("api/auth/status"));
    if (!response.ok) throw new Error("status error");
    const data = await response.json();
    setMacaroonStatus(Boolean(data.configured));
  } catch (error) {
    setMacaroonStatus(false);
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
}

function refreshLnurlInstructions() {
  if (!lnurlInstructions || !lnurlToggleBtn) return;
  lnurlInstructions.classList.toggle("collapsed", !lnurlDetailsOpen);
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
  if (!window.confirm("Clear all LNURL request logs? This cannot be undone.")) {
    return;
  }
  const defaultLabel = "Clear logs";
  clearLogsBtn.disabled = true;
  clearLogsBtn.textContent = "Clearing…";
  try {
    const response = await fetch(buildApiUrl("api/logs/recent"), { method: "DELETE" });
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }
    logPage = 1;
    await refreshLogs();
    clearLogsBtn.textContent = "Cleared";
  } catch (error) {
    clearLogsBtn.textContent = "Failed, retry?";
  } finally {
    setTimeout(() => {
      if (!clearLogsBtn) {
        return;
      }
      clearLogsBtn.disabled = false;
      clearLogsBtn.textContent = defaultLabel;
    }, 1500);
  }
}
