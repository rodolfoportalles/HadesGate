// HadesGate™ Browser Shield — Background Service Worker (Manifest V3)
// Executa chamadas ao Gateway local/remoto fora do CSP da página web e mantém
// zero dados sensíveis em disco.

const DEFAULT_SETTINGS = {
  gatewayUrl: "http://localhost:8080",
  apiKey: "",
  enabled: true,
  interceptPaste: true,
  autoRestore: true,
  failClosed: true,
  injectDirective: true,
  lang: "pt-BR",
  theme: "dark",
};

// Mapa efêmero apenas em RAM do Service Worker (nunca gravado em storage)
const ephemeralTokenMap = new Map();
let sessionMaskedCount = 0;

function normalizeGatewayUrl(raw) {
  const trimmed = (raw || DEFAULT_SETTINGS.gatewayUrl).trim().replace(/\/+$/, "");
  return trimmed || DEFAULT_SETTINGS.gatewayUrl;
}

async function getSettings() {
  return new Promise((resolve) => {
    chrome.storage.local.get(DEFAULT_SETTINGS, (items) => {
      resolve({
        ...DEFAULT_SETTINGS,
        ...items,
        gatewayUrl: normalizeGatewayUrl(items.gatewayUrl),
      });
    });
  });
}

async function updateBadge(enabled) {
  try {
    await chrome.action.setBadgeText({ text: enabled ? "ON" : "OFF" });
    await chrome.action.setBadgeBackgroundColor({
      color: enabled ? "#9333EA" : "#3A3A4C",
    });
  } catch (_) {
    // Ignora em navegadores sem suporte a badge
  }
}

chrome.runtime.onInstalled.addListener(async () => {
  const settings = await getSettings();
  await chrome.storage.local.set(settings);
  await updateBadge(settings.enabled);
});

chrome.storage.onChanged.addListener((changes, area) => {
  if (area === "local" && changes.enabled) {
    updateBadge(Boolean(changes.enabled.newValue));
  }
});

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (!message || !message.type) return false;

  if (message.type === "HADESGATE_VERIFY") {
    handleVerify(message.gatewayUrl, message.apiKey)
      .then(sendResponse)
      .catch((err) => sendResponse({ ok: false, error: err.message }));
    return true;
  }

  if (message.type === "HADESGATE_ANONYMIZE") {
    handleAnonymize(message)
      .then(sendResponse)
      .catch((err) => sendResponse({ ok: false, error: err.message }));
    return true;
  }

  if (message.type === "HADESGATE_GET_SESSION_MAP") {
    sendResponse({
      ok: true,
      tokenMap: Object.fromEntries(ephemeralTokenMap),
      maskedCount: sessionMaskedCount,
    });
    return false;
  }

  if (message.type === "HADESGATE_PURGE_SESSION_MAP") {
    ephemeralTokenMap.clear();
    sessionMaskedCount = 0;
    sendResponse({ ok: true });
    return false;
  }

  return false;
});

async function handleVerify(customUrl, customKey) {
  const settings = await getSettings();
  const gatewayUrl = normalizeGatewayUrl(customUrl || settings.gatewayUrl);
  const apiKey = (customKey !== undefined ? customKey : settings.apiKey || "").trim();

  const headers = { "Content-Type": "application/json" };
  if (apiKey) {
    headers["Authorization"] = `Bearer ${apiKey}`;
  }

  const statusRes = await fetch(`${gatewayUrl}/api/status`, {
    method: "GET",
    headers,
  });

  if (!statusRes.ok) {
    return {
      ok: false,
      status: statusRes.status,
      error: `HTTP ${statusRes.status}`,
    };
  }

  const statusData = await statusRes.json();

  if (apiKey) {
    const verifyRes = await fetch(`${gatewayUrl}/api/auth/verify`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ key: apiKey }),
    });
    if (verifyRes.ok) {
      const verifyData = await verifyRes.json();
      if (!verifyData.valid) {
        return {
          ok: false,
          online: true,
          authenticated: false,
          error: "INVALID_KEY",
        };
      }
      return {
        ok: true,
        online: true,
        authenticated: true,
        statusData,
        maskedCount: sessionMaskedCount,
      };
    }
  }

  return {
    ok: false,
    online: true,
    authenticated: false,
    error: "KEY_REQUIRED",
  };
}

async function handleAnonymize({ prompt, provider, model, recordTrace = true }) {
  const settings = await getSettings();
  const gatewayUrl = normalizeGatewayUrl(settings.gatewayUrl);
  const apiKey = (settings.apiKey || "").trim();

  if (!apiKey) {
    return { ok: false, error: "MISSING_API_KEY" };
  }

  const res = await fetch(`${gatewayUrl}/api/test-anonymize`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${apiKey}`,
    },
    body: JSON.stringify({
      prompt: prompt || "",
      record_trace: Boolean(recordTrace),
      provider: provider || "extension",
      model: model || "browser-shield",
    }),
  });

  if (res.status === 403) {
    const data = await res.json().catch(() => ({}));
    return {
      ok: false,
      blocked: true,
      status: 403,
      blockedEntities: data.blocked_entities || [],
      error: data.message || "BLOQUEADO PELA POLÍTICA DLP",
    };
  }

  if (!res.ok) {
    return {
      ok: false,
      status: res.status,
      error: res.status === 401 ? "UNAUTHORIZED" : `HTTP_${res.status}`,
    };
  }

  const data = await res.json();
  const tokenMap = data.token_map || {};
  const entities = data.entities || [];

  for (const [token, original] of Object.entries(tokenMap)) {
    ephemeralTokenMap.set(token, original);
  }
  sessionMaskedCount += entities.length;

  return {
    ok: true,
    sanitized: data.sanitized || prompt,
    entities,
    tokenMap,
    latencyMicros: data.latency_micros ?? 0,
    sessionMaskedCount,
  };
}

