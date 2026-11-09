// HadesGate™ Browser Shield — Popup Controller (PT-BR default + EN, Dark default + Light)

const I18N = {
  "pt-BR": {
    subtitle: ">>> ESCUDO ZERO-PII PARA CHATS DE IA",
    kpiStatus: "STATUS GATEWAY",
    kpiMasked: "ASSEGURADOS (RAM)",
    statusOnline: "ONLINE // PROTEGIDO",
    statusKeyReq: "CHAVE NECESSÁRIA",
    statusInvalidKey: "CHAVE INVÁLIDA",
    statusOffline: "OFFLINE",
    statusChecking: "VERIFICANDO...",
    tabShield: "01 // ESCUDO & CONEXÃO",
    tabSandbox: "02 // SANDBOX RÁPIDO",
    gatewayLabel: "01 // ENDPOINT DO HADESGATE",
    apiKeyLabel: "02 // CHAVE DE ACESSO",
    saveVerifyBtn: "SALVAR & VALIDAR CONEXÃO",
    tacticalRules: "DIRETRIZES DE INTERCEPTAÇÃO NOS CHATS",
    swEnabledTitle: "ESCUDO ATIVO NOS CHATS DE IA",
    swEnabledDesc: "ChatGPT, Claude, Gemini, DeepSeek, Perplexity, Grok & Copilot",
    swPasteTitle: "INTERCEPTAR COLAGEM (CTRL+V)",
    swPasteDesc: "Mascara CPF, PIX, senhas e chaves automaticamente ao colar",
    swRestoreTitle: "AUTO-RESTAURAR RESPOSTAS NA TELA",
    swRestoreDesc: "Substitui tokens [HG_...] pelos dados reais no DOM da conversa",
    swFailClosedTitle: "BLOQUEAR SE O GATEWAY FALHAR",
    swFailClosedDesc: "Não deixa enviar texto cru quando o gateway está fora ou recusa",
    swDirectiveTitle: "DIRETIVA ANTI-RECUSA IA",
    swDirectiveDesc: "Instrui a IA web a tratar tokens como dados reais preenchidos",
    sbInputLabel: "TEXTO BRUTO // ÁREA DE TRANSFERÊNCIA",
    sbMaskCopyBtn: "MASCARAR & COPIAR",
    sbRestoreBtn: "RESTAURAR TOKENS",
    sbOutputLabel: "PAYLOAD SANITIZADO",
    openConsole: "ABRIR CONSOLE WEB >>>",
    purgeRam: "LIMPAR RAM",
    showKey: "VER",
    hideKey: "OCULTAR",
    themeDark: "ESCURO",
    themeLight: "CLARO",
    connSuccess: "[ OK ] CONECTADO AO HADESGATE // ESCUDO ATIVO",
    connInvalid: "[ ERRO ] CREDENCIAIS INVÁLIDAS PARA ESTE GATEWAY",
    connOffline: "[ ERRO ] FALHA DE CONEXÃO COM O ENDPOINT",
    copiedMsg: "[ COPIADO PARA A ÁREA DE TRANSFERÊNCIA ]",
  },
  en: {
    subtitle: ">>> ZERO-PII SHIELD FOR WEB AI CHATS",
    kpiStatus: "GATEWAY STATUS",
    kpiMasked: "SECURED (RAM)",
    statusOnline: "ONLINE // SECURED",
    statusKeyReq: "KEY REQUIRED",
    statusInvalidKey: "INVALID KEY",
    statusOffline: "OFFLINE",
    statusChecking: "CHECKING...",
    tabShield: "01 // SHIELD & CONNECTION",
    tabSandbox: "02 // QUICK SANDBOX",
    gatewayLabel: "01 // HADESGATE ENDPOINT",
    apiKeyLabel: "02 // ACCESS KEY",
    saveVerifyBtn: "SAVE & VERIFY CONNECTION",
    tacticalRules: "WEB CHAT INTERCEPTION DIRECTIVES",
    swEnabledTitle: "ACTIVE SHIELD ON AI CHATS",
    swEnabledDesc: "ChatGPT, Claude, Gemini, DeepSeek, Perplexity, Grok & Copilot",
    swPasteTitle: "INTERCEPT PASTE (CTRL+V)",
    swPasteDesc: "Automatically masks CPF, PIX, passwords and keys on paste",
    swRestoreTitle: "AUTO-RESTORE DOM RESPONSES",
    swRestoreDesc: "Replaces [HG_...] tokens with original values in chat replies",
    swFailClosedTitle: "BLOCK WHEN THE GATEWAY FAILS",
    swFailClosedDesc: "Do not send raw text when the gateway is down or refuses",
    swDirectiveTitle: "AI ANTI-REFUSAL DIRECTIVE",
    swDirectiveDesc: "Instructs web LLMs to treat tokens as valid filled values",
    sbInputLabel: "RAW TEXT // CLIPBOARD SANDBOX",
    sbMaskCopyBtn: "MASK & COPY",
    sbRestoreBtn: "RESTORE TOKENS",
    sbOutputLabel: "SANITIZED PAYLOAD",
    openConsole: "OPEN WEB CONSOLE >>>",
    purgeRam: "PURGE RAM",
    showKey: "SHOW",
    hideKey: "HIDE",
    themeDark: "DARK",
    themeLight: "LIGHT",
    connSuccess: "[ OK ] CONNECTED TO HADESGATE // SHIELD ACTIVE",
    connInvalid: "[ ERR ] INVALID CREDENTIALS FOR THIS GATEWAY",
    connOffline: "[ ERR ] CONNECTION FAILED — CHECK ENDPOINT URL",
    copiedMsg: "[ COPIED TO CLIPBOARD ]",
  },
};

let currentLang = "pt-BR";
let currentTheme = "dark";
let showApiKey = false;

const el = (id) => document.getElementById(id);

function applyI18n() {
  const dict = I18N[currentLang] || I18N["pt-BR"];
  document.querySelectorAll("[data-i18n]").forEach((node) => {
    const key = node.getAttribute("data-i18n");
    if (dict[key]) {
      node.textContent = dict[key];
    }
  });
  el("langBtn").textContent = currentLang === "pt-BR" ? "PT-BR" : "EN";
  el("themeBtn").textContent =
    currentTheme === "dark" ? dict.themeDark : dict.themeLight;
  el("toggleKeyBtn").textContent = showApiKey ? dict.hideKey : dict.showKey;
}

function applyTheme() {
  document.documentElement.setAttribute("data-theme", currentTheme);
  applyI18n();
}

function setStatusUI(state, maskedCount) {
  const dict = I18N[currentLang] || I18N["pt-BR"];
  const dot = el("statusDot");
  const text = el("statusText");
  dot.className = "status-dot";

  if (typeof maskedCount === "number") {
    el("maskedCountVal").textContent = String(maskedCount);
  }

  if (state === "online") {
    dot.classList.add("online");
    text.textContent = dict.statusOnline;
  } else if (state === "invalid_key") {
    dot.classList.add("offline");
    text.textContent = dict.statusInvalidKey;
  } else if (state === "key_required") {
    dot.classList.add("offline");
    text.textContent = dict.statusKeyReq;
  } else {
    dot.classList.add("offline");
    text.textContent = dict.statusOffline;
  }
}

function showFeedback(message, isOk) {
  const bar = el("connFeedback");
  bar.textContent = message;
  bar.className = `feedback-bar ${isOk ? "ok" : "err"}`;
}

async function verifyConnection(showBanner = false) {
  const dict = I18N[currentLang] || I18N["pt-BR"];
  const gatewayUrl = el("gatewayUrl").value.trim() || "http://localhost:8080";
  const apiKey = el("apiKey").value.trim();

  el("statusText").textContent = dict.statusChecking;

  chrome.runtime.sendMessage(
    { type: "HADESGATE_VERIFY", gatewayUrl, apiKey },
    (res) => {
      if (chrome.runtime.lastError || !res) {
        setStatusUI("offline");
        if (showBanner) showFeedback(dict.connOffline, false);
        return;
      }

      if (res.ok && res.authenticated) {
        setStatusUI("online", res.maskedCount ?? 0);
        if (showBanner) showFeedback(dict.connSuccess, true);
      } else if (res.online && res.error === "INVALID_KEY") {
        setStatusUI("invalid_key");
        if (showBanner) showFeedback(dict.connInvalid, false);
      } else if (res.online && res.error === "KEY_REQUIRED") {
        setStatusUI("key_required");
        if (showBanner) showFeedback(dict.connInvalid, false);
      } else {
        setStatusUI("offline");
        if (showBanner) showFeedback(dict.connOffline, false);
      }
    }
  );
}

function saveSettings() {
  const gatewayUrl =
    (el("gatewayUrl").value || "http://localhost:8080").trim().replace(/\/+$/, "");
  const apiKey = (el("apiKey").value || "").trim();

  chrome.storage.local.set({
    gatewayUrl,
    apiKey,
    enabled: el("swEnabled").checked,
    interceptPaste: el("swPaste").checked,
    autoRestore: el("swRestore").checked,
    failClosed: el("swFailClosed").checked,
    injectDirective: el("swDirective").checked,
    lang: currentLang,
    theme: currentTheme,
  });
}

document.addEventListener("DOMContentLoaded", () => {
  chrome.storage.local.get(
    {
      gatewayUrl: "http://localhost:8080",
      apiKey: "",
      enabled: true,
      interceptPaste: true,
      autoRestore: true,
      failClosed: true,
      injectDirective: true,
      lang: "pt-BR",
      theme: "dark",
    },
    (items) => {
      el("gatewayUrl").value = items.gatewayUrl || "http://localhost:8080";
      el("apiKey").value = items.apiKey || "";
      el("swEnabled").checked = Boolean(items.enabled);
      el("swPaste").checked = Boolean(items.interceptPaste);
      el("swRestore").checked = Boolean(items.autoRestore);
      el("swFailClosed").checked = Boolean(items.failClosed);
      el("swDirective").checked = Boolean(items.injectDirective);
      currentLang = items.lang || "pt-BR";
      currentTheme = items.theme || "dark";
      applyTheme();
      verifyConnection(false);
    }
  );

  // Tabs
  document.querySelectorAll(".tab-btn").forEach((btn) => {
    btn.addEventListener("click", () => {
      document.querySelectorAll(".tab-btn").forEach((b) => b.classList.remove("active"));
      document.querySelectorAll(".tab-panel").forEach((p) => p.classList.remove("active"));
      btn.classList.add("active");
      const target = btn.getAttribute("data-tab");
      el(`tab-${target}`).classList.add("active");
    });
  });

  // Language & Theme
  el("langBtn").addEventListener("click", () => {
    currentLang = currentLang === "pt-BR" ? "en" : "pt-BR";
    applyI18n();
    saveSettings();
  });

  el("themeBtn").addEventListener("click", () => {
    currentTheme = currentTheme === "dark" ? "light" : "dark";
    applyTheme();
    saveSettings();
  });

  // Show/Hide API Key
  el("toggleKeyBtn").addEventListener("click", () => {
    showApiKey = !showApiKey;
    el("apiKey").type = showApiKey ? "text" : "password";
    applyI18n();
  });

  // Save & Verify
  el("saveVerifyBtn").addEventListener("click", () => {
    saveSettings();
    verifyConnection(true);
  });

  // Switches
  ["swEnabled", "swPaste", "swRestore", "swFailClosed", "swDirective"].forEach((id) => {
    el(id).addEventListener("change", saveSettings);
  });

  // Sandbox Mask & Copy
  el("sbMaskCopyBtn").addEventListener("click", () => {
    const prompt = el("sbInput").value;
    if (!prompt.trim()) return;

    chrome.runtime.sendMessage(
      {
        type: "HADESGATE_ANONYMIZE",
        prompt,
        provider: "extension",
        model: "popup-sandbox",
        recordTrace: true,
      },
      async (res) => {
        if (!res || !res.ok) {
          el("sbOutput").textContent = `[ ERRO: ${res?.error || "OFFLINE"} ]`;
          return;
        }
        el("sbLatency").textContent = `${res.latencyMicros} µS`;
        el("sbOutput").textContent = res.sanitized;
        el("maskedCountVal").textContent = String(res.sessionMaskedCount || 0);

        const tagsContainer = el("sbTags");
        tagsContainer.innerHTML = "";
        (res.entities || []).forEach((ent) => {
          const span = document.createElement("span");
          span.className = "entity-tag";
          span.textContent = ent.sub_type || ent.type;
          tagsContainer.appendChild(span);
        });

        try {
          await navigator.clipboard.writeText(res.sanitized);
          const dict = I18N[currentLang] || I18N["pt-BR"];
          el("sbOutput").textContent = `${res.sanitized}\n\n${dict.copiedMsg}`;
        } catch (_) {
          // Clipboard write optional
        }
      }
    );
  });

  // Sandbox Restore Tokens
  el("sbRestoreBtn").addEventListener("click", () => {
    const raw = el("sbInput").value;
    if (!raw.trim()) return;

    chrome.runtime.sendMessage({ type: "HADESGATE_GET_SESSION_MAP" }, (res) => {
      if (!res || !res.ok) return;
      let restored = raw;
      for (const [token, orig] of Object.entries(res.tokenMap || {})) {
        restored = restored.split(token).join(orig);
      }
      el("sbOutput").textContent = restored;
    });
  });

  // Footer Actions
  el("openDashboardBtn").addEventListener("click", () => {
    const gatewayUrl = el("gatewayUrl").value.trim() || "http://localhost:8080";
    chrome.tabs.create({ url: gatewayUrl });
  });

  el("purgeRamBtn").addEventListener("click", () => {
    chrome.runtime.sendMessage({ type: "HADESGATE_PURGE_SESSION_MAP" }, () => {
      el("maskedCountVal").textContent = "0";
      el("sbOutput").textContent = "[ RAM VAULT PURGED ]";
      el("sbTags").innerHTML = "";
    });
  });
});

