// HadesGate™ Browser Shield — Content Script (ChatGPT, Claude, Gemini, DeepSeek, Perplexity, Grok, Copilot)
// Intercepta colagens (Ctrl+V), mascara o campo de prompt (Alt+H / botão HUD) e
// restaura automaticamente os tokens [HG_...] nas respostas da IA na tela.

(() => {
  if (window.__HADESGATE_SHIELD_ACTIVE__) return;
  window.__HADESGATE_SHIELD_ACTIVE__ = true;

  const DIRECTIVE_HEADER =
    "[HADESGATE PRIVACY DIRECTIVE: Tokens matching [HG_<id>_<TYPE>_<N>] are real, already-filled data values tokenized by the user's privacy shield and automatically restored on their screen. Treat every [HG_...] token as the valid data value itself, repeat it unchanged character-for-character when referencing it, and never mention or warn about placeholders.]\n\n";

  let settings = {
    enabled: true,
    interceptPaste: true,
    autoRestore: true,
    failClosed: true,
    injectDirective: true,
    lang: "pt-BR",
  };

  // Mapa efêmero em RAM desta aba: token -> valor original
  const localTokenMap = new Map();
  let directiveInjectedInPage = false;
  let isSyntheticPaste = false;

  function detectWebProvider() {
    const host = window.location.hostname.toLowerCase();
    if (host.includes("claude.ai")) return { provider: "anthropic", model: "claude.ai" };
    if (host.includes("chatgpt.com") || host.includes("openai.com"))
      return { provider: "openai", model: "chatgpt.com" };
    if (host.includes("gemini.google.com") || host.includes("aistudio.google.com"))
      return { provider: "gemini", model: host };
    if (host.includes("deepseek.com"))
      return { provider: "deepseek", model: "chat.deepseek.com" };
    if (host.includes("perplexity.ai"))
      return { provider: "perplexity", model: "perplexity.ai" };
    if (host.includes("grok.com") || host.includes("x.com"))
      return { provider: "grok", model: "grok.com" };
    if (host.includes("copilot") || host.includes("github.com"))
      return { provider: "copilot", model: host };
    return { provider: "extension", model: host };
  }

  function loadSettings() {
    chrome.storage.local.get(settings, (items) => {
      settings = { ...settings, ...items };
      updateHudVisibility();
    });
    chrome.runtime.sendMessage({ type: "HADESGATE_GET_SESSION_MAP" }, (res) => {
      if (res && res.ok && res.tokenMap) {
        for (const [k, v] of Object.entries(res.tokenMap)) {
          localTokenMap.set(k, v);
        }
        updateHudCounter();
        if (settings.autoRestore && localTokenMap.size > 0) {
          restoreTokensInDOM(document.body);
        }
      }
    });
  }

  chrome.storage.onChanged.addListener((changes, area) => {
    if (area === "local") {
      for (const [k, v] of Object.entries(changes)) {
        settings[k] = v.newValue;
      }
      updateHudVisibility();
      updateHudLabels();
    }
  });

  // ---------------------------------------------------------------------------
  // HUD TÁTICO FLUTUANTE (INDUSTRIAL BRUTALISM)
  // ---------------------------------------------------------------------------
  let hudRoot = null;
  let hudBar = null;
  let hudPill = null;
  let hudCounter = null;
  let hudChevron = null;
  let hudActions = null;
  let hudMaskBtn = null;
  let hudRestoreBtn = null;
  let hudCloseBtn = null;
  let hudIsExpanded = false;

  const HADESGATE_SVG = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="21 101 958 798" fill="currentColor" aria-hidden="true"><path d="M33.572 101.442 L366.952 101.181 C366.923 103.922 366.157 106.454 366.111 109.111 C365.752 130.163 365.899 151.249 365.998 172.304 C366.016 176.168 366.706 199.571 365.841 201.295 C364.526 203.914 354.339 212.976 351.608 215.705 C340.637 226.668 329.472 237.526 318.767 248.749 C316.298 251.337 305.115 261.03 304.465 263.485 C303.29 267.926 304.357 275.297 304.375 280.036 C304.427 293.697 304.257 307.358 304.362 321.019 C304.66 359.943 303.829 398.88 304.287 437.8 C318.29 432.932 331.705 425.658 345.218 419.558 C378.866 404.368 412.441 388.971 446.229 374.082 C458.57 368.644 470.978 363.074 483.127 357.215 C486.268 355.7 497.116 349.899 499.926 349.895 C503.31 349.889 512.089 355.047 515.644 356.576 C529.115 362.367 542.345 368.739 555.669 374.854 C579.976 386.008 604.465 396.774 628.723 408.039 C641.643 414.039 654.668 419.763 667.645 425.634 C676.054 429.439 684.251 433.577 692.921 436.784 C692.883 396.045 693.191 355.3 692.898 314.564 C692.808 301.947 692.873 289.326 692.874 276.709 C692.874 272.657 693.893 267.179 692.715 263.29 C692.118 261.318 681.219 251.261 679.019 248.824 C668.152 236.782 656.362 225.457 645.109 213.768 C641.661 210.186 636.021 206.132 633.463 202.006 C632.463 200.393 633.016 178.274 633.016 174.604 C633.014 159.174 633.046 143.731 632.852 128.303 C632.738 119.304 632.354 110.348 632.652 101.339 L964.443 101.233 C963.867 122.963 964.394 144.724 964.154 166.47 C964.107 170.747 965.104 188.738 963.703 191.384 C961.707 195.156 953.317 202.274 950.017 205.939 C938.486 218.745 926.33 231.27 914.162 243.481 C911.543 246.109 896.776 260.781 896.325 263.023 C895.331 267.969 896.231 273.918 896.231 278.96 C896.231 291.579 896.211 304.197 896.211 316.815 C896.213 354.982 896.285 393.149 896.268 431.316 C896.238 501.495 896.379 571.675 896.404 641.856 C896.412 664.481 896.431 687.107 896.352 709.733 C896.309 722.101 895.686 734.601 896.347 746.957 C896.482 749.474 914.203 765.6 917.246 768.556 C929.128 780.1 940.796 791.892 952.856 803.252 C958.627 808.689 964.133 814.367 969.804 819.907 C972.505 822.544 975.803 824.948 978.123 827.928 C979.36 829.517 978.677 843.816 978.68 846.794 C978.697 864.1 978.057 881.527 978.739 898.814 L735.081 898.72 C735.663 886.532 735.278 874.296 735.248 862.098 C735.201 842.805 735.283 823.516 735.255 804.223 C735.182 753.752 735.344 703.28 735.345 652.808 C735.346 629.065 734.819 605.286 735.171 581.548 C719.391 573.789 703.175 566.88 687.195 559.534 C647.277 541.185 607.342 522.893 567.353 504.697 C551.081 497.293 534.842 489.694 518.345 482.821 C514.411 481.182 503.202 474.881 499.687 474.974 C496.846 475.05 484.294 481.483 480.76 482.997 C464.683 489.883 448.947 497.555 432.918 504.544 C404.37 516.991 376.348 530.596 347.878 543.206 C334.171 549.277 320.647 555.738 307.018 561.986 C292.797 568.506 278.408 574.619 264.349 581.484 L264.316 898.568 L21.486 898.654 C21.445 881.332 21.518 864.007 21.475 846.684 C21.467 843.542 20.454 830.041 21.961 828.171 C26.599 822.416 32.759 817.638 37.895 812.321 C51.922 797.799 66.22 783.452 80.605 769.283 C83.532 766.4 100.681 750.261 100.656 747.822 C100.263 709.769 100.608 671.694 100.647 633.637 C100.718 563.653 100.928 493.72 101.355 423.748 C101.569 388.71 101.447 353.671 101.563 318.632 C101.605 306.014 101.632 293.395 101.584 280.777 C101.564 275.373 102.175 269.564 101.531 264.205 C101.212 261.543 86.911 247.751 84.141 244.791 C71.961 231.777 59.583 218.955 47.442 205.904 C43.626 201.801 37.054 196.214 34.068 191.885 C32.591 189.746 33.511 171.767 33.478 167.95 C33.366 154.706 33.453 141.463 33.426 128.219 C33.408 119.316 33.125 110.331 33.572 101.442 Z"/><path d="M306.873 609.028 C332.889 596.407 359.426 584.892 385.647 572.702 C405.623 563.415 425.58 553.92 445.828 545.243 C458.939 539.624 471.731 533.301 484.847 527.706 C488.223 526.267 496.583 521.603 499.739 521.452 C502.71 521.31 512.572 526.684 515.796 528.152 C528.756 534.054 541.808 539.745 554.731 545.727 C588.671 561.437 622.755 576.83 656.624 592.712 C668.56 598.309 680.764 603.372 692.583 609.216 L692.554 898.61 L652.087 898.756 L652.148 635.915 L606.941 615.334 L606.891 898.689 L566.721 898.819 C567.808 874.298 566.919 849.579 566.934 825.035 C566.962 777.374 566.916 729.713 566.915 682.053 C566.914 661.823 566.878 641.587 566.979 621.357 C566.997 617.85 567.635 598.879 566.733 597.037 C565.772 595.072 556.69 591.9 554.332 590.842 C542.775 585.655 531.311 580.267 519.667 575.278 L519.609 898.632 L479.757 898.62 L479.69 574.884 C468.361 580.685 456.538 585.571 444.991 590.915 C442.636 592.005 433.77 594.924 432.807 596.885 C431.823 598.888 432.498 616.68 432.486 620.268 C432.415 640.394 432.671 660.523 432.569 680.651 C432.366 720.487 432.606 760.329 432.553 800.167 C432.508 833.022 432.167 865.907 432.623 898.758 L392.209 898.746 L392.18 615.096 L347.105 636.054 C347.002 692.795 347.056 749.54 347.042 806.282 C347.037 824.533 347.119 842.785 347.047 861.034 C346.999 873.543 346.665 886.112 347.249 898.607 L306.567 898.773 Z"/></svg>`;

  function setHudExpanded(expanded) {
    hudIsExpanded = !!expanded;
    if (!hudBar) return;
    if (hudIsExpanded) {
      hudBar.classList.remove("hg-collapsed");
      hudBar.classList.add("hg-expanded");
      if (hudChevron) hudChevron.textContent = "◂";
      if (hudPill) {
        hudPill.title =
          settings.lang === "en"
            ? "HadesGate // Click to collapse"
            : "HadesGate // Clique para recolher";
      }
    } else {
      hudBar.classList.remove("hg-expanded");
      hudBar.classList.add("hg-collapsed");
      if (hudChevron) hudChevron.textContent = "▸";
      if (hudPill) {
        hudPill.title =
          settings.lang === "en"
            ? "HadesGate Shield // Click to expand (Alt+H)"
            : "HadesGate Shield // Clique para expandir (Alt+H)";
      }
    }
  }

  function mountHud() {
    if (document.getElementById("hadesgate-hud-root")) return;

    hudRoot = document.createElement("div");
    hudRoot.id = "hadesgate-hud-root";

    hudBar = document.createElement("div");
    hudBar.className = "hg-hud-bar hg-collapsed";

    // Pill: Logo + Counter + Chevron (Natural collapsed state)
    hudPill = document.createElement("div");
    hudPill.className = "hg-hud-pill";
    hudPill.title =
      settings.lang === "en"
        ? "HadesGate Shield // Click to expand (Alt+H)"
        : "HadesGate Shield // Clique para expandir (Alt+H)";

    const logoCell = document.createElement("span");
    logoCell.className = "hg-hud-logo";
    logoCell.innerHTML = HADESGATE_SVG;

    hudCounter = document.createElement("span");
    hudCounter.className = "hg-hud-counter";
    hudCounter.textContent = "[ 0 TOKENS ]";

    hudChevron = document.createElement("span");
    hudChevron.className = "hg-hud-chevron";
    hudChevron.textContent = "▸";

    hudPill.appendChild(logoCell);
    hudPill.appendChild(hudCounter);
    hudPill.appendChild(hudChevron);

    hudPill.addEventListener("click", (e) => {
      e.preventDefault();
      e.stopPropagation();
      setHudExpanded(!hudIsExpanded);
    });

    // Actions drawer (Mask, Restore, Close)
    hudActions = document.createElement("div");
    hudActions.className = "hg-hud-actions";

    hudMaskBtn = document.createElement("button");
    hudMaskBtn.type = "button";
    hudMaskBtn.className = "hg-hud-btn primary";
    hudMaskBtn.title = "Atalho: Alt+H";
    hudMaskBtn.addEventListener("click", (e) => {
      e.preventDefault();
      e.stopPropagation();
      maskCurrentPromptInput();
      setHudExpanded(false);
    });

    hudRestoreBtn = document.createElement("button");
    hudRestoreBtn.type = "button";
    hudRestoreBtn.className = "hg-hud-btn";
    hudRestoreBtn.addEventListener("click", (e) => {
      e.preventDefault();
      e.stopPropagation();
      restoreTokensInDOM(document.body);
      setHudExpanded(false);
      showToast(
        settings.lang === "en"
          ? "[ HADESGATE // DOM TOKENS RESTORED ]"
          : "[ HADESGATE // TOKENS RESTAURADOS NA TELA ]",
        false
      );
    });

    hudCloseBtn = document.createElement("button");
    hudCloseBtn.type = "button";
    hudCloseBtn.className = "hg-hud-btn hg-hud-close";
    hudCloseBtn.textContent = "✕";
    hudCloseBtn.title = "Recolher (Esc)";
    hudCloseBtn.addEventListener("click", (e) => {
      e.preventDefault();
      e.stopPropagation();
      setHudExpanded(false);
    });

    hudActions.appendChild(hudMaskBtn);
    hudActions.appendChild(hudRestoreBtn);
    hudActions.appendChild(hudCloseBtn);

    hudBar.appendChild(hudPill);
    hudBar.appendChild(hudActions);
    hudRoot.appendChild(hudBar);
    document.body.appendChild(hudRoot);

    // Fechar ao clicar fora do HUD
    document.addEventListener("click", (e) => {
      if (hudIsExpanded && hudRoot && !hudRoot.contains(e.target)) {
        setHudExpanded(false);
      }
    });

    // Fechar ao pressionar Escape
    document.addEventListener("keydown", (e) => {
      if (e.key === "Escape" && hudIsExpanded) {
        setHudExpanded(false);
      }
    });

    updateHudLabels();
    updateHudVisibility();
    updateHudCounter();
  }

  function updateHudLabels() {
    if (!hudMaskBtn || !hudRestoreBtn) return;
    const isEn = settings.lang === "en";
    hudMaskBtn.textContent = isEn
      ? "HADESGATE // MASK PROMPT (ALT+H)"
      : "HADESGATE // MASCARAR (ALT+H)";
    hudRestoreBtn.textContent = isEn ? "RESTORE" : "RESTAURAR";
    if (hudCloseBtn) {
      hudCloseBtn.title = isEn ? "Collapse (Esc)" : "Recolher (Esc)";
    }
    if (hudPill) {
      hudPill.title = hudIsExpanded
        ? (isEn ? "HadesGate // Click to collapse" : "HadesGate // Clique para recolher")
        : (isEn ? "HadesGate Shield // Click to expand (Alt+H)" : "HadesGate Shield // Clique para expandir (Alt+H)");
    }
  }

  function updateHudCounter() {
    if (!hudCounter) return;
    const count = localTokenMap.size;
    hudCounter.textContent = `[ ${count} TOKENS ]`;
    if (count > 0) {
      hudCounter.classList.add("has-tokens");
    } else {
      hudCounter.classList.remove("has-tokens");
    }
  }

  function updateHudVisibility() {
    if (!hudRoot) return;
    hudRoot.style.display = settings.enabled ? "flex" : "none";
  }

  function showToast(msg, isError = false) {
    if (!hudRoot) mountHud();
    const toast = document.createElement("div");
    toast.className = `hg-toast ${isError ? "err" : ""}`;
    toast.textContent = msg;
    hudRoot.insertBefore(toast, hudRoot.firstChild);
    setTimeout(() => {
      toast.remove();
    }, 3200);
  }

  // Sticky warning used when the gateway fails and failClosed is on: the raw
  // text must not slip out unnoticed while the user reads the model answer.
  let stickyToast = null;

  function showStickyWarning(msg) {
    if (!hudRoot) mountHud();
    clearStickyWarning();
    stickyToast = document.createElement("div");
    stickyToast.className = "hg-toast err hg-sticky";
    stickyToast.textContent = msg;
    stickyToast.title = settings.lang === "en" ? "Click to dismiss" : "Clique para dispensar";
    stickyToast.addEventListener("click", clearStickyWarning);
    hudRoot.insertBefore(stickyToast, hudRoot.firstChild);
  }

  function clearStickyWarning() {
    if (stickyToast) {
      stickyToast.remove();
      stickyToast = null;
    }
  }

  function failureMessage(errCode) {
    if (settings.lang === "en") {
      if (settings.failClosed) {
        return `[ HADESGATE // ${errCode} ] RAW TEXT INSERTED, NOT PROTECTED`;
      }
      return `[ HADESGATE // ${errCode} ]`;
    }
    if (settings.failClosed) {
      return `[ HADESGATE // ${errCode} ] TEXTO CRU INSERIDO, SEM PROTEÇÃO`;
    }
    return `[ HADESGATE // ${errCode} ]`;
  }

  // Inserts the raw text after a failed anonymization. With failClosed the
  // failure stays visible until the next success or an explicit dismissal.
  function insertAfterFailure(target, rawText, errCode) {
    writeEditableText(target, rawText, false);
    if (settings.failClosed) {
      showStickyWarning(failureMessage(errCode));
      return;
    }
    showToast(failureMessage(errCode), true);
  }

  // ---------------------------------------------------------------------------
  // DETECÇÃO E MANIPULAÇÃO DO INPUT DE CHAT (TEXTAREA & PROSEMIRROR/QUILL)
  // ---------------------------------------------------------------------------
  function isEditableElement(node) {
    if (!node || !(node instanceof HTMLElement)) return false;
    if (node.closest("#hadesgate-hud-root")) return false;
    const tag = node.tagName.toLowerCase();
    if (tag === "textarea") return true;
    if (tag === "input" && (node.type === "text" || node.type === "search")) return true;
    if (node.isContentEditable) return true;
    return Boolean(node.closest('[contenteditable="true"]'));
  }

  function findActiveChatInput() {
    const active = document.activeElement;
    if (isEditableElement(active)) {
      return active.closest('[contenteditable="true"]') || active;
    }

    const selectors = [
      "#prompt-textarea",
      'div.ProseMirror[contenteditable="true"]',
      'div.ql-editor[contenteditable="true"]',
      'rich-textarea [contenteditable="true"]',
      'textarea[placeholder]',
      '[contenteditable="true"][role="textbox"]',
      "textarea",
    ];
    for (const sel of selectors) {
      const found = document.querySelector(sel);
      if (found && found.offsetParent !== null) {
        return found;
      }
    }
    return null;
  }

  function readEditableText(target) {
    if (!target) return "";
    const tag = target.tagName.toLowerCase();
    if (tag === "textarea" || tag === "input") {
      return target.value || "";
    }
    return target.innerText || target.textContent || "";
  }

  function writeEditableText(target, newText, replaceAll = false) {
    if (!target) return;
    target.focus();
    const tag = target.tagName.toLowerCase();

    if (tag === "textarea" || tag === "input") {
      const proto =
        tag === "textarea"
          ? window.HTMLTextAreaElement.prototype
          : window.HTMLInputElement.prototype;
      const nativeSetter = Object.getOwnPropertyDescriptor(proto, "value")?.set;

      let finalValue = newText;
      if (!replaceAll && typeof target.selectionStart === "number") {
        const start = target.selectionStart;
        const end = target.selectionEnd;
        const current = target.value || "";
        finalValue = current.slice(0, start) + newText + current.slice(end);
      }

      if (nativeSetter) {
        nativeSetter.call(target, finalValue);
      } else {
        target.value = finalValue;
      }
      target.dispatchEvent(new Event("input", { bubbles: true }));
      target.dispatchEvent(new Event("change", { bubbles: true }));
      return;
    }

    // ContentEditable (ProseMirror no Claude/ChatGPT, Quill no Gemini)
    if (replaceAll) {
      const sel = window.getSelection();
      const range = document.createRange();
      range.selectNodeContents(target);
      sel.removeAllRanges();
      sel.addRange(range);
    }

    isSyntheticPaste = true;
    const inserted = document.execCommand("insertText", false, newText);
    isSyntheticPaste = false;

    if (!inserted) {
      target.textContent = replaceAll
        ? newText
        : (target.textContent || "") + newText;
      target.dispatchEvent(
        new InputEvent("input", {
          bubbles: true,
          inputType: "insertText",
          data: newText,
        })
      );
    }
  }

  function applyDirectiveIfNeeded(sanitizedText, entitiesCount, fullPromptContext) {
    if (
      !settings.injectDirective ||
      entitiesCount === 0 ||
      directiveInjectedInPage ||
      (fullPromptContext && fullPromptContext.includes("[HADESGATE PRIVACY DIRECTIVE"))
    ) {
      return sanitizedText;
    }
    directiveInjectedInPage = true;
    return DIRECTIVE_HEADER + sanitizedText;
  }

  // ---------------------------------------------------------------------------
  // 1. INTERCEPTAÇÃO DE COLAGEM (CTRL+V)
  // ---------------------------------------------------------------------------
  document.addEventListener(
    "paste",
    (e) => {
      if (isSyntheticPaste || !settings.enabled || !settings.interceptPaste) return;
      const target = e.target;
      if (!isEditableElement(target)) return;

      const editableRoot = target.closest('[contenteditable="true"]') || target;
      const rawText = e.clipboardData?.getData("text/plain");
      if (!rawText || !rawText.trim()) return;

      // Intercepta imediatamente para consultar o motor determinístico do HadesGate
      e.preventDefault();
      e.stopPropagation();

      const { provider, model } = detectWebProvider();
      chrome.runtime.sendMessage(
        {
          type: "HADESGATE_ANONYMIZE",
          prompt: rawText,
          provider,
          model,
          recordTrace: true,
        },
        (res) => {
          if (res && res.blocked) {
            const blockedList = (res.blockedEntities || []).join(", ");
            const msg =
              settings.lang === "en"
                ? `[ HADESGATE // BLOCKED BY POLICY: ${blockedList || "SENSITIVE DATA"} ]`
                : `[ HADESGATE // BLOQUEADO PELA POLÍTICA: ${blockedList || "DADOS SENSÍVEIS"} ]`;
            showToast(msg, true);
            return;
          }

          if (chrome.runtime.lastError || !res || !res.ok) {
            insertAfterFailure(editableRoot, rawText, res?.error || "OFFLINE");
            return;
          }

          clearStickyWarning();
          const entities = res.entities || [];
          if (entities.length === 0) {
            writeEditableText(editableRoot, rawText, false);
            return;
          }

          for (const [token, orig] of Object.entries(res.tokenMap || {})) {
            localTokenMap.set(token, orig);
          }
          updateHudCounter();

          const existingContext = readEditableText(editableRoot);
          const payloadToInsert = applyDirectiveIfNeeded(
            res.sanitized,
            entities.length,
            existingContext
          );
          writeEditableText(editableRoot, payloadToInsert, false);

          showToast(
            settings.lang === "en"
              ? `[ HADESGATE // ${entities.length} ITEMS MASKED IN ${res.latencyMicros} µS ]`
              : `[ HADESGATE // ${entities.length} DADOS PROTEGIDOS EM ${res.latencyMicros} µS ]`,
            false
          );
        }
      );
    },
    true
  );

  // ---------------------------------------------------------------------------
  // 2. MASCARAMENTO DO CAMPO DE PROMPT (BOTÃO HUD OU ALT+H)
  // ---------------------------------------------------------------------------
  function maskCurrentPromptInput() {
    if (!settings.enabled) return;
    const inputEl = findActiveChatInput();
    if (!inputEl) {
      showToast(
        settings.lang === "en"
          ? "[ HADESGATE // NO CHAT INPUT FOUND ]"
          : "[ HADESGATE // CAMPO DE PROMPT NÃO ENCONTRADO ]",
        true
      );
      return;
    }

    const rawText = readEditableText(inputEl);
    if (!rawText || !rawText.trim()) return;

    const { provider, model } = detectWebProvider();
    chrome.runtime.sendMessage(
      {
        type: "HADESGATE_ANONYMIZE",
        prompt: rawText,
        provider,
        model,
        recordTrace: true,
      },
      (res) => {
        if (res && res.blocked) {
          const blockedList = (res.blockedEntities || []).join(", ");
          const msg =
            settings.lang === "en"
              ? `[ HADESGATE // BLOCKED BY POLICY: ${blockedList || "SENSITIVE DATA"} ]`
              : `[ HADESGATE // BLOQUEADO PELA POLÍTICA: ${blockedList || "DADOS SENSÍVEIS"} ]`;
          showToast(msg, true);
          return;
        }

        if (chrome.runtime.lastError || !res || !res.ok) {
          insertAfterFailure(inputEl, rawText, res?.error || "OFFLINE");
          return;
        }

        clearStickyWarning();

        const entities = res.entities || [];
        if (entities.length === 0) {
          showToast(
            settings.lang === "en"
              ? `[ HADESGATE // 0 PII DETECTED (${res.latencyMicros} µS) ]`
              : `[ HADESGATE // NENHUM PII DETECTADO (${res.latencyMicros} µS) ]`,
            false
          );
          return;
        }

        for (const [token, orig] of Object.entries(res.tokenMap || {})) {
          localTokenMap.set(token, orig);
        }
        updateHudCounter();

        const finalPrompt = applyDirectiveIfNeeded(
          res.sanitized,
          entities.length,
          rawText
        );
        writeEditableText(inputEl, finalPrompt, true);

        showToast(
          settings.lang === "en"
            ? `[ HADESGATE // ${entities.length} ITEMS MASKED IN ${res.latencyMicros} µS ]`
            : `[ HADESGATE // ${entities.length} DADOS PROTEGIDOS EM ${res.latencyMicros} µS ]`,
          false
        );
      }
    );
  }

  document.addEventListener("keydown", (e) => {
    if (e.altKey && (e.key === "h" || e.key === "H")) {
      e.preventDefault();
      maskCurrentPromptInput();
    }
  });

  // ---------------------------------------------------------------------------
  // 3. DETOKENIZADOR AUTOMÁTICO DE RESPOSTAS NO DOM (MUTATION OBSERVER)
  // ---------------------------------------------------------------------------
  const TOKEN_REGEX = /\[(?:HG|PG)_[a-fA-F0-9]+_[A-Z0-9_]+_\d+\]/g;

  function restoreTokensInDOM(rootNode) {
    if (!rootNode || localTokenMap.size === 0) return;

    const walker = document.createTreeWalker(rootNode, NodeFilter.SHOW_TEXT, {
      acceptNode(node) {
        const val = node.nodeValue;
        if (!val || (!val.includes("[HG_") && !val.includes("[PG_"))) {
          return NodeFilter.FILTER_REJECT;
        }
        const parent = node.parentElement;
        if (!parent) return NodeFilter.FILTER_REJECT;
        if (
          parent.closest(
            'textarea, input, [contenteditable="true"], #hadesgate-hud-root, script, style'
          )
        ) {
          return NodeFilter.FILTER_REJECT;
        }
        return NodeFilter.FILTER_ACCEPT;
      },
    });

    const nodesToUpdate = [];
    let current;
    while ((current = walker.nextNode())) {
      nodesToUpdate.push(current);
    }

    for (const textNode of nodesToUpdate) {
      const originalText = textNode.nodeValue;
      const replacedText = originalText.replace(TOKEN_REGEX, (match) => {
        return localTokenMap.has(match) ? localTokenMap.get(match) : match;
      });
      if (replacedText !== originalText) {
        textNode.nodeValue = replacedText;
      }
    }
  }

  let restoreScheduled = false;
  const observer = new MutationObserver(() => {
    if (!settings.enabled || !settings.autoRestore || localTokenMap.size === 0) return;
    if (restoreScheduled) return;
    restoreScheduled = true;
    requestAnimationFrame(() => {
      restoreScheduled = false;
      restoreTokensInDOM(document.body);
    });
  });

  function init() {
    mountHud();
    loadSettings();
    if (document.body) {
      observer.observe(document.body, {
        childList: true,
        subtree: true,
        characterData: true,
      });
    }
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();

