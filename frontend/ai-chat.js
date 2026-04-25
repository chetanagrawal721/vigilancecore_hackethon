/**
 * VigilanceCore AI Chat Panel — interactive UI component.
 * Includes Voice Support & Language Selection.
 */

/* eslint-disable no-unused-vars */
const VCChat = (() => {
  "use strict";

  let assistant = null;
  let panel     = null;
  let messages  = null;
  let input     = null;
  let micBtn    = null;

  // ── Markdown-lite renderer ───────────────────────────────────────────────
  function md(text) {
    return text
      .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
      .replace(/\*\*(.+?)\*\*/g, "<strong>$1</strong>")
      .replace(/`([^`]+)`/g, "<code>$1</code>")
      .replace(/\n/g, "<br>");
  }

  // ── Build the chat panel DOM ───────────────────────────────────────────────
  function buildPanel() {
    // Floating toggle button
    const toggle = document.createElement("button");
    toggle.id        = "vcChatToggle";
    toggle.className = "vc-chat-toggle";
    toggle.innerHTML = `
      <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
        <path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/>
      </svg>
      <span>AI Assistant</span>`;
    toggle.setAttribute("aria-label", "Open AI Assistant");
    document.body.appendChild(toggle);

    // Language options
    let langOptions = "";
    if (typeof VCVoice !== "undefined") {
      VCVoice.LANGUAGES.forEach(l => {
        langOptions += `<option value="${l.code}">${l.flag} ${l.label}</option>`;
      });
    }

    // Panel
    panel = document.createElement("aside");
    panel.id        = "vcChatPanel";
    panel.className = "vc-chat-panel";
    panel.innerHTML = `
      <div class="vc-chat-header">
        <div class="vc-chat-header-left">
          <div class="vc-chat-avatar" aria-hidden="true">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <circle cx="12" cy="12" r="10"/><path d="M8 14s1.5 2 4 2 4-2 4-2"/><line x1="9" y1="9" x2="9.01" y2="9"/><line x1="15" y1="9" x2="15.01" y2="9"/>
            </svg>
          </div>
          <div>
            <strong>VigilanceCore AI</strong>
            <span>Security assistant</span>
          </div>
        </div>
        <div class="vc-chat-header-actions">
          ${typeof VCVoice !== "undefined" ? `<select id="vcLangSelect" class="vc-chat-lang-select">${langOptions}</select>` : ""}
          <button class="vc-chat-dl-btn" id="vcDownloadAIReport" title="Download AI Report">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
              <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/>
            </svg>
          </button>
          <button class="vc-chat-close-btn" id="vcChatClose" aria-label="Close assistant">✕</button>
        </div>
      </div>
      <div class="vc-chat-messages" id="vcChatMessages"></div>
      <div class="vc-chat-suggestions" id="vcChatSuggestions"></div>
      <form class="vc-chat-input-bar" id="vcChatForm" autocomplete="off">
        <input type="text" id="vcChatInput" placeholder="Ask about your scan results..." aria-label="Chat input" />
        ${typeof VCVoice !== "undefined" && VCVoice.isSupported() ? `
        <button type="button" id="vcChatMic" class="vc-chat-mic" aria-label="Voice input">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <path d="M12 1a3 3 0 0 0-3 3v8a3 3 0 0 0 6 0V4a3 3 0 0 0-3-3z"></path><path d="M19 10v2a7 7 0 0 1-14 0v-2"></path><line x1="12" y1="19" x2="12" y2="23"></line><line x1="8" y1="23" x2="16" y2="23"></line>
          </svg>
        </button>` : ""}
        <button type="submit" class="vc-chat-send" aria-label="Send message">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <line x1="22" y1="2" x2="11" y2="13"/><polygon points="22 2 15 22 11 13 2 9 22 2"/>
          </svg>
        </button>
      </form>`;
    document.body.appendChild(panel);

    messages = document.getElementById("vcChatMessages");
    input    = document.getElementById("vcChatInput");
    micBtn   = document.getElementById("vcChatMic");

    // Toggle open/close
    toggle.addEventListener("click", () => {
      panel.classList.toggle("open");
      toggle.classList.toggle("active");
      if (panel.classList.contains("open")) input.focus();
    });
    document.getElementById("vcChatClose").addEventListener("click", () => {
      panel.classList.remove("open");
      toggle.classList.remove("active");
    });

    // Language change
    const langSelect = document.getElementById("vcLangSelect");
    if (langSelect) {
      langSelect.addEventListener("change", (e) => {
        if (typeof VCVoice !== "undefined") {
          VCVoice.setLanguage(e.target.value);
        }
      });
    }

    // Chat form text submission
    document.getElementById("vcChatForm").addEventListener("submit", (e) => {
      e.preventDefault();
      const q = input.value.trim();
      if (!q) return;
      handleUserQuery(q);
      input.value = "";
    });

    // Voice button handling
    if (micBtn && typeof VCVoice !== "undefined") {
      micBtn.addEventListener("click", () => {
        if (VCVoice.isListening()) {
          VCVoice.stopListening();
        } else {
          VCVoice.stopSpeaking();
          // Visual feedback
          micBtn.classList.add("listening");
          input.placeholder = "Listening...";
          
          VCVoice.startListening(
            (transcript) => {
              // On success
              micBtn.classList.remove("listening");
              input.placeholder = "Ask about your scan results...";
              if (transcript) handleUserQuery(transcript);
            },
            (err) => {
              // On error
              micBtn.classList.remove("listening");
              input.placeholder = "Ask about your scan results...";
              addMessage("bot", `❌ Voice Error: ${err}`);
            },
            (state, interim) => {
              if (state === "interim" && interim) {
                input.value = interim;
              } else if (state === "stopped") {
                micBtn.classList.remove("listening");
                input.value = "";
                input.placeholder = "Ask about your scan results...";
              }
            }
          );
        }
      });
    }

    // Stop speaking when user types
    input.addEventListener("input", () => {
      if (typeof VCVoice !== "undefined") VCVoice.stopSpeaking();
    });

    // Download AI report
    document.getElementById("vcDownloadAIReport").addEventListener("click", handleDownload);
  }

  // ── Query processor ────────────────────────────────────────────────────────
  function handleUserQuery(query) {
    addMessage("user", query);
    // Clear suggestions
    const sug = document.getElementById("vcChatSuggestions");
    if (sug) sug.classList.add("used");

    const lang = typeof VCVoice !== "undefined" ? VCVoice.getLanguage().code : "en";
    
    if (typeof VCVoice !== "undefined") VCVoice.stopSpeaking();

    setTimeout(() => {
      const answer = assistant.ask(query, lang);
      addMessage("bot", answer);
      
      // Speak the response if voice is active
      if (typeof VCVoice !== "undefined" && VCVoice.isSupported()) {
        VCVoice.speak(answer);
      }
    }, 300);
  }

  // ── Add a message bubble ───────────────────────────────────────────────────
  function addMessage(sender, text) {
    const bubble = document.createElement("div");
    bubble.className = `vc-chat-msg vc-chat-msg-${sender}`;
    if (sender === "bot") {
      bubble.innerHTML = `
        <div class="vc-chat-msg-avatar" aria-hidden="true">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <circle cx="12" cy="12" r="10"/><path d="M8 14s1.5 2 4 2 4-2 4-2"/>
            <line x1="9" y1="9" x2="9.01" y2="9"/><line x1="15" y1="9" x2="15.01" y2="9"/>
          </svg>
        </div>
        <div class="vc-chat-msg-body">${md(text)}</div>`;
    } else {
      bubble.innerHTML = `<div class="vc-chat-msg-body">${md(text)}</div>`;
    }
    messages.appendChild(bubble);
    messages.scrollTop = messages.scrollHeight;
  }

  // ── Quick suggestion chips ─────────────────────────────────────────────────
  function addSuggestions() {
    const suggestions = [
      "Give me a summary",
      "Is it safe to deploy?",
      "Explain finding #1",
    ];
    const container = document.getElementById("vcChatSuggestions");
    if (!container) return;
    suggestions.forEach(s => {
      const chip = document.createElement("button");
      chip.className   = "vc-chat-chip";
      chip.textContent = s;
      chip.addEventListener("click", () => handleUserQuery(s));
      container.appendChild(chip);
    });
  }

  // ── Download handler ───────────────────────────────────────────────────────
  function handleDownload() {
    const report   = assistant.generateFullReport();
    const blob     = new Blob([report], { type: "text/plain;charset=utf-8" });
    const url      = URL.createObjectURL(blob);
    const a        = document.createElement("a");
    a.href         = url;
    a.download     = `vigilancecore_ai_report_${Date.now()}.txt`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);

    addMessage("bot", "📥 **AI Report downloaded!**");
  }

  // ── Public init ────────────────────────────────────────────────────────────
  function init(reportData) {
    if (!reportData) return;
    assistant = new VCAssistant(reportData);
    buildPanel();
    addSuggestions();

    const welcomeText = "👋 **Hi! I'm the VigilanceCore AI Assistant.**\n\nI've analyzed your scan results and I'm ready to help you understand them. Select your language, ask a question, or use the microphone to talk to me!";
    addMessage("bot", welcomeText);
  }

  return { init };
})();
