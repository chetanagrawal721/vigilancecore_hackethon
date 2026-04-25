/**
 * VigilanceCore Voice Module — Multilingual speech I/O for the AI chat.
 *
 * Uses the browser Web Speech API (SpeechRecognition + SpeechSynthesis).
 * Supports English, Hindi, and Hinglish.
 * No backend changes — runs entirely in the browser.
 *
 * Public API:
 *   VCVoice.isSupported()              → boolean
 *   VCVoice.setLanguage(langCode)      → void
 *   VCVoice.getLanguage()              → string
 *   VCVoice.startListening(onResult, onError, onStateChange) → void
 *   VCVoice.stopListening()            → void
 *   VCVoice.speak(text, onEnd)         → void
 *   VCVoice.stopSpeaking()             → void
 *   VCVoice.isSpeaking()               → boolean
 *   VCVoice.isListening()              → boolean
 *   VCVoice.LANGUAGES                  → array of { code, label, flag, sttCode, ttsCode }
 */

/* eslint-disable no-unused-vars */
const VCVoice = (() => {
  "use strict";

  // ── Language definitions ────────────────────────────────────────────────────
  const LANGUAGES = [
    { code: "en",      label: "English",  flag: "🇬🇧", sttCode: "en-IN",  ttsCode: "en-US" },
    { code: "hi",      label: "हिन्दी",    flag: "🇮🇳", sttCode: "hi-IN",  ttsCode: "hi-IN" },
    { code: "hinglish", label: "Hinglish", flag: "🇮🇳", sttCode: "hi-IN",  ttsCode: "en-IN" },
  ];

  let currentLang = LANGUAGES[0]; // default: English
  let recognition  = null;
  let listening    = false;

  // ── Browser support check ──────────────────────────────────────────────────
  const SpeechRecognition = window.SpeechRecognition || window.webkitSpeechRecognition;
  const synthesis         = window.speechSynthesis;

  function isSupported() {
    return !!(SpeechRecognition && synthesis);
  }

  // ── Language management ────────────────────────────────────────────────────
  function setLanguage(langCode) {
    const found = LANGUAGES.find(l => l.code === langCode);
    if (found) currentLang = found;
  }

  function getLanguage() {
    return currentLang;
  }

  // ── Speech-to-Text (Microphone → Text) ─────────────────────────────────────
  function startListening(onResult, onError, onStateChange) {
    if (!SpeechRecognition) {
      if (onError) onError("Speech recognition is not supported in this browser.");
      return;
    }

    // Stop any previous session
    stopListening();

    recognition = new SpeechRecognition();
    recognition.lang            = currentLang.sttCode;
    recognition.continuous      = false;
    recognition.interimResults  = true;
    recognition.maxAlternatives = 1;

    let finalTranscript = "";

    recognition.onstart = () => {
      listening = true;
      if (onStateChange) onStateChange("listening");
    };

    recognition.onresult = (event) => {
      let interimTranscript = "";
      for (let i = event.resultIndex; i < event.results.length; i++) {
        const transcript = event.results[i][0].transcript;
        if (event.results[i].isFinal) {
          finalTranscript += transcript;
        } else {
          interimTranscript += transcript;
        }
      }
      // Show interim results as live preview
      if (onStateChange) {
        onStateChange("interim", interimTranscript || finalTranscript);
      }
    };

    recognition.onend = () => {
      listening = false;
      if (onStateChange) onStateChange("stopped");
      if (finalTranscript.trim() && onResult) {
        onResult(finalTranscript.trim());
      }
    };

    recognition.onerror = (event) => {
      listening = false;
      if (onStateChange) onStateChange("stopped");
      // "no-speech" and "aborted" are not real errors
      if (event.error === "no-speech") {
        if (onError) onError("No speech detected. Please try again.");
      } else if (event.error === "not-allowed") {
        if (onError) onError("Microphone access denied. Please allow microphone access in your browser settings.");
      } else if (event.error !== "aborted") {
        if (onError) onError(`Voice error: ${event.error}`);
      }
    };

    recognition.start();
  }

  function stopListening() {
    if (recognition) {
      try { recognition.abort(); } catch (_) {}
      recognition = null;
    }
    listening = false;
  }

  // ── Text-to-Speech (Text → Speaker) ────────────────────────────────────────
  function speak(text, onEnd) {
    if (!synthesis) {
      if (onEnd) onEnd();
      return;
    }

    // Cancel any current speech
    synthesis.cancel();

    // Strip markdown formatting for cleaner speech
    const cleanText = text
      .replace(/\*\*/g, "")
      .replace(/`[^`]+`/g, (match) => match.replace(/`/g, ""))
      .replace(/[🔴🟠🟡🔵⚪📋✅⚠️💡📥👋•─═]/g, "")
      .replace(/\n+/g, ". ")
      .replace(/\s+/g, " ")
      .trim();

    if (!cleanText) {
      if (onEnd) onEnd();
      return;
    }

    // Split into chunks — browser has ~200-char limit per utterance on some platforms
    const chunks = splitIntoChunks(cleanText, 180);
    let chunkIndex = 0;

    function speakNext() {
      if (chunkIndex >= chunks.length) {
        if (onEnd) onEnd();
        return;
      }

      const utterance  = new SpeechSynthesisUtterance(chunks[chunkIndex]);
      utterance.lang   = currentLang.ttsCode;
      utterance.rate   = 0.95;
      utterance.pitch  = 1.0;
      utterance.volume = 1.0;

      // Try to find a matching voice
      const voices = synthesis.getVoices();
      const langPrefix = currentLang.ttsCode.split("-")[0];
      const matchedVoice = voices.find(v => v.lang.startsWith(langPrefix));
      if (matchedVoice) utterance.voice = matchedVoice;

      utterance.onend  = () => { chunkIndex++; speakNext(); };
      utterance.onerror = () => { chunkIndex++; speakNext(); };

      synthesis.speak(utterance);
    }

    // Voices may load async — wait for them
    if (synthesis.getVoices().length === 0) {
      synthesis.addEventListener("voiceschanged", () => speakNext(), { once: true });
    } else {
      speakNext();
    }
  }

  function splitIntoChunks(text, maxLen) {
    const chunks = [];
    let remaining = text;
    while (remaining.length > maxLen) {
      let breakPoint = remaining.lastIndexOf(". ", maxLen);
      if (breakPoint < maxLen / 2) breakPoint = remaining.lastIndexOf(" ", maxLen);
      if (breakPoint < maxLen / 2) breakPoint = maxLen;
      chunks.push(remaining.substring(0, breakPoint + 1).trim());
      remaining = remaining.substring(breakPoint + 1).trim();
    }
    if (remaining) chunks.push(remaining);
    return chunks;
  }

  function stopSpeaking() {
    if (synthesis) synthesis.cancel();
  }

  function isSpeaking() {
    return synthesis ? synthesis.speaking : false;
  }

  function isListeningNow() {
    return listening;
  }

  return {
    isSupported,
    setLanguage,
    getLanguage,
    startListening,
    stopListening,
    speak,
    stopSpeaking,
    isSpeaking,
    isListening: isListeningNow,
    LANGUAGES,
  };
})();
