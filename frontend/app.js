document.addEventListener("DOMContentLoaded", () => {
  const reduceMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  const API_BASE = ""; // Same origin as FastAPI — never hardcode a port

  // ── Scroll reveal ────────────────────────────────────────────────────────────
  if (!reduceMotion) {
    const observer = new IntersectionObserver(
      (entries) => entries.forEach((e) => {
        if (e.isIntersecting) { e.target.classList.add("is-visible"); observer.unobserve(e.target); }
      }),
      { threshold: 0.12 }
    );
    document.querySelectorAll(".feature,.stat,.eyebrow,.lead,.actions,.hero-card,.summary-card,.finding-card,.form-shell")
      .forEach((el) => { el.classList.add("reveal"); observer.observe(el); });
  }

  // ── Smooth anchor scroll ─────────────────────────────────────────────────────
  document.querySelectorAll('a[href^="#"]').forEach((link) => {
    link.addEventListener("click", (e) => {
      const target = document.querySelector(link.getAttribute("href"));
      if (!target) return;
      e.preventDefault();
      target.scrollIntoView({ behavior: reduceMotion ? "auto" : "smooth", block: "start" });
    });
  });

  // ── Route by pathname ────────────────────────────────────────────────────────
  const path = window.location.pathname;
  if (path === "/input")   initInputPage();
  if (path === "/results") initResultsPage();

  // ════════════════════════════════════════════════════════════════════════════
  // INPUT PAGE
  // ════════════════════════════════════════════════════════════════════════════
  function initInputPage() {
    const form         = document.getElementById("analysisForm");
    const fileInput    = document.getElementById("fileInput");
    const fileDropZone = document.getElementById("fileDropZone");
    const fileLabel    = document.getElementById("fileLabel");
    const analyzeBtn   = document.getElementById("analyzeBtn");
    const btnText      = document.getElementById("analyzeBtnText");
    const spinner      = document.getElementById("analyzeSpinner");
    const statusCard   = document.getElementById("statusCard");
    const statusDot    = document.getElementById("statusDot");
    const statusTitle  = document.getElementById("statusTitle");
    const statusBadge  = document.getElementById("statusBadge");
    const statusMsg    = document.getElementById("statusMessage");
    const progressFill = document.getElementById("progressFill");

    if (!form) return;

    // ── Drop zone click → open file picker ────────────────────────────────────
    fileDropZone.addEventListener("click", (e) => {
      e.stopPropagation();
      fileInput.click();
    });

    fileDropZone.addEventListener("dragover", (e) => {
      e.preventDefault();
      fileDropZone.classList.add("drag-over");
    });

    fileDropZone.addEventListener("dragleave", () => {
      fileDropZone.classList.remove("drag-over");
    });

    fileDropZone.addEventListener("drop", (e) => {
      e.preventDefault();
      fileDropZone.classList.remove("drag-over");
      const f = e.dataTransfer.files[0];
      if (f && f.name.endsWith(".sol")) {
        setFile(f);
      } else {
        statusCard.classList.remove("hidden");
        showStatus("error", "Only .sol files are accepted.", "Invalid", 0);
      }
    });

    // ── Native file picker ─────────────────────────────────────────────────────
    fileInput.addEventListener("change", () => {
      if (fileInput.files && fileInput.files[0]) setFile(fileInput.files[0]);
    });

    function setFile(file) {
      // Sync into fileInput.files so FormData picks it up
      const dt = new DataTransfer();
      dt.items.add(file);
      fileInput.files = dt.files;

      fileLabel.innerHTML = `<span class="link-text">${escHtml(file.name)}</span> &nbsp;✓`;
      fileDropZone.classList.add("has-file");

      // Mirror into textarea
      const reader = new FileReader();
      reader.onload = (ev) => {
        const ta = document.getElementById("solidityCode");
        if (ta) ta.value = ev.target.result;
      };
      reader.readAsText(file);
    }

    // ── Form submit ────────────────────────────────────────────────────────────
    form.addEventListener("submit", async (e) => {
      e.preventDefault();
      e.stopPropagation();

      if (!validateForm()) return;

      setLoading(true);
      statusCard.classList.remove("hidden");
      showStatus("running", "Preparing contract for upload...", "Uploading", 10);

      try {
        const formData     = new FormData();
        const contractName = document.getElementById("contractName").value.trim() || "contract";
        const filename     = contractName.endsWith(".sol") ? contractName : `${contractName}.sol`;
        const solidityCode = document.getElementById("solidityCode").value.trim();

        if (fileInput.files && fileInput.files[0]) {
          formData.append("file", fileInput.files[0]);
        } else {
          // Wrap textarea content as a blob
          formData.append("file", new Blob([solidityCode], { type: "text/plain" }), filename);
        }

        showStatus("running", "Uploading to analysis pipeline...", "Uploading", 20);

        // Do NOT set Content-Type — browser sets multipart boundary automatically
        const res = await fetch(`${API_BASE}/api/analyze`, { method: "POST", body: formData });

        if (!res.ok) {
          let detail = `Server error ${res.status}`;
          try { const err = await res.json(); detail = err.detail || detail; } catch (_) {}
          throw new Error(detail);
        }

        const data = await res.json();
        showStatus("running", "Pipeline started. Polling for results...", "Processing", 30);
        pollStatus(data.scan_id);

      } catch (err) {
        setLoading(false);
        showStatus("error", err.message || "An unexpected error occurred.", "Failed", 0);
      }
    });

    // ── Poll /api/status ───────────────────────────────────────────────────────
    function pollStatus(scanId) {
      const MAX = 120;
      let attempt = 0;

      async function poll() {
        attempt++;
        if (attempt > MAX) {
          setLoading(false);
          showStatus("error", "Analysis timed out after 5 minutes.", "Timeout", 0);
          return;
        }
        try {
          const res  = await fetch(`${API_BASE}/api/status/${scanId}`);
          if (!res.ok) throw new Error(`Status check failed (${res.status})`);
          const data = await res.json();

          const pct = Math.min(30 + Math.round((attempt / MAX) * 62), 92);
          showStatus("running", data.message || "Processing...", "Running", pct);

          if (data.status === "completed") {
            showStatus("success", "Scan complete. Redirecting...", "Done", 100);
            setLoading(false);
            setTimeout(() => { window.location.href = `/results?scan_id=${scanId}`; }, 800);
            return;
          }
          if (data.status === "failed") {
            setLoading(false);
            showStatus("error", data.message || "Analysis failed.", "Failed", 0);
            return;
          }
          setTimeout(poll, 2500);
        } catch (err) {
          setLoading(false);
          showStatus("error", err.message || "Connection error.", "Error", 0);
        }
      }

      poll(); // Fire immediately
    }

    // ── Validation ─────────────────────────────────────────────────────────────
    function validateForm() {
      let valid = true;
      const nameField = document.getElementById("contractName");
      const nameError = document.getElementById("contractNameError");
      if (!nameField.value.trim()) {
        nameError.classList.add("visible"); valid = false;
      } else {
        nameError.classList.remove("visible");
      }
      const codeField = document.getElementById("solidityCode");
      const codeError = document.getElementById("solidityCodeError");
      const hasFile   = fileInput.files && fileInput.files.length > 0;
      const hasCode   = codeField && codeField.value.trim().length > 0;
      if (!hasFile && !hasCode) {
        codeError.classList.add("visible"); valid = false;
      } else {
        codeError.classList.remove("visible");
      }
      return valid;
    }

    // ── UI helpers ─────────────────────────────────────────────────────────────
    function setLoading(on) {
      analyzeBtn.disabled   = on;
      btnText.textContent   = on ? "Analyzing..." : "Run security analysis";
      spinner.classList.toggle("hidden", !on);
      statusCard.setAttribute("aria-busy", String(on));
    }

    function showStatus(type, message, badge, pct) {
      statusDot.className   = `status-dot ${type}`;
      statusTitle.textContent = type === "success" ? "Complete" : type === "error" ? "Error" : "In progress";
      statusBadge.textContent = badge;
      statusBadge.className   = `status-badge ${type}`;
      statusMsg.textContent   = message;
      progressFill.style.width = `${pct}%`;
    }
  }

  // ════════════════════════════════════════════════════════════════════════════
  // RESULTS PAGE
  // ════════════════════════════════════════════════════════════════════════════
  function initResultsPage() {
    const loading   = document.getElementById("resultsLoading");
    const errorDiv  = document.getElementById("resultsError");
    const errorText = document.getElementById("resultsErrorText");
    const shell     = document.getElementById("resultsShell");

    const scanId = new URLSearchParams(window.location.search).get("scan_id");

    if (!scanId) { showError("No scan ID found. Please run a new analysis."); return; }

    if (loading) loading.classList.remove("hidden");

    fetch(`${API_BASE}/api/report/${scanId}`)
      .then((res) => {
        if (!res.ok) throw new Error(`Could not load report (HTTP ${res.status})`);
        return res.json();
      })
      .then((data) => {
        if (loading) loading.classList.add("hidden");
        render(data);
      })
      .catch((err) => {
        if (loading) loading.classList.add("hidden");
        showError(err.message);
      });

    function render(data) {
      if (shell) shell.classList.remove("hidden");
      const findings = data.findings || [];

      setText("resultContractName", extractFilename(data.source_file) || "Unknown");
      setText("resultStatus",       data.status || "-");
      setText("resultStatusText",   data.status === "completed" ? "Analysis finished successfully." : data.status);
      setText("resultTotal",        findings.length);

      const counts = { critical: 0, high: 0, medium: 0, low: 0, informational: 0 };
      findings.forEach((f) => { const s = cleanSev(f.severity); if (s in counts) counts[s]++; });

      setText("countCritical", counts.critical);
      setText("countHigh",     counts.high);
      setText("countMedium",   counts.medium);
      setText("countLow",      counts.low);
      setText("countInfo",     counts.informational);

      const overall = ["critical","high","medium","low","informational"].find((s) => counts[s] > 0) || "none";
      const sevEl   = document.getElementById("resultSeverity");
      if (sevEl) { sevEl.textContent = cap(overall); sevEl.className = `severity-badge sev-${overall}`; }
      setText("resultSeverityText", overall === "none" ? "No issues detected." : "Highest finding level.");

      const list = document.getElementById("findingsList");
      if (list) {
        list.innerHTML = "";
        if (!findings.length) {
          list.innerHTML = `<div class="no-findings">No vulnerabilities detected.</div>`;
        } else {
          findings.forEach((f, i) => list.appendChild(buildCard(f, i + 1)));
        }
      }

      const dlBtn = document.getElementById("downloadReportBtn");
      if (dlBtn) dlBtn.addEventListener("click", () => {
        window.location.href = `${API_BASE}/api/report/${data.scan_id}/download`;
      });
    }

    function buildCard(f, num) {
      const sev  = cleanSev(f.severity);
      const card = document.createElement("article");
      card.className = `finding-card sev-border-${sev}`;
      card.innerHTML = `
        <div class="finding-header">
          <div class="finding-meta">
            <span class="finding-num">Finding #${num}</span>
            <span class="finding-type">${escHtml(cleanType(f.vuln_type))}</span>
          </div>
          <span class="severity-badge sev-${sev}">${cap(sev)}</span>
        </div>
        <h3 class="finding-title">${escHtml(f.title || "Unnamed Finding")}</h3>
        <p class="finding-desc">${escHtml(f.description || "No description provided.")}</p>
        ${f.function_name ? `
        <div class="finding-section">
          <span class="finding-section-label">Affected function</span>
          <code class="code-tag">${escHtml(f.function_name)}</code>
        </div>` : ""}
        ${f.start_line ? `
        <div class="finding-section">
          <span class="finding-section-label">Line number</span>
          <code class="code-tag">Line ${f.start_line}</code>
        </div>` : ""}
        ${f.recommendation ? `
        <div class="finding-section remediation">
          <span class="finding-section-label">Recommendation</span>
          <p class="finding-section-text">${escHtml(f.recommendation)}</p>
        </div>` : ""}
        <div class="finding-footer">
          ${f.cvss_score ? `<span class="cvss-score">CVSS ${Number(f.cvss_score).toFixed(1)}</span>` : ""}
          ${f.swc_reference && f.swc_reference !== "SWC-UNKNOWN"
            ? `<span class="swc-tag">${escHtml(f.swc_reference)}</span>` : ""}
          <span class="finding-type" style="margin-left:auto">${escHtml(f.detector_id || "")}</span>
        </div>`;
      return card;
    }

    function showError(msg) {
      if (loading)   loading.classList.add("hidden");
      if (shell)     shell.classList.add("hidden");
      if (errorDiv)  errorDiv.classList.remove("hidden");
      if (errorText) errorText.textContent = msg;
    }
  }

  // ── Utilities ─────────────────────────────────────────────────────────────────
  function escHtml(s) {
    return String(s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;");
  }
  function cap(s)     { return s ? s.charAt(0).toUpperCase() + s.slice(1) : ""; }
  function setText(id, v) { const el = document.getElementById(id); if (el) el.textContent = String(v); }
  function cleanSev(r) { return String(r||"informational").replace("Severity.","").toLowerCase().trim(); }
  function cleanType(r){ return String(r||"UNKNOWN").replace("VulnerabilityType.","").replace(/_/g," ").trim(); }
  function extractFilename(p) { return p ? p.split(/[\\/]/).pop() : null; }
});