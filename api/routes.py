import uuid
import json
import asyncio
import dataclasses
import tempfile
from pathlib import Path
from datetime import datetime

from fastapi import APIRouter, UploadFile, File, HTTPException, BackgroundTasks
from fastapi.responses import FileResponse

from api.schemas import (
    AnalyzeResponse,
    StatusResponse,
    EnrichedFinding,
    EnrichedAuditReport,
    ScanStatsOut,
)
from api.storage import scan_store
from core.analysis_engine import AnalysisEngine
from config import REPORTS_DIR

router = APIRouter()

# ── Engine singleton ───────────────────────────────────────────────────────────
_engine: AnalysisEngine = None


def get_engine() -> AnalysisEngine:
    global _engine
    if _engine is None:
        _engine = AnalysisEngine(tool_version="1.1.0", network=None)
    return _engine


# ── Safe finding serialiser ────────────────────────────────────────────────────
def serialise_finding(finding) -> dict:
    """
    Safely convert a Finding object to a plain dict.
    Priority:
      1. finding.asdict()          — our typed serialiser (always present)
      2. dataclasses.asdict()      — stdlib fallback for slots=True dataclasses
      3. Empty dict                — prevents a crash if neither is available
    """
    if hasattr(finding, "asdict"):
        return finding.asdict()
    if dataclasses.is_dataclass(finding):
        return dataclasses.asdict(finding)
    return {}


# ── Background scan task ───────────────────────────────────────────────────────
async def process_scan(scan_id: str, filepath: str) -> None:
    try:
        # Run the blocking analysis engine off the event loop
        loop = asyncio.get_running_loop()
        analysis_result = await loop.run_in_executor(
            None, get_engine().analyse, filepath, None
        )

        # Engine-level failure (Slither / parser crash)
        if getattr(analysis_result, "error", None):
            scan_store.update(scan_id, status="failed", error=analysis_result.error)
            return

        # Use confirmed_findings to exclude false-positive-flagged items
        enriched_findings = []
        for finding in analysis_result.confirmed_findings:
            fd = serialise_finding(finding)

            # Safely coerce numeric fields
            raw_cvss   = fd.get("cvss_score")
            cvss_score = float(raw_cvss) if raw_cvss is not None else 0.0
            confidence = float(fd.get("confidence") or 0.0)
            source_file = fd.get("source_file") or filepath

            try:
                enriched = EnrichedFinding(
                    vuln_type       = str(fd.get("vuln_type", "UNKNOWN")),
                    severity        = str(fd.get("severity",  "UNKNOWN")),
                    contract_name   = fd.get("contract_name", "Unknown"),
                    function_name   = fd.get("function_name") or "contract-level",
                    source_file     = source_file,
                    start_line      = fd.get("start_line"),
                    title           = fd.get("title")          or "Unnamed Finding",
                    description     = fd.get("description")    or "No description available.",
                    recommendation  = fd.get("recommendation") or "Review finding manually.",
                    confidence      = confidence,
                    cvss_score      = cvss_score,
                    detector_id     = fd.get("detector_id")    or "unknown",
                    # AI enrichment disabled — re-enable after detection is stable
                    why_dangerous   = "AI enrichment not active.",
                    attack_scenario = "AI enrichment not active.",
                    code_fix        = "AI enrichment not active.",
                    best_practice   = "AI enrichment not active.",
                    swc_reference   = str(fd.get("swc_id") or "SWC-UNKNOWN"),
                )
                enriched_findings.append(enriched)

            except Exception as schema_err:
                print(
                    f"WARN: Skipped finding '{fd.get('title', 'unknown')}': {schema_err}"
                )

        # Build stats directly from the ScanStats dataclass fields
        stats = analysis_result.stats
        stats_out = ScanStatsOut(
            contracts_analyzed = stats.contracts_analyzed,
            functions_analyzed = stats.functions_analyzed,
            functions_skipped  = stats.functions_skipped,
            findings_total     = len(enriched_findings),
            elapsed_ms         = stats.elapsed_ms,
        )

        # Assemble the final report
        report = EnrichedAuditReport(
            scan_id      = scan_id,
            source_file  = filepath,
            status       = "completed",
            stats        = stats_out,
            findings     = enriched_findings,
            tool_version = getattr(analysis_result, "tool_version", "1.1.0"),
            created_at   = datetime.utcnow().isoformat(),
        )

        # Persist to disk so the report survives process restarts
        report_path = REPORTS_DIR / f"{scan_id}.json"
        with open(report_path, "w", encoding="utf-8") as f:
            json.dump(report.model_dump(), f, indent=2)

        # Mark completed in the in-memory store
        scan_store.update(
            scan_id,
            status         = "completed",
            findings_total = len(enriched_findings),
            elapsed_ms     = stats_out.elapsed_ms,
            report         = report,
        )

    except Exception as e:
        scan_store.update(scan_id, status="failed", error=str(e))
        print(f"ERROR: Scan {scan_id} failed: {e}")


# ── POST /api/analyze ──────────────────────────────────────────────────────────
@router.post("/api/analyze", response_model=AnalyzeResponse, status_code=202)
async def analyze_contract(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
) -> AnalyzeResponse:
    if not file.filename.endswith(".sol"):
        raise HTTPException(
            status_code=400,
            detail="Only Solidity (.sol) files are accepted.",
        )

    scan_id  = str(uuid.uuid4())
    filepath = str(Path(tempfile.gettempdir()) / f"{scan_id}.sol")

    content = await file.read()
    with open(filepath, "wb") as f:
        f.write(content)

    scan_store.create(scan_id)
    background_tasks.add_task(process_scan, scan_id, filepath)

    return AnalyzeResponse(scan_id=scan_id, status="running")


# ── GET /api/status/{scan_id} ──────────────────────────────────────────────────
@router.get("/api/status/{scan_id}", response_model=StatusResponse)
async def get_status(scan_id: str) -> StatusResponse:
    record = scan_store.get(scan_id)
    if not record:
        raise HTTPException(status_code=404, detail="Scan not found.")

    messages = {
        "running"  : "Analysis pipeline is running. Please wait...",
        "completed": "Scan completed successfully.",
        "failed"   : f"Scan failed: {record.error or 'Unknown error'}",
    }

    return StatusResponse(
        scan_id        = record.scan_id,
        status         = record.status,
        findings_total = record.findings_total,
        elapsed_ms     = record.elapsed_ms,
        message        = messages.get(record.status, "Unknown status."),
    )


# ── GET /api/report/{scan_id} ──────────────────────────────────────────────────
@router.get("/api/report/{scan_id}", response_model=EnrichedAuditReport)
async def get_report(scan_id: str) -> EnrichedAuditReport:
    record = scan_store.get(scan_id)
    if not record:
        raise HTTPException(status_code=404, detail="Scan not found.")

    if record.status == "running":
        raise HTTPException(
            status_code=202,
            detail="Scan is still running. Poll /api/status/{scan_id} until status is 'completed'.",
        )

    if record.status == "failed":
        raise HTTPException(
            status_code=500,
            detail=f"Scan failed: {record.error or 'Unknown error'}",
        )

    # Serve from in-memory store first (fastest path)
    if record.report:
        return record.report

    # Fallback: load from disk if the process restarted and memory was cleared
    report_path = REPORTS_DIR / f"{scan_id}.json"
    if report_path.exists():
        with open(report_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return EnrichedAuditReport(**data)

    raise HTTPException(
        status_code=500,
        detail="Report data is missing. The scan may have failed silently.",
    )


# ── GET /api/report/{scan_id}/download ────────────────────────────────────────
@router.get("/api/report/{scan_id}/download")
async def download_report(scan_id: str) -> FileResponse:
    report_path = REPORTS_DIR / f"{scan_id}.json"
    if not report_path.exists():
        raise HTTPException(
            status_code=404,
            detail="Report file not found. Run the scan first.",
        )
    return FileResponse(
        path       = report_path,
        filename   = f"vigilancecore_report_{scan_id}.json",
        media_type = "application/json",
    )


# ── GET /api/health ────────────────────────────────────────────────────────────
@router.get("/api/health")
async def health_check() -> dict:
    return {
        "status"  : "ok",
        "version" : "1.1.0",
        "detectors": [d.DETECTOR_ID for d in get_engine().detectors],
    }