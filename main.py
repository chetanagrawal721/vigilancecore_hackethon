import logging
import traceback

logging.basicConfig(
    level=logging.DEBUG,
    format="%(levelname)s %(name)s %(message)s",
)

def main() -> None:
    print("Starting VigilanceCore...")
    try:
        from core.analysis_engine import AnalysisEngine
        print("Imported AnalysisEngine successfully")

        engine = AnalysisEngine()
        print("Engine created successfully")
        print("Loaded detectors:", engine.registered_detectors)
        print("\n── VigilanceCore Integration Tests ──\n")

        tests = [
            ("tests/contracts/bank.sol", "bank", True),
            ("tests/contracts/token.sol", "token", True),
            ("tests/contracts/safe_token.sol", "safe_token", False),
        ]

        for path, label, expect_findings in tests:
            print(f"Running: {path}")
            result = engine.analyse(path)

            has_findings = result.total_findings > 0
            status = "✅ PASS" if has_findings == expect_findings else "❌ FAIL"

            print(f"{status}  {label:20s}  findings={result.total_findings}")
            print(f"       {result.stats}")

            for f in result.findings:
                print(f"       [{f.severity.value:8s}] {f.title}")
                print(f"                CVSS: {f.cvss_score}  line: {f.start_line}")

            if result.error:
                print(f"       ERROR: {result.error}")

            print()

    except Exception as e:
        print("FATAL ERROR:", e)
        traceback.print_exc()

if __name__ == "__main__":
    main()
