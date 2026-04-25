# VigilanceCore

VigilanceCore is a modular static analysis framework for Ethereum smart contracts written in Solidity. It is designed to detect multiple classes of security vulnerabilities before deployment by combining contract parsing, Control Flow Graph (CFG) construction, Data Flow Graph (DFG) analysis, inter-procedural taint propagation, and class-specific vulnerability detectors.

The project focuses on identifying vulnerabilities such as reentrancy, access control issues, arithmetic flaws, unchecked return values, timestamp dependence, weak randomness, delegatecall misuse, denial of service, tx.origin misuse, and business logic errors.

## Features

- Static analysis of Solidity smart contracts.
- CFG and DFG construction for semantic reasoning.
- Inter-procedural taint propagation from sensitive sources to sinks.
- Modular detector architecture for multiple vulnerability classes.
- CVSS-inspired severity scoring.
- Benchmark support for SmartBugs Curated and SolidiFI datasets.
- Structured output for reporting and evaluation.

## Project Structure

```text
vigilancecore_hackathon/
├── main.py
├── config.py
├── requirements.txt
├── core/
├── detectors/
├── tests/
├── reports/
├── patches/
├── research paper/
└── README.md
```

## Core Components

### `main.py`
Entry point of the project. Starts the analysis pipeline and runs the scanner.

### `core/analysis_engine.py`
Orchestrates the entire analysis process, including parsing, graph construction, taint analysis, detector execution, and result aggregation.

### `core/slither_wrapper.py`
Integrates the project with Slither and handles compiler interaction.

### `core/contract_parser.py`
Extracts contract metadata such as functions, state variables, modifiers, and inheritance.

### `core/cfg_builder.py`
Builds Control Flow Graphs and Data Flow Graphs for each function.

### `core/taint_engine.py`
Performs taint propagation from sensitive sources to security-critical sinks.

### `detectors/`
Contains individual vulnerability detectors such as:
- reentrancy
- access control
- arithmetic
- timestamp
- randomness
- delegatecall
- DoS
- tx.origin
- unchecked return values
- logic/business errors

## Installation

### Prerequisites
- Python 3.13 or compatible version
- Git
- Solidity compiler support via `py-solc-x`
- Slither installed in the Python environment

### Setup
```powershell
git clone https://github.com/chetanagrawal721/vigilancecore_hackathon.git
cd vigilancecore_hackathon
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

### Install Solidity compiler
```powershell
python -c "import solcx; solcx.install_solc('0.8.21')"
```

## Usage

Run the main analysis script:

```powershell
python main.py
```

To analyze a specific Solidity file, update the input path in the configuration or runner script depending on your setup.

## Test Contracts

The project includes test contracts under `tests/contracts/`:
- `bank.sol`
- `token.sol`
- `safe_token.sol`

These are used to validate the analysis pipeline and detector behavior.

## Benchmarking

The project supports benchmark evaluation through scripts such as:
- `benchmark_runner.py`
- `messiq_runner.py`
- `metrics.py`

Results are stored under `reports/` and may include CSV and JSON outputs.

## Output

The analysis engine produces:
- vulnerability type
- severity
- confidence
- source line number
- a structured summary of findings

## Limitations

- Cross-contract analysis is limited.
- Some detectors may produce false positives.
- Results depend on compiler compatibility and source code quality.
- Complex application-specific business logic may require further refinement.

## Future Work

- Cross-contract vulnerability detection.
- Better reentrancy handling across function boundaries.
- Precision improvement for false-positive reduction.
- Machine learning-based confidence scoring.
- Multi-file contract support.

## Research Background

VigilanceCore is designed as a research-oriented smart contract security framework and is evaluated using benchmark datasets such as SmartBugs Curated and SolidiFI.

## License

[MIT License](LICENSE) *(Update as needed)*

## Contact

**Chetan Agrawal** - [GitHub Profile](https://github.com/chetanagrawal721)
