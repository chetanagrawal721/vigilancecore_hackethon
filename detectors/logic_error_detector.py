"""
detectors/logic_error_detector.py

Logic Error / Semantic Vulnerability detector for VigilanceCore.

This is the novel contribution of the VigilanceCore project — Detector 10.
No existing tool (Slither, Mythril, Manticore, Echidna) attempts this.

What it detects
---------------
Mismatches between what a function's NatSpec documentation SAYS it does
and what the actual Solidity IR code DOES — semantic inconsistencies that
are syntactically valid and pass all other checks.

Examples:
  @notice Splits amount equally among all shareholders
  → code does: amount / 2         (divides by 2, not by shareholders.length)

  @notice Only the owner can call this
  → code has: no require/modifier (access check promised but absent)

  @notice Transfers the full balance to the recipient
  → code does: transfer(amount / 10)  (transfers fraction, not full balance)

  @notice Burns tokens from the sender
  → code does: adds tokens instead of subtracting

Why existing tools miss this
-----------------------------
Slither, Mythril, etc. analyse CODE only. They check properties of the
code — does it reenter? Is the return checked? — but they have zero
awareness of what the code is SUPPOSED to do. If the code is syntactically
valid and structurally sound, those tools give it a clean bill of health
even if it does the exact opposite of what its documentation claims.

NLP Architecture
----------------
This detector implements a lightweight NLP pipeline using ONLY Python
stdlib (re, difflib, collections) to ensure it runs without any
external model dependencies in constrained environments.

When SpaCy is available (pip install spacy + en_core_web_sm), the
pipeline automatically upgrades to full linguistic analysis — tokenisation,
lemmatisation, dependency parsing, and named entity recognition. The
detector degrades gracefully if SpaCy is not installed.

Two-layer pipeline:

  Layer 1 — Intent Extraction (NatSpec → Intent)
    Parse the NatSpec comment block for:
      • Action verbs  (split, transfer, burn, mint, lock, distribute)
      • Quantifiers   (all, every, equally, full, half, total, partial)
      • Actor nouns   (owner, sender, caller, recipient, shareholder)
      • Constraints   (only, never, always, at least, at most)

  Layer 2 — Code Verification (IR → Behaviour)
    Analyse the actual CFG/IR for:
      • Arithmetic patterns (what divisor is used?)
      • Access control presence (is there a guard?)
      • Transfer direction (add vs subtract)
      • Completeness (does it touch all relevant state vars?)

  Mismatch scoring
    Each intent claim is checked against actual code behaviour.
    A mismatch score [0.0–1.0] is computed for each claim.
    Findings are only raised when mismatch_score >= MISMATCH_THRESHOLD.

Detection pipeline (7 steps)
-----------------------------
  Step 1  Fast-path      — skip if no NatSpec, or NatSpec is trivially short
  Step 2  Intent extract — parse NatSpec into structured intent claims
  Step 3  Code analyse   — extract actual behaviour from CFG/IR
  Step 4  Mismatch score — compare each intent claim against code facts
  Step 5  Filter         — drop low-confidence mismatches
  Step 6  Dedup          — one finding per (claim_type, mismatch_kind)
  Step 7  Build          — Finding with safe_recommendation + safe_cvss

SpaCy integration
-----------------
  If SpaCy is installed:
    _NLPBackend = SpaCyBackend   (full lemmatisation + POS tagging)
  Else:
    _NLPBackend = RegexBackend   (regex + difflib keyword matching)

  Both backends expose the same interface:
    .extract_verbs(text)   → List[str]
    .extract_nouns(text)   → List[str]
    .extract_negations(text) → List[str]
    .lemmatize(word)       → str

Change log
----------
  v1.0.0  Initial release — covers equality/distribution mismatches,
          missing access control, transfer direction errors, full/partial
          balance mismatches. Dual-backend NLP (SpaCy / regex stdlib).
          Mismatch scoring, CVSS, taint enrichment placeholder.
"""

from __future__ import annotations

import difflib
import logging
import math
import re
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, FrozenSet, List, Optional, Set, Tuple

from core.cfg_builder import CFGGraph, DFGGraph
from core.models import (
    ContractInfo,
    Finding,
    FindingMetadata,
    FunctionInfo,
    Severity,
    VulnerabilityType,
)
from core.taint_engine import TaintResult
from detectors.base_detector import BaseDetector

logger = logging.getLogger(__name__)

# Minimum mismatch score to raise a finding
MISMATCH_THRESHOLD = 0.55

# Minimum NatSpec length to attempt analysis (chars)
MIN_NATSPEC_LEN = 20


# ---------------------------------------------------------------------------
# NLP Backend — SpaCy if available, regex stdlib fallback
# ---------------------------------------------------------------------------

class _RegexBackend:
    """
    Stdlib-only NLP backend.
    Uses regex + difflib for keyword extraction and simple lemmatisation.
    No external dependencies — always available.
    """

    # Action verbs relevant to smart contract behaviour
    _VERB_PATTERNS = re.compile(
        r"\b(split|transfer|send|burn|mint|lock|unlock|distribute|allocate"
        r"|withdraw|deposit|swap|approve|revoke|stake|unstake|claim|refund"
        r"|update|set|get|calculate|compute|return|emit|pay|charge|deduct"
        r"|add|subtract|increase|decrease|multiply|divide|check|verify"
        r"|allow|prevent|require|ensure|guarantee|enforce)\b",
        re.IGNORECASE,
    )

    # Nouns relevant to actors and objects
    _NOUN_PATTERNS = re.compile(
        r"\b(owner|sender|caller|recipient|shareholder|holder|user|admin"
        r"|balance|amount|token|supply|fund|fee|reward|penalty|allowance"
        r"|total|half|quarter|portion|fraction|percentage|ratio|share)\b",
        re.IGNORECASE,
    )

    # Negation words
    _NEG_PATTERNS = re.compile(
        r"\b(not|never|no|none|cannot|can't|won't|should not|must not"
        r"|only|exclusively|solely|restricted|forbidden|prohibited)\b",
        re.IGNORECASE,
    )

    # Simple irregular verb → base form map
    _LEMMA_MAP: Dict[str, str] = {
        "splits":       "split",   "splitting":    "split",
        "transfers":    "transfer","transferring":  "transfer","transferred": "transfer",
        "sends":        "send",    "sending":       "send",    "sent":        "send",
        "burns":        "burn",    "burning":       "burn",    "burned":      "burn",
        "mints":        "mint",    "minting":       "mint",    "minted":      "mint",
        "distributes":  "distribute","distributing":"distribute",
        "allocates":    "allocate","allocating":    "allocate",
        "withdraws":    "withdraw","withdrawing":   "withdraw","withdrew":    "withdraw",
        "deposits":     "deposit", "depositing":    "deposit", "deposited":   "deposit",
        "locks":        "lock",    "locking":       "lock",    "locked":      "lock",
        "unlocks":      "unlock",  "unlocking":     "unlock",
        "calculates":   "calculate","calculating":  "calculate",
        "ensures":      "ensure",  "ensuring":      "ensure",
        "requires":     "require", "required":      "require",
        "prevents":     "prevent", "preventing":    "prevent",
        "increases":    "increase","increasing":    "increase","increased":   "increase",
        "decreases":    "decrease","decreasing":    "decrease","decreased":   "decrease",
        "divides":      "divide",  "dividing":      "divide",  "divided":     "divide",
        "equalises":    "equalise","equalizing":    "equalize","equalised":   "equalise",
    }

    def extract_verbs(self, text: str) -> List[str]:
        return [
            self.lemmatize(m.group(1).lower())
            for m in self._VERB_PATTERNS.finditer(text)
        ]

    def extract_nouns(self, text: str) -> List[str]:
        return [m.group(1).lower() for m in self._NOUN_PATTERNS.finditer(text)]

    def extract_negations(self, text: str) -> List[str]:
        return [m.group(1).lower() for m in self._NEG_PATTERNS.finditer(text)]

    def lemmatize(self, word: str) -> str:
        return self._LEMMA_MAP.get(word.lower(), word.lower())


class _SpaCyBackend:
    """
    SpaCy-powered NLP backend — used when spacy + en_core_web_sm available.
    Provides proper tokenisation, POS tagging, and lemmatisation.
    """

    def __init__(self, nlp: Any) -> None:
        self._nlp = nlp

    def extract_verbs(self, text: str) -> List[str]:
        doc = self._nlp(text)
        return [
            token.lemma_.lower()
            for token in doc
            if token.pos_ in ("VERB", "AUX") and not token.is_stop
        ]

    def extract_nouns(self, text: str) -> List[str]:
        doc = self._nlp(text)
        return [
            token.lemma_.lower()
            for token in doc
            if token.pos_ in ("NOUN", "PROPN") and not token.is_stop
        ]

    def extract_negations(self, text: str) -> List[str]:
        doc = self._nlp(text)
        return [
            token.text.lower()
            for token in doc
            if token.dep_ == "neg" or token.text.lower() in ("not", "never", "only")
        ]

    def lemmatize(self, word: str) -> str:
        doc = self._nlp(word)
        return doc[0].lemma_.lower() if doc else word.lower()


def _load_nlp_backend() -> _RegexBackend | _SpaCyBackend:
    """
    Try to load SpaCy. Fall back to regex backend gracefully.
    Logs which backend is active so the report header can show it.
    """
    try:
        import spacy  # type: ignore
        nlp = spacy.load("en_core_web_sm")
        logger.info("LogicError: SpaCy backend active (en_core_web_sm).")
        return _SpaCyBackend(nlp)
    except Exception:
        logger.info(
            "LogicError: SpaCy not available — using regex backend. "
            "Install with: pip install spacy && python -m spacy download en_core_web_sm"
        )
        return _RegexBackend()


# Module-level singleton — loaded once, reused for every function
_NLP_BACKEND: _RegexBackend | _SpaCyBackend = _load_nlp_backend()


# ---------------------------------------------------------------------------
# Intent claim types
# ---------------------------------------------------------------------------

class _ClaimType(str, Enum):
    EQUAL_DISTRIBUTION  = "equal_distribution"   # "splits equally among all"
    FULL_TRANSFER       = "full_transfer"         # "transfers full balance"
    ACCESS_RESTRICTED   = "access_restricted"     # "only owner can call"
    BURN_OPERATION      = "burn_operation"        # "burns tokens from sender"
    MINT_OPERATION      = "mint_operation"        # "mints tokens to recipient"
    NO_FEE              = "no_fee"                # "no fee is charged"
    LOCK_OPERATION      = "lock_operation"        # "locks tokens until date"
    SPECIFIC_AMOUNT     = "specific_amount"       # "transfers exactly N tokens"
    NEVER_REVERTS       = "never_reverts"         # "always succeeds"
    ACTOR_CONSTRAINT    = "actor_constraint"      # "caller must be X"


@dataclass
class _IntentClaim:
    """One extracted claim from NatSpec."""
    claim_type:   _ClaimType
    raw_text:     str           # the original natspec sentence/phrase
    keywords:     List[str]     # verbs + nouns that triggered this claim
    negated:      bool          # "does NOT transfer" etc.
    confidence:   float         # [0,1] how confident we are this is a real claim


# ---------------------------------------------------------------------------
# Code facts extracted from IR
# ---------------------------------------------------------------------------

@dataclass
class _CodeFacts:
    """
    Actual observed behaviours extracted from the CFG/IR.
    These are compared against _IntentClaims to find mismatches.
    """
    # Arithmetic
    divisors:            List[str]    # all divisors found in IR (e.g. ["2", "length"])
    has_modulo:          bool
    has_multiplication:  bool

    # Transfer direction
    has_subtraction:     bool         # tokens/ETH leaving
    has_addition:        bool         # tokens/ETH arriving
    transfer_targets:    List[str]    # callee expressions

    # Access control
    has_require_sender:  bool         # require(msg.sender == ...)
    has_modifier:        bool         # onlyOwner etc.
    has_any_guard:       bool

    # Completeness
    uses_length:         bool         # iterates over .length (all members)
    uses_full_balance:   bool         # uses balanceOf / totalSupply / balance
    has_revert:          bool         # can revert

    # Raw IR for fallback matching
    all_stmts:           List[str]


# ---------------------------------------------------------------------------
# Module-level patterns for code fact extraction
# ---------------------------------------------------------------------------

_DIVISOR_RE   = re.compile(r"/\s*(\w[\w.]*)", re.IGNORECASE)
_MODULO_RE    = re.compile(r"%\s*\w", re.IGNORECASE)
_MUL_RE       = re.compile(r"\*\s*\w", re.IGNORECASE)
_SUB_RE       = re.compile(r"[-]?=|-=|\bSUB\b|\bsubstract\b", re.IGNORECASE)
_ADD_RE       = re.compile(r"\+=|\bADD\b|\baddition\b", re.IGNORECASE)
_REQUIRE_SENDER_RE = re.compile(
    r"(?:require|assert)\s*\([^)]*msg\.sender", re.IGNORECASE
)
_MODIFIER_RE  = re.compile(
    r"\b(?:onlyOwner|onlyAdmin|onlyRole|onlyGovernance|requiresAuth)\b",
    re.IGNORECASE,
)
_LENGTH_RE    = re.compile(r"\.length\b", re.IGNORECASE)
_BALANCE_RE   = re.compile(
    r"\b(?:balance|balanceOf|totalSupply|getBalance|_balance)\b",
    re.IGNORECASE,
)
_REVERT_RE    = re.compile(r"\b(?:revert|require|assert)\b", re.IGNORECASE)
_TRANSFER_TARGET_RE = re.compile(
    r"([\w.[\]]+)\s*\.\s*(?:transfer|send|call)\b", re.IGNORECASE
)


# ---------------------------------------------------------------------------
# Step 2 — Intent extractor
# ---------------------------------------------------------------------------

class _IntentExtractor:
    """
    Parses NatSpec text and produces a list of _IntentClaim objects.
    Each claim represents one verifiable assertion about function behaviour.
    """

    # Keyword sets for each claim type
    _EQUAL_DIST_VERBS  = {"split", "distribute", "allocate", "divide", "share"}
    _EQUAL_DIST_QUALS  = {"equal", "equally", "evenly", "proportional",
                           "fair", "same", "uniform", "all", "every"}
    _FULL_XFER_VERBS   = {"transfer", "send", "pay", "withdraw", "move"}
    _FULL_XFER_QUALS   = {"full", "entire", "whole", "all", "complete",
                           "total", "everything", "maximum", "max"}
    _ACCESS_WORDS      = {"only", "exclusively", "restricted", "authorized",
                           "authorised", "privileged", "admin", "owner",
                           "governance", "permitted", "allowed"}
    _BURN_WORDS        = {"burn", "destroy", "incinerate", "remove",
                           "eliminate", "reduce", "subtract", "deduct"}
    _MINT_WORDS        = {"mint", "create", "issue", "generate", "produce",
                           "add", "increase", "inflate"}
    _NO_FEE_WORDS      = {"free", "no fee", "zero fee", "feeless",
                           "without fee", "no charge", "no cost"}
    _LOCK_WORDS        = {"lock", "freeze", "hold", "vest", "escrow",
                           "restrict", "prevent", "block"}
    _NEVER_REVERT_WORDS = {"always succeed", "never revert", "guaranteed",
                            "cannot fail", "will not revert"}

    def extract(self, natspec: str, backend: Any) -> List[_IntentClaim]:
        claims: List[_IntentClaim] = []

        # Normalise — strip NatSpec markers
        text = self._clean_natspec(natspec)
        if len(text) < MIN_NATSPEC_LEN:
            return claims

        verbs      = set(backend.extract_verbs(text))
        nouns      = set(backend.extract_nouns(text))
        negations  = set(backend.extract_negations(text))
        has_neg    = bool(negations)
        text_lower = text.lower()

        # ── Claim: Equal distribution ────────────────────────────────
        verb_match = bool(verbs & self._EQUAL_DIST_VERBS)
        qual_match = any(q in text_lower for q in self._EQUAL_DIST_QUALS)
        if verb_match and qual_match:
            claims.append(_IntentClaim(
                claim_type = _ClaimType.EQUAL_DISTRIBUTION,
                raw_text   = text,
                keywords   = list((verbs & self._EQUAL_DIST_VERBS) |
                                  {q for q in self._EQUAL_DIST_QUALS if q in text_lower}),
                negated    = has_neg,
                confidence = self._score(verb_match, qual_match, 0.85),
            ))

        # ── Claim: Full transfer ─────────────────────────────────────
        verb_match = bool(verbs & self._FULL_XFER_VERBS)
        qual_match = any(q in text_lower for q in self._FULL_XFER_QUALS)
        if verb_match and qual_match:
            claims.append(_IntentClaim(
                claim_type = _ClaimType.FULL_TRANSFER,
                raw_text   = text,
                keywords   = list((verbs & self._FULL_XFER_VERBS) |
                                  {q for q in self._FULL_XFER_QUALS if q in text_lower}),
                negated    = has_neg,
                confidence = self._score(verb_match, qual_match, 0.80),
            ))

        # ── Claim: Access restricted ─────────────────────────────────
        access_match = any(w in text_lower for w in self._ACCESS_WORDS)
        if access_match:
            claims.append(_IntentClaim(
                claim_type = _ClaimType.ACCESS_RESTRICTED,
                raw_text   = text,
                keywords   = [w for w in self._ACCESS_WORDS if w in text_lower],
                negated    = False,
                confidence = 0.80,
            ))

        # ── Claim: Burn operation ────────────────────────────────────
        burn_match = bool(verbs & self._BURN_WORDS) or any(
            w in text_lower for w in self._BURN_WORDS
        )
        if burn_match:
            claims.append(_IntentClaim(
                claim_type = _ClaimType.BURN_OPERATION,
                raw_text   = text,
                keywords   = [w for w in self._BURN_WORDS if w in text_lower],
                negated    = has_neg,
                confidence = 0.75,
            ))

        # ── Claim: Mint operation ────────────────────────────────────
        mint_match = bool(verbs & self._MINT_WORDS) or any(
            w in text_lower for w in self._MINT_WORDS
        )
        if mint_match:
            claims.append(_IntentClaim(
                claim_type = _ClaimType.MINT_OPERATION,
                raw_text   = text,
                keywords   = [w for w in self._MINT_WORDS if w in text_lower],
                negated    = has_neg,
                confidence = 0.75,
            ))

        # ── Claim: No fee ────────────────────────────────────────────
        no_fee_match = any(w in text_lower for w in self._NO_FEE_WORDS)
        if no_fee_match:
            claims.append(_IntentClaim(
                claim_type = _ClaimType.NO_FEE,
                raw_text   = text,
                keywords   = [w for w in self._NO_FEE_WORDS if w in text_lower],
                negated    = False,
                confidence = 0.70,
            ))

        # ── Claim: Lock / freeze operation ───────────────────────────
        lock_match = bool(verbs & self._LOCK_WORDS) or any(
            w in text_lower for w in self._LOCK_WORDS
        )
        if lock_match and any(
            w in text_lower for w in {"token", "fund", "balance", "asset"}
        ):
            claims.append(_IntentClaim(
                claim_type = _ClaimType.LOCK_OPERATION,
                raw_text   = text,
                keywords   = [w for w in self._LOCK_WORDS if w in text_lower],
                negated    = has_neg,
                confidence = 0.70,
            ))

        return claims

    @staticmethod
    def _clean_natspec(natspec: str) -> str:
        """Strip NatSpec markers and normalise whitespace."""
        text = re.sub(r"/\*\*|\*/|///|/\*|\*", " ", natspec)
        text = re.sub(r"@\w+\s*", " ", text)         # @notice @dev @param etc.
        text = re.sub(r"\s+", " ", text).strip()
        return text

    @staticmethod
    def _score(v: bool, q: bool, base: float) -> float:
        return round(base * (1.0 if v else 0.7) * (1.0 if q else 0.8), 4)


# ---------------------------------------------------------------------------
# Step 3 — Code analyser
# ---------------------------------------------------------------------------

class _CodeAnalyser:
    """
    Extracts concrete behavioural facts from CFG/IR statements.
    These are objective code observations — not interpretations.
    """

    def analyse(
        self,
        cfg:     CFGGraph,
        fn_info: FunctionInfo,
    ) -> _CodeFacts:
        all_stmts: List[str] = []
        for node in cfg.ordered_nodes():
            all_stmts.extend(node.ir_stmts)

        combined = " ".join(all_stmts)

        # Divisors
        divisors = _DIVISOR_RE.findall(combined)

        # Transfer targets
        targets = [m.group(1) for m in _TRANSFER_TARGET_RE.finditer(combined)]

        # Modifiers
        has_modifier = any(
            _MODIFIER_RE.search(mod) for mod in fn_info.modifiers
        )

        return _CodeFacts(
            divisors           = divisors,
            has_modulo         = bool(_MODULO_RE.search(combined)),
            has_multiplication = bool(_MUL_RE.search(combined)),
            has_subtraction    = bool(_SUB_RE.search(combined)),
            has_addition       = bool(_ADD_RE.search(combined)),
            transfer_targets   = targets,
            has_require_sender = bool(_REQUIRE_SENDER_RE.search(combined)),
            has_modifier       = has_modifier,
            has_any_guard      = (
                bool(_REQUIRE_SENDER_RE.search(combined)) or has_modifier
            ),
            uses_length        = bool(_LENGTH_RE.search(combined)),
            uses_full_balance  = bool(_BALANCE_RE.search(combined)),
            has_revert         = bool(_REVERT_RE.search(combined)),
            all_stmts          = all_stmts,
        )


# ---------------------------------------------------------------------------
# Step 4 — Mismatch scorer
# ---------------------------------------------------------------------------

@dataclass
class _Mismatch:
    """A confirmed mismatch between one intent claim and actual code."""
    claim:          _IntentClaim
    mismatch_kind:  str          # human-readable mismatch label
    mismatch_score: float        # [0,1] how severe the mismatch is
    evidence:       str          # what the code actually does
    suggestion:     str          # what the code should do instead


class _MismatchScorer:
    """
    Compares each _IntentClaim against _CodeFacts and produces
    _Mismatch objects where they contradict each other.
    """

    def score(
        self,
        claims: List[_IntentClaim],
        facts:  _CodeFacts,
    ) -> List[_Mismatch]:
        mismatches: List[_Mismatch] = []

        for claim in claims:
            m = self._check_claim(claim, facts)
            if m is not None:
                mismatches.append(m)

        return mismatches

    def _check_claim(
        self,
        claim: _IntentClaim,
        facts: _CodeFacts,
    ) -> Optional[_Mismatch]:
        handlers = {
            _ClaimType.EQUAL_DISTRIBUTION: self._check_equal_dist,
            _ClaimType.FULL_TRANSFER:      self._check_full_transfer,
            _ClaimType.ACCESS_RESTRICTED:  self._check_access,
            _ClaimType.BURN_OPERATION:     self._check_burn,
            _ClaimType.MINT_OPERATION:     self._check_mint,
            _ClaimType.NO_FEE:             self._check_no_fee,
            _ClaimType.LOCK_OPERATION:     self._check_lock,
        }
        handler = handlers.get(claim.claim_type)
        return handler(claim, facts) if handler else None

    # ── Individual claim checkers ────────────────────────────────────

    @staticmethod
    def _check_equal_dist(
        claim: _IntentClaim, facts: _CodeFacts
    ) -> Optional[_Mismatch]:
        """
        Claim: "splits equally among all shareholders / recipients"
        Expected code: divides by .length (or similar participant count)
        Mismatch: divides by a hardcoded constant (2, 10, 100…)
        """
        if not facts.divisors:
            # No division at all — claim says distribute but code doesn't
            return _Mismatch(
                claim          = claim,
                mismatch_kind  = "equal_distribution_no_division",
                mismatch_score = 0.70,
                evidence       = "No division operation found in function body.",
                suggestion     = (
                    "The NatSpec says the function distributes equally. "
                    "The code has no division — add: amount / recipients.length"
                ),
            )

        # Check if any divisor is a hardcoded literal (not .length)
        hardcoded = [
            d for d in facts.divisors
            if re.match(r"^\d+$", d) and d != "1"
        ]
        uses_length = facts.uses_length or any(
            "length" in d.lower() for d in facts.divisors
        )

        if hardcoded and not uses_length:
            return _Mismatch(
                claim          = claim,
                mismatch_kind  = "equal_distribution_hardcoded_divisor",
                mismatch_score = 0.85,
                evidence       = (
                    f"Division by hardcoded constant(s): "
                    f"{', '.join(hardcoded)}. "
                    f"This distributes a fixed fraction, not an equal share."
                ),
                suggestion     = (
                    f"Replace '/ {hardcoded[0]}' with "
                    f"'/ recipients.length' (or the appropriate participant count) "
                    f"to distribute equally among all participants."
                ),
            )
        return None

    @staticmethod
    def _check_full_transfer(
        claim: _IntentClaim, facts: _CodeFacts
    ) -> Optional[_Mismatch]:
        """
        Claim: "transfers the full balance / entire amount"
        Mismatch: a divisor is present (transfers a fraction)
        """
        hardcoded_div = [
            d for d in facts.divisors
            if re.match(r"^\d+$", d) and d not in ("1", "0")
        ]
        if hardcoded_div:
            return _Mismatch(
                claim          = claim,
                mismatch_kind  = "full_transfer_partial_amount",
                mismatch_score = 0.80,
                evidence       = (
                    f"Transfer amount is divided by {hardcoded_div[0]} "
                    f"— only a fraction of the intended amount is sent."
                ),
                suggestion     = (
                    "Remove the division or use the full balance variable "
                    "directly (e.g. address(this).balance or balanceOf(address(this)))."
                ),
            )
        return None

    @staticmethod
    def _check_access(
        claim: _IntentClaim, facts: _CodeFacts
    ) -> Optional[_Mismatch]:
        """
        Claim: "only owner / admin can call"
        Mismatch: no require(msg.sender == owner) and no modifier
        """
        if not facts.has_any_guard:
            return _Mismatch(
                claim          = claim,
                mismatch_kind  = "access_restriction_missing",
                mismatch_score = 0.90,
                evidence       = (
                    "No access control guard found — no modifier "
                    "(onlyOwner etc.) and no require(msg.sender == ...) present."
                ),
                suggestion     = (
                    "Add the access control the NatSpec promises:\n"
                    "  modifier onlyOwner() {\n"
                    "      require(msg.sender == owner, 'Not owner'); _;\n"
                    "  }"
                ),
            )
        return None

    @staticmethod
    def _check_burn(
        claim: _IntentClaim, facts: _CodeFacts
    ) -> Optional[_Mismatch]:
        """
        Claim: "burns / destroys tokens"
        Mismatch: no subtraction found (tokens aren't being removed)
        """
        if not claim.negated and not facts.has_subtraction:
            # If only addition present — code is minting, not burning
            if facts.has_addition:
                return _Mismatch(
                    claim          = claim,
                    mismatch_kind  = "burn_adds_instead_of_subtracts",
                    mismatch_score = 0.85,
                    evidence       = (
                        "NatSpec says tokens are burned (removed), but the "
                        "code only contains addition operations — tokens are "
                        "being ADDED, not removed."
                    ),
                    suggestion     = (
                        "Replace += with -= for the token balance update, "
                        "or use the standard _burn(account, amount) pattern."
                    ),
                )
            return _Mismatch(
                claim          = claim,
                mismatch_kind  = "burn_no_subtraction",
                mismatch_score = 0.70,
                evidence       = (
                    "NatSpec describes a burn operation but no subtraction "
                    "(-= or equivalent) is present in the function body."
                ),
                suggestion     = (
                    "Add a balance subtraction: balances[account] -= amount; "
                    "and reduce totalSupply: totalSupply -= amount;"
                ),
            )
        return None

    @staticmethod
    def _check_mint(
        claim: _IntentClaim, facts: _CodeFacts
    ) -> Optional[_Mismatch]:
        """
        Claim: "mints / creates tokens"
        Mismatch: no addition found (tokens aren't being created)
        """
        if not claim.negated and not facts.has_addition:
            if facts.has_subtraction:
                return _Mismatch(
                    claim          = claim,
                    mismatch_kind  = "mint_subtracts_instead_of_adds",
                    mismatch_score = 0.85,
                    evidence       = (
                        "NatSpec says tokens are minted (created), but the "
                        "code only contains subtraction operations — tokens "
                        "are being REMOVED, not added."
                    ),
                    suggestion     = (
                        "Replace -= with += for the token balance update, "
                        "and increase totalSupply: totalSupply += amount;"
                    ),
                )
        return None

    @staticmethod
    def _check_no_fee(
        claim: _IntentClaim, facts: _CodeFacts
    ) -> Optional[_Mismatch]:
        """
        Claim: "no fee / free / zero cost"
        Mismatch: a percentage/modulo or fee variable is present
        """
        combined = " ".join(facts.all_stmts).lower()
        fee_patterns = re.compile(
            r"\b(?:fee|charge|cost|tax|levy|commission|basis_point|bps)\b",
            re.IGNORECASE,
        )
        has_fee_var = bool(fee_patterns.search(combined))
        has_fraction = bool(facts.divisors) or facts.has_modulo

        if has_fee_var or has_fraction:
            evidence = []
            if has_fee_var:
                evidence.append("fee-related variable found in IR")
            if has_fraction:
                evidence.append(
                    f"arithmetic fraction found (divisors: {facts.divisors})"
                )
            return _Mismatch(
                claim          = claim,
                mismatch_kind  = "no_fee_but_fee_present",
                mismatch_score = 0.75,
                evidence       = (
                    "NatSpec claims no fee is charged, but the code contains: "
                    + "; ".join(evidence)
                ),
                suggestion     = (
                    "Either remove the fee calculation from the code, "
                    "or update the NatSpec to document the fee correctly."
                ),
            )
        return None

    @staticmethod
    def _check_lock(
        claim: _IntentClaim, facts: _CodeFacts
    ) -> Optional[_Mismatch]:
        """
        Claim: "locks / freezes tokens"
        Mismatch: no state write or transfer present (nothing actually locked)
        """
        combined = " ".join(facts.all_stmts).lower()
        has_lock_state = re.search(
            r"\b(?:locked|frozen|lockedUntil|lockTime|vestingEnd|isLocked)\b",
            combined, re.IGNORECASE,
        )
        if not has_lock_state and not facts.has_subtraction:
            return _Mismatch(
                claim          = claim,
                mismatch_kind  = "lock_operation_no_state_change",
                mismatch_score = 0.65,
                evidence       = (
                    "NatSpec describes a lock/freeze operation but no "
                    "lock-state variable write or balance deduction found."
                ),
                suggestion     = (
                    "Add a lock state variable: "
                    "lockedUntil[account] = block.timestamp + lockDuration; "
                    "and enforce it in withdraw functions."
                ),
            )
        return None


# ---------------------------------------------------------------------------
# Internal finding data class
# ---------------------------------------------------------------------------

@dataclass
class _LogicFinding:
    """One confirmed logic error — a mismatch between docs and code."""
    mismatch:       _Mismatch
    fn_info:        FunctionInfo
    natspec_snippet: str        # first 200 chars of cleaned natspec


# ---------------------------------------------------------------------------
# Step 7 — Finding builder
# ---------------------------------------------------------------------------

class _FindingBuilder:

    def build(
        self,
        lf:               _LogicFinding,
        contract_name:    str,
        detector_id:      str,
        detector_version: str,
        recommendation:   str,
        cvss_score:       float,
    ) -> Finding:
        m  = lf.mismatch
        fn = lf.fn_info
        return Finding(
            vuln_type        = VulnerabilityType.LOGIC_ERROR,
            severity         = self._severity(m),
            contract_name    = contract_name,
            function_name    = fn.name,
            source_file      = fn.source_file,
            start_line       = fn.start_line,
            title            = self._title(m),
            description      = self._description(lf),
            recommendation   = recommendation,
            confidence       = self._confidence(m),
            cvss_score       = cvss_score,
            detector_id      = detector_id,
            detector_version = detector_version,
            metadata         = FindingMetadata(
                extra = {
                    "claim_type":        m.claim.claim_type.value,
                    "mismatch_kind":     m.mismatch_kind,
                    "mismatch_score":    m.mismatch_score,
                    "claim_keywords":    m.claim.keywords,
                    "claim_confidence":  m.claim.confidence,
                    "natspec_snippet":   lf.natspec_snippet,
                    "evidence":          m.evidence,
                    "nlp_backend":       (
                        "spacy" if isinstance(_NLP_BACKEND, _SpaCyBackend)
                        else "regex"
                    ),
                },
            ),
        )

    @staticmethod
    def _severity(m: _Mismatch) -> Severity:
        """
        Severity based on mismatch score and claim type:
          CRITICAL  — access control promised but absent (score >= 0.85)
          HIGH      — burn/mint direction reversed, or distribution wrong
          MEDIUM    — partial amount instead of full, or fee present
          LOW       — lock state missing, uncertain mismatches
        """
        score      = m.mismatch_score
        claim_type = m.claim.claim_type

        if claim_type == _ClaimType.ACCESS_RESTRICTED and score >= 0.85:
            return Severity.CRITICAL
        if score >= 0.80:
            return Severity.HIGH
        if score >= 0.65:
            return Severity.MEDIUM
        return Severity.LOW

    @staticmethod
    def _confidence(m: _Mismatch) -> float:
        # Blend mismatch_score and claim confidence
        return round(
            min(1.0, (m.mismatch_score * 0.6 + m.claim.confidence * 0.4)),
            4,
        )

    @staticmethod
    def _title(m: _Mismatch) -> str:
        kind_titles = {
            "equal_distribution_hardcoded_divisor": (
                "Logic Error: NatSpec claims equal distribution — "
                "code divides by hardcoded constant"
            ),
            "equal_distribution_no_division": (
                "Logic Error: NatSpec claims distribution — no division in code"
            ),
            "full_transfer_partial_amount": (
                "Logic Error: NatSpec claims full transfer — code transfers fraction"
            ),
            "access_restriction_missing": (
                "Logic Error: NatSpec promises access restriction — no guard in code"
            ),
            "burn_adds_instead_of_subtracts": (
                "Logic Error: NatSpec claims burn — code performs addition"
            ),
            "burn_no_subtraction": (
                "Logic Error: NatSpec claims burn — no subtraction in code"
            ),
            "mint_subtracts_instead_of_adds": (
                "Logic Error: NatSpec claims mint — code performs subtraction"
            ),
            "no_fee_but_fee_present": (
                "Logic Error: NatSpec claims no fee — fee calculation present"
            ),
            "lock_operation_no_state_change": (
                "Logic Error: NatSpec claims lock — no lock state written"
            ),
        }
        return kind_titles.get(m.mismatch_kind, f"Logic Error: {m.mismatch_kind}")

    @staticmethod
    def _description(lf: _LogicFinding) -> str:
        m  = lf.mismatch
        fn = lf.fn_info

        return (
            f"Semantic mismatch detected in function '{fn.name}'.\n\n"
            f"NatSpec documentation states:\n"
            f"  \"{lf.natspec_snippet}\"\n\n"
            f"Actual code behaviour:\n"
            f"  {m.evidence}\n\n"
            f"Claim type: {m.claim.claim_type.value}\n"
            f"Triggered by keywords: {', '.join(m.claim.keywords)}\n"
            f"Mismatch score: {m.mismatch_score:.2f} / 1.00\n"
            f"NLP backend: "
            + ("SpaCy (en_core_web_sm)"
               if isinstance(_NLP_BACKEND, _SpaCyBackend) else "Regex (stdlib)")
        )


# ---------------------------------------------------------------------------
# Public detector
# ---------------------------------------------------------------------------

class LogicErrorDetector(BaseDetector):
    """
    Novel NLP-based semantic vulnerability detector — Detector 10.

    Detects mismatches between NatSpec documentation and actual code
    behaviour. No existing tool (Slither, Mythril, Manticore) does this.

    Fires on:
      - Equal distribution claimed but hardcoded divisor used
      - Full transfer claimed but fractional amount sent
      - Access restriction documented but no guard implemented
      - Burn operation documented but addition found instead
      - Mint operation documented but subtraction found instead
      - No-fee claim but fee arithmetic present
      - Lock operation documented but no state written

    Does NOT fire on:
      - Functions with no NatSpec (nothing to compare against)
      - Functions whose NatSpec is too short to extract claims
      - Mismatches below the confidence threshold (0.55)

    NLP Backend:
      - SpaCy (en_core_web_sm) when available — best accuracy
      - Regex stdlib fallback — always available, lower accuracy
    """

    DETECTOR_ID      = "logic_error_v1"
    DETECTOR_VERSION = "1.0.0"
    VULN_TYPE        = VulnerabilityType.LOGIC_ERROR
    DEFAULT_SEVERITY = Severity.MEDIUM

    def __init__(self) -> None:
        self._intent_extractor = _IntentExtractor()
        self._code_analyser    = _CodeAnalyser()
        self._mismatch_scorer  = _MismatchScorer()
        self._finding_builder  = _FindingBuilder()

    # ------------------------------------------------------------------
    # BaseDetector abstract method implementations
    # ------------------------------------------------------------------

    def detect(
        self,
        contract:     ContractInfo,
        fn_info:      FunctionInfo,
        cfg:          CFGGraph,
        dfg:          DFGGraph,
        taint_result: Optional[TaintResult],
    ) -> List[Finding]:

        # ── Step 1: Fast-path ─────────────────────────────────────────
        natspec = fn_info.natspec or ""
        if len(natspec.strip()) < MIN_NATSPEC_LEN:
            logger.debug(
                "LogicError: '%s.%s' — no/short NatSpec, skipped.",
                contract.name, fn_info.name,
            )
            return []

        # ── Step 2: Extract intent claims from NatSpec ─────────────
        claims = self._intent_extractor.extract(natspec, _NLP_BACKEND)
        if not claims:
            logger.debug(
                "LogicError: '%s.%s' — no verifiable claims extracted.",
                contract.name, fn_info.name,
            )
            return []

        logger.debug(
            "LogicError: '%s.%s' — extracted %d claim(s): %s",
            contract.name, fn_info.name,
            len(claims), [c.claim_type.value for c in claims],
        )

        # ── Step 3: Extract code facts from CFG/IR ───────────────────
        facts = self._code_analyser.analyse(cfg, fn_info)

        # ── Step 4: Score mismatches ──────────────────────────────────
        mismatches = self._mismatch_scorer.score(claims, facts)
        if not mismatches:
            logger.debug(
                "LogicError: '%s.%s' — all claims consistent with code.",
                contract.name, fn_info.name,
            )
            return []

        # ── Step 5: Filter by threshold ───────────────────────────────
        significant = [
            m for m in mismatches
            if m.mismatch_score >= MISMATCH_THRESHOLD
        ]
        if not significant:
            return []

        # ── Step 6: Deduplication ─────────────────────────────────────
        seen:         Set[Tuple[str, str]] = set()
        deduplicated: List[_Mismatch]      = []
        for m in significant:
            key = (m.claim.claim_type.value, m.mismatch_kind)
            if key not in seen:
                seen.add(key)
                deduplicated.append(m)

        # ── Step 7: Build findings ────────────────────────────────────
        cleaned_natspec = self._intent_extractor._clean_natspec(natspec)
        snippet         = cleaned_natspec[:200].strip()

        findings: List[Finding] = []
        for m in deduplicated:
            lf      = _LogicFinding(
                mismatch        = m,
                fn_info         = fn_info,
                natspec_snippet = snippet,
            )
            context = self._build_context(lf, contract)
            finding = self._finding_builder.build(
                lf               = lf,
                contract_name    = contract.name,
                detector_id      = self.DETECTOR_ID,
                detector_version = self.DETECTOR_VERSION,
                recommendation   = self.safe_recommendation(context),
                cvss_score       = self.safe_cvss(context),
            )
            findings.append(finding)
            logger.debug(
                "LogicError: '%s.%s' — %s severity, kind='%s', score=%.2f.",
                contract.name, fn_info.name,
                finding.severity.value, m.mismatch_kind, m.mismatch_score,
            )

        return findings

    def build_recommendation(self, context: dict) -> str:
        fn_name       = context["function_name"]
        mismatch_kind = context.get("mismatch_kind", "unknown")
        suggestion    = context.get("suggestion", "")
        natspec       = context.get("natspec_snippet", "")
        evidence      = context.get("evidence", "")
        backend       = context.get("nlp_backend", "regex")

        rec = (
            f"Semantic mismatch in function '{fn_name}':\n\n"
            f"The NatSpec says: \"{natspec[:120]}\"\n"
            f"The code does:    {evidence}\n\n"
            f"Recommended fix:\n{suggestion}\n\n"
            f"Resolution options:\n"
            f"  1. Fix the CODE to match the documentation.\n"
            f"  2. Fix the DOCUMENTATION to match the code.\n"
            f"  3. If intentional, add a @dev comment explaining the discrepancy.\n"
        )

        if backend == "regex":
            rec += (
                f"\nNote: This finding was generated by the regex NLP backend. "
                f"For higher accuracy, install SpaCy:\n"
                f"  pip install spacy\n"
                f"  python -m spacy download en_core_web_sm"
            )

        return rec

    def calculate_cvss(self, context: dict) -> float:
        """
        Base: 5.0

        ┌──────────────────────────────────────────────┬───────┐
        │ Condition                                    │ Delta │
        ├──────────────────────────────────────────────┼───────┤
        │ access_restriction_missing                   │ +3.0  │
        │ burn/mint direction reversed                 │ +2.0  │
        │ equal_distribution wrong divisor             │ +1.5  │
        │ full_transfer sends fraction                 │ +1.5  │
        │ no_fee but fee present                       │ +1.0  │
        │ lock operation missing                       │ +0.5  │
        │ mismatch_score > 0.80                        │ +0.5  │
        │ external / public visibility                 │ +0.3  │
        │ spacy backend (higher confidence)            │ +0.2  │
        └──────────────────────────────────────────────┴───────┘
        """
        score         = 5.0
        mismatch_kind = context.get("mismatch_kind", "")
        mismatch_score = context.get("mismatch_score", 0.0)

        kind_deltas = {
            "access_restriction_missing":         3.0,
            "burn_adds_instead_of_subtracts":     2.0,
            "mint_subtracts_instead_of_adds":     2.0,
            "burn_no_subtraction":                1.5,
            "equal_distribution_hardcoded_divisor": 1.5,
            "equal_distribution_no_division":     1.5,
            "full_transfer_partial_amount":       1.5,
            "no_fee_but_fee_present":             1.0,
            "lock_operation_no_state_change":     0.5,
        }
        score += kind_deltas.get(mismatch_kind, 0.5)

        if mismatch_score > 0.80:
            score += 0.5
        if context.get("function_visibility") in ("external", "public"):
            score += 0.3
        if context.get("nlp_backend") == "spacy":
            score += 0.2

        return round(max(0.0, min(10.0, score)), 1)

    # ------------------------------------------------------------------
    # Context builder
    # ------------------------------------------------------------------

    @staticmethod
    def _build_context(
        lf:       _LogicFinding,
        contract: ContractInfo,
    ) -> dict:
        m  = lf.mismatch
        fn = lf.fn_info
        return {
            "contract_name":       contract.name,
            "function_name":       fn.name,
            "function_visibility": getattr(fn.visibility, "value",
                                           fn.visibility),
            "is_payable":          (
                getattr(fn.state_mutability, "value",
                        fn.state_mutability) == "payable"
            ),
            "line_number":         fn.start_line,
            "mismatch_kind":       m.mismatch_kind,
            "mismatch_score":      m.mismatch_score,
            "claim_type":          m.claim.claim_type.value,
            "claim_keywords":      m.claim.keywords,
            "evidence":            m.evidence,
            "suggestion":          m.suggestion,
            "natspec_snippet":     lf.natspec_snippet,
            "nlp_backend":         (
                "spacy" if isinstance(_NLP_BACKEND, _SpaCyBackend)
                else "regex"
            ),
        }