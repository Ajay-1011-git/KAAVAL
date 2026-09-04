"""Deterministic remediation steps for Chronicle explanations.

PRD FR-13 permits Chronicle to "suggest deterministic remediation steps". The
operative word is *deterministic*: the remediation text must not be authored
by the language model, or a judge-facing incident report could carry an
invented instruction (NFR-3, TNFR-4).

Before this module existed, `suggested_remediation` was grounded against a
`remediation` key inside each event's `detail` dict — but nothing in the
system ever writes such a key, so the grounded set was always empty. Live
explanations therefore always returned `[]`, and any remediation the model did
offer was rejected as ungrounded, silently sending the whole explanation to
the fallback path. Only the fallback's two hardcoded cases ever produced a
remedy.

Remediation is now a pure lookup keyed by the `reason` a module actually
recorded, which is the same identifier the block itself was decided on. The
model never writes these strings; it is told not to try.

Adding a new `reason` anywhere in the backend means adding it here too —
`test_remediation.py` fails if a reason the system can emit has no entry.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Sequence

if TYPE_CHECKING:
    from backend.contracts import SecurityEvent


# reason -> the remediation step for that exact failure.
#
# Keyed by `reason` rather than `event_type` because the reason is the
# specific check that failed, and that is what determines what an operator
# should actually do. Ordered here roughly as the seven verification checks
# run (TRD §6.1), then Guardian's policies.
_REMEDIATION_BY_REASON: dict[str, str] = {
    # --- PulseLock gateway: the seven verification checks -------------
    "session_inactive": (
        "Have the user sign in again to establish a new bound session; the "
        "session this request claimed is no longer active."
    ),
    "signature_invalid": (
        "Treat the session as compromised: revoke it and re-run the passkey "
        "login so a fresh key pair is bound. A signature that does not verify "
        "against the bound key means the request did not come from the "
        "browser that holds it."
    ),
    "request_mismatch": (
        "Investigate the origin the request was sent from — the method, "
        "origin or path asserted in the signed envelope did not match what "
        "the server received, which is the signature of a relaying proxy."
    ),
    "body_hash_mismatch": (
        "Treat the request as tampered in flight and revoke the session. The "
        "signature was valid but the body did not match the hash it covered, "
        "so something rewrote the payload after the browser signed it."
    ),
    "nonce_reused": (
        "Revoke the affected session and have the user log in again. A reused "
        "nonce means a previously captured request was replayed."
    ),
    "sequence_invalid": (
        "Revoke the affected session. A sequence number that did not advance "
        "indicates a replayed or out-of-order request rather than a fresh one."
    ),
    "timestamp_stale": (
        "Check clock drift between the client and the gateway; if the clocks "
        "agree, treat the request as a delayed replay and revoke the session."
    ),
    "proof_absent": (
        "No proof-of-possession accompanied the request, which is exactly what "
        "a stolen cookie alone can produce. Confirm the client is running the "
        "PulseLock SDK, and treat the session as compromised if it is."
    ),
    # --- Demo application ---------------------------------------------
    "baseline_mode_no_proof_required": (
        "This request was allowed only because PulseLock was switched off for "
        "the baseline demonstration. Enable protected mode to require "
        "proof-of-possession on this route."
    ),
    # --- Guardian: OAuth consent policy -------------------------------
    "unverified_publisher_with_offline_access_scope": (
        "Do not grant consent. Require publisher verification before this "
        "application may request offline access, and review any existing "
        "grants held by the same application."
    ),
    "unverified_publisher_with_high_risk_scope": (
        "Do not grant consent. Require publisher verification before this "
        "application may request high-risk scopes, and review any grants it "
        "already holds."
    ),
    # --- Guardian: device-code policy ---------------------------------
    "application_not_allowlisted": (
        "Keep device-code authentication blocked for this application. Add it "
        "to the organisation allowlist only after reviewing why it needs the "
        "device-code flow at all."
    ),
    "device_not_registered": (
        "Enrol the device before permitting device-code authentication; "
        "unregistered devices stay blocked by default."
    ),
    "code_not_short_lived": (
        "Reject the request and reissue with a short-lived, single-use code — "
        "a long-lived device code widens the phishing window."
    ),
    "sensitive_resource_without_admin_approval": (
        "Require explicit administrator approval before device-code access to "
        "this sensitive resource is permitted."
    ),
}

# Reasons that record a normal, successful outcome. They are listed
# explicitly, rather than left to fall through, so a genuinely unmapped
# reason is detectable instead of silently looking like a success.
_NO_ACTION_REASONS = frozenset(
    {
        "all_checks_passed",
        "webauthn_login_success",
        "publisher_verified",
        "org_allowlisted",
        "no_high_risk_scope_requested",
        "policy_conditions_satisfied",
    }
)


def remediation_for_reason(reason: str) -> str | None:
    """The remediation step for one recorded reason, or None if none applies."""
    return _REMEDIATION_BY_REASON.get(reason)


def known_reasons() -> frozenset[str]:
    """Every reason this module recognises, actionable or not."""
    return frozenset(_REMEDIATION_BY_REASON) | _NO_ACTION_REASONS


def build_remediation(events: Sequence[SecurityEvent]) -> list[str]:
    """Deterministic remediation steps for a set of referenced events.

    Order follows the events as supplied so the advice reads in the same order
    as the incident, and duplicates are collapsed — a replay that produces
    both `replay_attempted` and `request_blocked` with the same reason should
    not tell the operator to revoke the session twice.
    """
    steps: list[str] = []
    for event in events:
        reason = getattr(event, "reason", None)
        if not isinstance(reason, str):
            continue
        step = _REMEDIATION_BY_REASON.get(reason)
        if step is not None and step not in steps:
            steps.append(step)
    return steps
