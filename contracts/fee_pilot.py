# { "Depends": "py-genlayer:1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6" }

"""FeePilot: consensus-bound, payable execution budgets for GenLayer agents."""

from genlayer import *
import hashlib
import json
import typing


@gl.evm.contract_interface
class _Account:
    class View:
        pass

    class Write:
        pass


class FeePilot(gl.Contract):
    """A one-use GEN execution budget with evidence-bound consensus authorization."""

    budget_count: u64
    latest_budget_id: str
    budgets: TreeMap[str, str]
    authorizations: TreeMap[str, str]
    budget_ids: DynArray[str]

    def __init__(self):
        self.budget_count = u64(0)
        self.latest_budget_id = ""

    @gl.public.view
    def get_budget(self, budget_id: str) -> str:
        return self.budgets.get(budget_id.strip(), "")

    @gl.public.view
    def get_authorization(self, authorization_id: str) -> str:
        return self.authorizations.get(authorization_id.strip(), "")

    @gl.public.view
    def get_latest_budget_id(self) -> str:
        return self.latest_budget_id

    @gl.public.view
    def list_budget_ids(self, offset: u64, limit: u64) -> str:
        start, count = int(offset), int(limit)
        if start < 0 or count < 1 or count > 50:
            raise Exception("invalid_page")
        return _canonical_json([self.budget_ids[i] for i in range(start, min(start + count, len(self.budget_ids)))])

    @gl.public.write.payable
    def create_budget(
        self,
        executor: str,
        action_scope: str,
        action_payload_hash: str,
        policy_url: str,
        expires_at: u64,
    ) -> str:
        if gl.message.value == u256(0):
            raise Exception("positive_gen_reserve_required")
        expires = int(expires_at)
        now = _now()
        if now <= 0 or expires <= now or expires > now + 2_592_000:
            raise Exception("invalid_budget_expiry")
        scope = _clean(action_scope, 180, "action_scope_required")
        payload_hash = _digest(action_payload_hash, "invalid_action_payload_hash")
        policy = _https_url(policy_url, "invalid_policy_url")
        owner = str(gl.message.sender_address).lower()
        executor_address = str(Address(executor)).lower()
        action = {
            "action_payload_hash": payload_hash,
            "action_scope": scope,
            "executor": executor_address,
            "owner": owner,
            "policy_url": policy,
            "schema": "feepilot.action.v1",
        }
        action_hash = _sha256(_canonical_json(action))
        self.budget_count = u64(int(self.budget_count) + 1)
        sequence = int(self.budget_count)
        budget_id = "fpb_" + _sha256_parts([action_hash, str(gl.message.value), str(expires), str(sequence)])[:20]
        budget = {
            "schema_version": "feepilot.v1",
            "budget_id": budget_id,
            "sequence": sequence,
            "owner": owner,
            "executor": executor_address,
            "canonical_action": action,
            "action_hash": action_hash,
            "policy_url": policy,
            "reserved_gen_wei": str(gl.message.value),
            "expires_at": expires,
            "status": "open",
            "authorization_id": "",
            "settlement": {},
            "created_at": now,
        }
        self.budgets[budget_id] = _canonical_json(budget)
        self.budget_ids.append(budget_id)
        self.latest_budget_id = budget_id
        return budget_id

    @gl.public.write
    def authorize_budget(self, budget_id: str, evidence_url: str) -> str:
        budget = _load(self.budgets, budget_id, "unknown_budget")
        if str(gl.message.sender_address).lower() != budget["owner"]:
            raise Exception("only_budget_owner_can_authorize")
        if budget["status"] != "open":
            raise Exception("budget_not_open")
        if _now() <= 0 or _now() >= int(budget["expires_at"]):
            raise Exception("budget_expired")
        evidence = _https_url(evidence_url, "invalid_evidence_url")
        source_context = {
            "action_hash": budget["action_hash"],
            "budget_id": budget["budget_id"],
            "evidence_url": evidence,
            "policy_url": budget["policy_url"],
            "reserved_gen_wei": budget["reserved_gen_wei"],
        }

        def leader_fn():
            return _canonical_json(_evaluate_budget(source_context))

        def validator_fn(leader_result) -> bool:
            if not isinstance(leader_result, gl.vm.Return):
                return False
            try:
                proposed = _parse_assessment(leader_result.calldata)
                independent = _parse_assessment(_canonical_json(_evaluate_budget(source_context)))
            except Exception:
                return False
            fields = ["decision", "policy_snapshot_hash", "evidence_snapshot_hash", "bundle_hash", "action_hash", "reason_code"]
            return all(proposed[field] == independent[field] for field in fields)

        assessment = _parse_assessment(gl.vm.run_nondet_unsafe(leader_fn, validator_fn))
        authorization_id = "fpa_" + _sha256_parts([budget["budget_id"], assessment["bundle_hash"], assessment["decision"]])[:20]
        authorization = {
            "authorization_id": authorization_id,
            "budget_id": budget["budget_id"],
            "action_hash": budget["action_hash"],
            "decision": assessment["decision"],
            "reason_code": assessment["reason_code"],
            "policy_snapshot_hash": assessment["policy_snapshot_hash"],
            "evidence_snapshot_hash": assessment["evidence_snapshot_hash"],
            "bundle_hash": assessment["bundle_hash"],
            "evidence_url": evidence,
            "created_at": _now(),
        }
        budget["authorization_id"] = authorization_id
        budget["status"] = "authorized" if assessment["decision"] == "approved" else "denied"
        self.authorizations[authorization_id] = _canonical_json(authorization)
        self.budgets[budget["budget_id"]] = _canonical_json(budget)
        return authorization_id

    @gl.public.write
    def settle_authorized_budget(self, budget_id: str, authorization_id: str, completion_hash: str) -> None:
        budget = _load(self.budgets, budget_id, "unknown_budget")
        authorization = _load(self.authorizations, authorization_id, "unknown_authorization")
        sender = str(gl.message.sender_address).lower()
        if sender != budget["executor"]:
            raise Exception("only_named_executor_can_settle")
        if budget["status"] != "authorized" or budget["authorization_id"] != authorization_id.strip():
            raise Exception("budget_not_authorized")
        if authorization["decision"] != "approved" or authorization["action_hash"] != budget["action_hash"]:
            raise Exception("authorization_binding_mismatch")
        if _now() <= 0 or _now() >= int(budget["expires_at"]):
            raise Exception("authorization_expired")
        completion = _digest(completion_hash, "invalid_completion_hash")
        value = u256(int(budget["reserved_gen_wei"]))
        if value == u256(0):
            raise Exception("empty_budget")
        # This transfer is the on-chain fee-reserve settlement, not a claim about an external purchase.
        _Account(Address(budget["executor"])).emit_transfer(value=value)
        budget["status"] = "settled"
        budget["settlement"] = {
            "completion_hash": completion,
            "executor": sender,
            "settled_gen_wei": str(value),
            "settled_at": _now(),
            "settlement_hash": _sha256_parts([budget["budget_id"], authorization_id, completion, str(value)]),
        }
        self.budgets[budget["budget_id"]] = _canonical_json(budget)

    @gl.public.write
    def cancel_budget(self, budget_id: str) -> None:
        budget = _load(self.budgets, budget_id, "unknown_budget")
        sender = str(gl.message.sender_address).lower()
        now = _now()
        if budget["status"] not in ("open", "denied"):
            raise Exception("budget_not_cancellable")
        if sender != budget["owner"] and (now <= 0 or now < int(budget["expires_at"])):
            raise Exception("only_owner_before_expiry")
        value = u256(int(budget["reserved_gen_wei"]))
        _Account(Address(budget["owner"])).emit_transfer(value=value)
        budget["status"] = "cancelled"
        budget["settlement"] = {"refunded_gen_wei": str(value), "cancelled_by": sender, "cancelled_at": now}
        self.budgets[budget["budget_id"]] = _canonical_json(budget)


def _evaluate_budget(context: dict) -> dict:
    policy = _render(context["policy_url"])
    evidence = _render(context["evidence_url"])
    policy_hash, evidence_hash = policy["content_hash"], evidence["content_hash"]
    bundle_hash = _sha256(_canonical_json({"action_hash": context["action_hash"], "policy": policy_hash, "evidence": evidence_hash}))
    if not policy["readable"] or not evidence["readable"]:
        return {"decision": "inconclusive", "reason_code": "source_unavailable", "policy_snapshot_hash": policy_hash, "evidence_snapshot_hash": evidence_hash, "bundle_hash": bundle_hash, "action_hash": context["action_hash"]}
    prompt = """You are a strict GenLayer fee-budget authorization judge. Use only the two rendered sources. Approve only when the policy clearly permits the exact scope and the evidence supports that execution request. Reject if either source conflicts with the action. Return minified JSON only with decision (approved|denied|inconclusive) and reason_code (approved_by_policy|policy_conflict|insufficient_evidence|unsafe_source)."""
    raw = json.loads(gl.nondet.exec_prompt(prompt + "\nContext: " + _canonical_json({"action_hash": context["action_hash"], "policy": policy["content"], "evidence": evidence["content"]})))
    decision = str(raw.get("decision", "inconclusive")).lower()
    reason = str(raw.get("reason_code", "insufficient_evidence")).lower()
    if decision not in ("approved", "denied", "inconclusive"):
        decision = "inconclusive"
    if reason not in ("approved_by_policy", "policy_conflict", "insufficient_evidence", "unsafe_source"):
        reason = "insufficient_evidence"
    if decision == "approved" and reason != "approved_by_policy":
        decision, reason = "inconclusive", "insufficient_evidence"
    return {"decision": decision, "reason_code": reason, "policy_snapshot_hash": policy_hash, "evidence_snapshot_hash": evidence_hash, "bundle_hash": bundle_hash, "action_hash": context["action_hash"]}


def _render(url: str) -> dict:
    try:
        content = " ".join(str(gl.nondet.web.render(url, mode="text")).split())
        if len(content) < 80:
            return {"readable": False, "content": "", "content_hash": _sha256("SOURCE_TOO_SHORT")}
        return {"readable": True, "content": content[:12000], "content_hash": _sha256(content)}
    except Exception:
        return {"readable": False, "content": "", "content_hash": _sha256("SOURCE_UNAVAILABLE")}


def _parse_assessment(raw: str) -> dict:
    value = json.loads(raw)
    decision = str(value.get("decision", "")).lower()
    reason = str(value.get("reason_code", "")).lower()
    if decision not in ("approved", "denied", "inconclusive") or reason not in ("approved_by_policy", "policy_conflict", "insufficient_evidence", "unsafe_source"):
        raise Exception("invalid_assessment")
    if decision == "approved" and reason != "approved_by_policy":
        raise Exception("invalid_approval")
    result = {"decision": decision, "reason_code": reason}
    for key in ("policy_snapshot_hash", "evidence_snapshot_hash", "bundle_hash", "action_hash"):
        result[key] = _digest(str(value.get(key, "")), "invalid_assessment_hash")
    return result


def _load(records, record_id: str, error: str) -> dict:
    raw = records.get(record_id.strip(), "")
    if not raw:
        raise Exception(error)
    return json.loads(raw)


def _https_url(raw: str, error: str) -> str:
    value = str(raw).strip()
    if not value.startswith("https://") or len(value) > 500 or any(char in value for char in "\n\r\t"):
        raise Exception(error)
    return value


def _clean(raw: str, limit: int, error: str) -> str:
    value = " ".join(str(raw).strip().split())
    if not value or len(value) > limit:
        raise Exception(error)
    return value


def _digest(raw: str, error: str) -> str:
    value = str(raw).strip().lower()
    if len(value) != 64 or any(char not in "0123456789abcdef" for char in value):
        raise Exception(error)
    return value


def _canonical_json(value) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _sha256_parts(parts: typing.Sequence[str]) -> str:
    return _sha256("".join(str(len(str(part))) + ":" + str(part) for part in parts))


def _now() -> int:
    try:
        return int(gl.block.timestamp)
    except Exception:
        return 0
