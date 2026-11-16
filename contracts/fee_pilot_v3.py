# { "Depends": "py-genlayer:1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6" }

"""FeePilot v3: delegated execution budgets with consensus-bound spend receipts."""

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


class FeePilotV3(gl.Contract):
    """A payable GEN budget with per-executor caps and final spend records."""

    budget_count: u64
    spend_count: u64
    budgets: TreeMap[str, str]
    spends: TreeMap[str, str]
    budget_ids: DynArray[str]
    spend_ids: DynArray[str]

    def __init__(self):
        self.budget_count = u64(0)
        self.spend_count = u64(0)

    @gl.public.view
    def get_budget(self, budget_id: str) -> str:
        return self.budgets.get(budget_id.strip(), "")

    @gl.public.view
    def get_spend(self, spend_id: str) -> str:
        return self.spends.get(spend_id.strip(), "")

    @gl.public.view
    def list_budget_ids(self, offset: u64, limit: u64) -> str:
        return _page(self.budget_ids, offset, limit)

    @gl.public.view
    def list_spend_ids(self, offset: u64, limit: u64) -> str:
        return _page(self.spend_ids, offset, limit)

    @gl.public.view
    def preview_budget_id(self, owner: str, policy_url: str, expires_at: u64, creation_nonce: str) -> str:
        return _budget_id(str(Address(owner)).lower(), _https_url(policy_url), int(expires_at), _digest(creation_nonce))

    @gl.public.view
    def preview_spend_id(self, budget_id: str, executor: str, amount_gen_wei: u256, action_scope: str, payload_hash: str, evidence_url: str, spend_nonce: str) -> str:
        budget = _budget(self.budgets, budget_id)
        request = _canonical_request(budget["budget_id"], executor, int(amount_gen_wei), action_scope, payload_hash, evidence_url, spend_nonce, budget["policy_url"])
        return "fps_" + _sha256(_canonical_json(request))[:20]

    @gl.public.write.payable
    def create_delegated_budget(self, policy_url: str, expires_at: u64, creation_nonce: str) -> str:
        if gl.message.value == u256(0):
            raise Exception("positive_budget_required")
        now, expires = _now(), int(expires_at)
        if now <= 0 or expires <= now or expires > now + 2_592_000:
            raise Exception("invalid_budget_expiry")
        owner = str(gl.message.sender_address).lower()
        policy, nonce = _https_url(policy_url), _digest(creation_nonce)
        budget_id = _budget_id(owner, policy, expires, nonce)
        if self.budgets.get(budget_id, ""):
            raise Exception("creation_nonce_already_used")
        self.budget_count = u64(int(self.budget_count) + 1)
        budget = {
            "schema_version": "feepilot.v3",
            "budget_id": budget_id,
            "sequence": int(self.budget_count),
            "owner": owner,
            "policy_url": policy,
            "policy_commitment": _sha256(policy),
            "reserved_gen_wei": str(gl.message.value),
            "spent_gen_wei": "0",
            "refunded_gen_wei": "0",
            "expires_at": expires,
            "status": "open",
            "creation_nonce": nonce,
            "executors": {},
            "created_at": now,
        }
        self.budgets[budget_id] = _canonical_json(budget)
        self.budget_ids.append(budget_id)
        return budget_id

    @gl.public.write
    def grant_executor(self, budget_id: str, executor: str, allowance_gen_wei: u256) -> None:
        budget = _budget(self.budgets, budget_id)
        _only_owner(budget)
        _active(budget)
        allowance = int(allowance_gen_wei)
        if allowance <= 0:
            raise Exception("positive_allowance_required")
        address = str(Address(executor)).lower()
        current = budget["executors"].get(address, {"allowance_gen_wei": "0", "spent_gen_wei": "0", "revoked": False})
        used_by_others = sum(int(v["allowance_gen_wei"]) for key, v in budget["executors"].items() if key != address and not v.get("revoked", False))
        if used_by_others + allowance > int(budget["reserved_gen_wei"]):
            raise Exception("executor_allowances_exceed_budget")
        if int(current["spent_gen_wei"]) > allowance:
            raise Exception("allowance_below_already_spent")
        budget["executors"][address] = {"allowance_gen_wei": str(allowance), "spent_gen_wei": current["spent_gen_wei"], "revoked": False, "granted_at": _now()}
        self.budgets[budget["budget_id"]] = _canonical_json(budget)

    @gl.public.write
    def revoke_executor(self, budget_id: str, executor: str) -> None:
        budget = _budget(self.budgets, budget_id)
        _only_owner(budget)
        _active(budget)
        address = str(Address(executor)).lower()
        entry = budget["executors"].get(address)
        if not entry:
            raise Exception("unknown_executor")
        entry["revoked"] = True
        entry["revoked_at"] = _now()
        budget["executors"][address] = entry
        self.budgets[budget["budget_id"]] = _canonical_json(budget)

    @gl.public.write
    def authorize_spend(self, budget_id: str, amount_gen_wei: u256, action_scope: str, payload_hash: str, evidence_url: str, spend_nonce: str) -> str:
        budget = _budget(self.budgets, budget_id)
        _active(budget)
        sender, amount = str(gl.message.sender_address).lower(), int(amount_gen_wei)
        if amount <= 0:
            raise Exception("positive_spend_required")
        executor = budget["executors"].get(sender)
        if not executor or executor.get("revoked", False):
            raise Exception("only_active_executor_can_authorize")
        if int(executor["spent_gen_wei"]) + amount > int(executor["allowance_gen_wei"]):
            raise Exception("executor_allowance_exceeded")
        if int(budget["spent_gen_wei"]) + amount > int(budget["reserved_gen_wei"]):
            raise Exception("budget_remaining_exceeded")
        request = _canonical_request(budget["budget_id"], sender, amount, action_scope, payload_hash, evidence_url, spend_nonce, budget["policy_url"])
        spend_id = "fps_" + _sha256(_canonical_json(request))[:20]
        if self.spends.get(spend_id, ""):
            raise Exception("spend_nonce_already_used")

        def leader_fn():
            return _canonical_json(_assess(request, budget["policy_commitment"]))

        def validator_fn(leader_result) -> bool:
            if not isinstance(leader_result, gl.vm.Return):
                return False
            try:
                proposed = _parse_assessment(leader_result.calldata, request)
                independent = _parse_assessment(_canonical_json(_assess(request, budget["policy_commitment"])), request)
                return all(proposed[k] == independent[k] for k in ("decision", "reason_code", "request_hash", "policy_snapshot_hash", "evidence_snapshot_hash", "bundle_hash"))
            except Exception:
                return False

        assessed = _parse_assessment(gl.vm.run_nondet_unsafe(leader_fn, validator_fn), request)
        spend = {"schema_version": "feepilot.v3", "spend_id": spend_id, "request": request, "request_hash": assessed["request_hash"], "decision": assessed["decision"], "reason_code": assessed["reason_code"], "policy_snapshot_hash": assessed["policy_snapshot_hash"], "evidence_snapshot_hash": assessed["evidence_snapshot_hash"], "bundle_hash": assessed["bundle_hash"], "status": "authorized" if assessed["decision"] == "approved" else "blocked", "settlement": {}, "created_at": _now()}
        self.spend_count = u64(int(self.spend_count) + 1)
        self.spends[spend_id] = _canonical_json(spend)
        self.spend_ids.append(spend_id)
        return spend_id

    @gl.public.write
    def settle_authorized_spend(self, spend_id: str, completion_hash: str) -> None:
        spend = _load(self.spends, spend_id, "unknown_spend")
        budget = _budget(self.budgets, spend["request"]["budget_id"])
        sender, amount = str(gl.message.sender_address).lower(), int(spend["request"]["amount_gen_wei"])
        if sender != spend["request"]["executor"]:
            raise Exception("only_named_executor_can_settle")
        if spend["status"] != "authorized" or _now() <= 0 or _now() >= int(budget["expires_at"]):
            raise Exception("spend_not_settleable")
        entry = budget["executors"].get(sender)
        if not entry or entry.get("revoked", False) or int(entry["spent_gen_wei"]) + amount > int(entry["allowance_gen_wei"]):
            raise Exception("executor_not_settleable")
        if int(budget["spent_gen_wei"]) + amount > int(budget["reserved_gen_wei"]):
            raise Exception("budget_remaining_exceeded")
        completion = _digest(completion_hash)
        _Account(Address(sender)).emit_transfer(value=u256(amount))
        entry["spent_gen_wei"] = str(int(entry["spent_gen_wei"]) + amount)
        budget["executors"][sender] = entry
        budget["spent_gen_wei"] = str(int(budget["spent_gen_wei"]) + amount)
        budget["status"] = "settled" if int(budget["spent_gen_wei"]) == int(budget["reserved_gen_wei"]) else "open"
        spend["status"] = "settled"
        spend["settlement"] = {"executor": sender, "amount_gen_wei": str(amount), "completion_hash": completion, "settled_at": _now(), "settlement_hash": _sha256(_canonical_json({"spend_id": spend["spend_id"], "completion_hash": completion, "amount_gen_wei": str(amount)}))}
        self.spends[spend["spend_id"]] = _canonical_json(spend)
        self.budgets[budget["budget_id"]] = _canonical_json(budget)

    @gl.public.write
    def refund_remaining_budget(self, budget_id: str) -> None:
        budget = _budget(self.budgets, budget_id)
        sender, now = str(gl.message.sender_address).lower(), _now()
        if sender != budget["owner"] and (now <= 0 or now < int(budget["expires_at"])):
            raise Exception("only_owner_before_expiry")
        remaining = int(budget["reserved_gen_wei"]) - int(budget["spent_gen_wei"]) - int(budget["refunded_gen_wei"])
        if remaining <= 0:
            raise Exception("no_refundable_balance")
        _Account(Address(budget["owner"])).emit_transfer(value=u256(remaining))
        budget["refunded_gen_wei"] = str(int(budget["refunded_gen_wei"]) + remaining)
        budget["status"] = "closed"
        budget["closed_at"] = now
        self.budgets[budget["budget_id"]] = _canonical_json(budget)


def _assess(request: dict, policy_commitment: str) -> dict:
    policy, evidence = _render(request["policy_url"]), _render(request["evidence_url"])
    request_hash = _sha256(_canonical_json(request))
    base = {"request_hash": request_hash, "policy_snapshot_hash": policy["hash"], "evidence_snapshot_hash": evidence["hash"], "bundle_hash": _sha256(_canonical_json({"request_hash": request_hash, "policy_commitment": policy_commitment, "policy_snapshot_hash": policy["hash"], "evidence_snapshot_hash": evidence["hash"]}))}
    if not policy["readable"] or not evidence["readable"]:
        return {"decision": "inconclusive", "reason_code": "source_unavailable", **base}
    prompt = "Return minified JSON only: decision (approved|denied|inconclusive) and reason_code (approved_by_policy|policy_conflict|insufficient_evidence). Approve only if the rendered policy permits this exact bounded spend and evidence supports it."
    raw = json.loads(gl.nondet.exec_prompt(prompt + "\n" + _canonical_json({"request": request, "policy": policy["content"], "evidence": evidence["content"]})))
    decision, reason = str(raw.get("decision", "inconclusive")).lower(), str(raw.get("reason_code", "insufficient_evidence")).lower()
    if decision not in ("approved", "denied", "inconclusive") or reason not in ("approved_by_policy", "policy_conflict", "insufficient_evidence"):
        decision, reason = "inconclusive", "insufficient_evidence"
    if decision == "approved" and reason != "approved_by_policy":
        decision, reason = "inconclusive", "insufficient_evidence"
    return {"decision": decision, "reason_code": reason, **base}


def _parse_assessment(raw: str, request: dict) -> dict:
    value = json.loads(raw)
    result = {k: str(value.get(k, "")).lower() for k in ("decision", "reason_code", "request_hash", "policy_snapshot_hash", "evidence_snapshot_hash", "bundle_hash")}
    if result["decision"] not in ("approved", "denied", "inconclusive") or result["reason_code"] not in ("approved_by_policy", "policy_conflict", "insufficient_evidence", "source_unavailable"):
        raise Exception("invalid_assessment")
    if result["request_hash"] != _sha256(_canonical_json(request)):
        raise Exception("assessment_request_binding_mismatch")
    for key in ("policy_snapshot_hash", "evidence_snapshot_hash", "bundle_hash"):
        if len(result[key]) != 64 or any(c not in "0123456789abcdef" for c in result[key]):
            raise Exception("invalid_assessment_hash")
    return result


def _budget(records, budget_id: str) -> dict:
    return _load(records, budget_id, "unknown_budget")


def _only_owner(budget: dict) -> None:
    if str(gl.message.sender_address).lower() != budget["owner"]:
        raise Exception("only_budget_owner")


def _active(budget: dict) -> None:
    if budget["status"] not in ("open", "authorized") or _now() <= 0 or _now() >= int(budget["expires_at"]):
        raise Exception("budget_not_active")


def _page(items, offset: u64, limit: u64) -> str:
    start, count = int(offset), int(limit)
    if start < 0 or count < 1 or count > 50:
        raise Exception("invalid_page")
    return _canonical_json([items[i] for i in range(start, min(start + count, len(items)))])


def _load(records, record_id: str, error: str) -> dict:
    raw = records.get(record_id.strip(), "")
    if not raw:
        raise Exception(error)
    return json.loads(raw)


def _https_url(value: str) -> str:
    value = str(value).strip()
    if not value.startswith("https://") or len(value) > 500 or any(c in value for c in "\n\r\t@"):
        raise Exception("invalid_https_url")
    return value


def _clean(value: str, limit: int) -> str:
    value = " ".join(str(value).strip().split())
    if not value or len(value) > limit:
        raise Exception("invalid_text")
    return value


def _digest(value: str) -> str:
    value = str(value).strip().lower()
    if len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
        raise Exception("invalid_sha256")
    return value


def _render(url: str) -> dict:
    try:
        content = " ".join(str(gl.nondet.web.render(url, mode="text")).split())
        if len(content) < 80:
            return {"readable": False, "content": "", "hash": _sha256("SOURCE_TOO_SHORT")}
        return {"readable": True, "content": content[:12000], "hash": _sha256(content)}
    except Exception:
        return {"readable": False, "content": "", "hash": _sha256("SOURCE_UNAVAILABLE")}


def _budget_id(owner: str, policy_url: str, expires_at: int, nonce: str) -> str:
    return "fp3_" + _sha256(_canonical_json({"schema": "feepilot.budget.v3", "owner": owner, "policy_url": policy_url, "expires_at": expires_at, "nonce": nonce}))[:20]


def _canonical_request(budget_id: str, executor: str, amount: int, action_scope: str, payload_hash: str, evidence_url: str, spend_nonce: str, policy_url: str = "") -> dict:
    if amount <= 0:
        raise Exception("positive_spend_required")
    return {"budget_id": str(budget_id).strip(), "executor": str(Address(executor)).lower(), "amount_gen_wei": str(amount), "action_scope": _clean(action_scope, 180), "payload_hash": _digest(payload_hash), "policy_url": _https_url(policy_url) if policy_url else "", "evidence_url": _https_url(evidence_url), "spend_nonce": _digest(spend_nonce)}


def _canonical_json(value) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _now() -> int:
    try:
        return int(gl.block.timestamp)
    except Exception:
        return 0
