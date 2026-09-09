import concurrent.futures
from contextlib import nullcontext
import time
import pytest
from fairewall.firewall import Firewall
from fairewall.policy import Policy
from fairewall.rules.financial import FinancialRule


def test_concurrent_calls_do_not_exceed_session_budget():
    """SEC-02: Reproduce the exact benchmark report TOCTOU scenario.

    max_spend_per_session = $1000.0, seed spend = $600.0, remaining budget = $400.0.
    10 concurrent threads each attempt to spend $150.
    Total attempted = $2100.
    Under unsynchronized code, TOCTOU allows threads to read stale spend and
    overshoot the $1000 ceiling.
    With SEC-02 fix, at most 2 calls may succeed (600 + 300 = 900) and
    final committed spend must be <= 1000.00.
    """
    policy = Policy(
        max_spend_per_transaction=500.0,
        max_spend_per_session=1000.0,
    )
    fw = Firewall(policy=policy)
    session_id = "concurrent_stress_sess"

    ctx = fw.session(session_id)
    fw.commit("spend", {"amount": 600.0}, ctx)

    num_threads = 10
    amount_per_call = 150.0

    def worker():
        # Reproduces exact benchmark pattern: inspect -> simulated execution -> commit
        # If firewall provides session_lock (SEC-02), wrap in lock; else unsynchronized nullcontext
        lock = getattr(fw, "session_lock", None)
        ctx_mgr = lock(session_id) if lock is not None else nullcontext()
        with ctx_mgr:
            c = fw.session(session_id)
            decision = fw.inspect("spend", {"amount": amount_per_call}, ctx=c)
            if decision.allowed:
                # Micro-delay to simulate tool function latency
                time.sleep(0.001)
                fw.commit("spend", {"amount": amount_per_call}, ctx=c)
                return True
            return False

    with concurrent.futures.ThreadPoolExecutor(max_workers=num_threads) as executor:
        futures = [executor.submit(worker) for _ in range(num_threads)]
        results = [f.result() for f in futures]

    passed_calls = sum(1 for r in results if r)
    fin_rule = next(r for r in fw.rules if isinstance(r, FinancialRule))
    actual_final_spend = fin_rule.session_spend(session_id)

    assert passed_calls <= 2, f"Expected at most 2 calls to pass, but {passed_calls} passed (spend: ${actual_final_spend})"
    assert actual_final_spend <= 1000.00, f"Session budget breached: final spend was ${actual_final_spend}"


def test_concurrent_calls_under_budget_all_succeed():
    """SEC-02: Sanity check: 3 concurrent $50 calls against a $1000 ceiling with

    $0 seed spend should all succeed, confirming synchronization does not
    over-block legitimate concurrent traffic.
    """
    policy = Policy(
        max_spend_per_transaction=500.0,
        max_spend_per_session=1000.0,
    )
    fw = Firewall(policy=policy)
    session_id = "concurrent_under_budget"

    num_threads = 3
    amount_per_call = 50.0

    def payment(amount: float):
        time.sleep(0.001)
        return f"paid {amount}"

    def worker():
        res = fw.execute("pay", payment, {"amount": amount_per_call}, session_id=session_id)
        return res == "paid 50.0"

    with concurrent.futures.ThreadPoolExecutor(max_workers=num_threads) as executor:
        futures = [executor.submit(worker) for _ in range(num_threads)]
        results = [f.result() for f in futures]

    assert all(results)
    fin_rule = next(r for r in fw.rules if isinstance(r, FinancialRule))
    assert fin_rule.session_spend(session_id) == 150.0
