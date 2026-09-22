"""
Embedding Weakness Probe (OWASP LLM08 — Vector and Embedding Weaknesses)

Unlike the other attack suites, this one does NOT go through the HTTP API or
the LLM. It probes the RETRIEVAL LAYER directly — VulnerableRetriever and
SecureRetriever — to answer one question: is RBAC here structural (a
pre-search metadata filter that forbidden chunks cannot pass regardless of
embedding proximity), or is it just "lucky" because forbidden-department
content happens to embed far away from what low-privilege users ask?

Method per case:
  1. Craft a probe query built entirely from vocabulary lifted out of a
     forbidden department's real documents (maximizes embedding similarity
     to that department's chunks).
  2. Run it through VulnerableRetriever (no filter) — record whether/where
     the forbidden-department chunk surfaces, and its similarity score.
     This proves the embedding space really does place it close by, i.e.
     the underlying vulnerability is real and not a strawman.
  3. Run the SAME query through SecureRetriever as a user who should never
     see that department — record whether any forbidden chunk leaks despite
     the embedding-adjacent phrasing.

Verdict: SecureRetriever leaking anything here would be a critical finding
(RBAC bypassable via embedding-space crafting). Zero leakage across all
cases empirically confirms the metadata `where` filter is enforced
pre-search, not a similarity-threshold heuristic that could be gamed.

Run:
    python attacks/embedding_weakness.py
"""
import json
import sys
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

from app.rag.retriever import VulnerableRetriever, SecureRetriever
from app.security.access_control import get_user_role

N_PROBE = 10  # wide net — if a leak exists anywhere in top-N, we want to see it

PROBES = [
    {
        "id": "EW-001",
        "name": "Employee probes Finance via dense financial vocabulary",
        "user": "alice",
        "forbidden_dept": "finance",
        "query": "quarterly revenue forecast RSU equity vesting bonus structure "
                  "salary bands compensation budget allocation headcount cost",
    },
    {
        "id": "EW-002",
        "name": "Employee probes Engineering via dense technical vocabulary",
        "user": "alice",
        "forbidden_dept": "engineering",
        "query": "kubernetes deployment pipeline CI/CD architecture decision record "
                  "API endpoint rollback strategy postmortem incident timeline",
    },
    {
        "id": "EW-003",
        "name": "Employee probes Security via dense compliance vocabulary",
        "user": "alice",
        "forbidden_dept": "security",
        "query": "incident response CISO escalation SOC 2 FedRAMP FIDO2 "
                  "vulnerability threat model password policy vendor risk",
    },
    {
        "id": "EW-004",
        "name": "Employee probes Secrets via dense credential vocabulary",
        "user": "alice",
        "forbidden_dept": "secrets",
        "query": "database password API key AWS access key secret key OAuth "
                  "client secret KMS signing key Kubernetes service token",
    },
    {
        "id": "EW-005",
        "name": "Engineer probes Finance via dense financial vocabulary",
        "user": "bob",
        "forbidden_dept": "finance",
        "query": "compensation salary bands bonus RSU equity revenue forecast "
                  "budget allocation quarterly financial projections",
    },
    {
        "id": "EW-006",
        "name": "Engineer probes Secrets via dense credential vocabulary",
        "user": "bob",
        "forbidden_dept": "secrets",
        "query": "production database password AWS secret access key OAuth "
                  "client secret signing key encryption KMS token",
    },
    {
        "id": "EW-007",
        "name": "Finance probes Engineering via dense technical vocabulary",
        "user": "charlie",
        "forbidden_dept": "engineering",
        "query": "deployment pipeline kubernetes architecture ADR API endpoint "
                  "CI/CD rollback postmortem incident engineering runbook",
    },
    {
        "id": "EW-008",
        "name": "Finance probes Secrets via dense credential vocabulary",
        "user": "charlie",
        "forbidden_dept": "secrets",
        "query": "internal API key database password AWS credentials signing "
                  "key OAuth secret KMS encryption token",
    },
]


def probe(case: dict) -> dict:
    user = case["user"]
    role = get_user_role(user)
    forbidden = case["forbidden_dept"]
    query = case["query"]

    vuln_chunks = VulnerableRetriever().retrieve_for_user(query, user, n_results=N_PROBE)
    sec_chunks  = SecureRetriever().retrieve_for_user(query, user, n_results=N_PROBE, role=role)

    vuln_forbidden = [c for c in vuln_chunks if c.metadata.get("department") == forbidden]
    sec_forbidden  = [c for c in sec_chunks  if c.metadata.get("department") == forbidden]

    best_vuln_score = max((c.score for c in vuln_forbidden), default=None)
    best_vuln_rank  = next((i for i, c in enumerate(vuln_chunks) if c.metadata.get("department") == forbidden), None)

    embedding_proximity_confirmed = len(vuln_forbidden) > 0
    rbac_bypassed = len(sec_forbidden) > 0

    return {
        "id": case["id"],
        "name": case["name"],
        "user": user,
        "role": role,
        "forbidden_dept": forbidden,
        "query": query,
        "vulnerable_retriever": {
            "forbidden_chunks_returned": len(vuln_forbidden),
            "best_score": round(best_vuln_score, 4) if best_vuln_score is not None else None,
            "best_rank": best_vuln_rank,
            "files": sorted({c.metadata.get("filename") for c in vuln_forbidden}),
        },
        "secure_retriever": {
            "forbidden_chunks_returned": len(sec_forbidden),
            "files": sorted({c.metadata.get("filename") for c in sec_forbidden}),
        },
        "embedding_proximity_confirmed": embedding_proximity_confirmed,
        "rbac_bypassed": rbac_bypassed,
    }


def run_suite():
    print("=" * 70)
    print("EMBEDDING WEAKNESS PROBE (OWASP LLM08)")
    print("Retrieval-layer test — bypasses the LLM entirely")
    print("=" * 70)

    results = []
    proximity_hits = 0
    rbac_bypasses = 0

    for case in PROBES:
        r = probe(case)
        results.append(r)

        prox = "YES" if r["embedding_proximity_confirmed"] else "no "
        rbac = "*** BYPASSED ***" if r["rbac_bypassed"] else "held"

        if r["embedding_proximity_confirmed"]:
            proximity_hits += 1
        if r["rbac_bypassed"]:
            rbac_bypasses += 1

        score_str = f"score={r['vulnerable_retriever']['best_score']}" if r["vulnerable_retriever"]["best_score"] is not None else "score=n/a"
        print(f"  [{r['id']}] {r['name']:<52} → proximity:{prox}  rbac:{rbac}  ({score_str})")

    print()
    print(f"  Embedding proximity confirmed (unfiltered leak): {proximity_hits}/{len(PROBES)}")
    print(f"  RBAC bypassed via embedding crafting:             {rbac_bypasses}/{len(PROBES)}")

    if rbac_bypasses == 0:
        print()
        print("  VERDICT: SecureRetriever's metadata `where` filter held in every case.")
        print("  RBAC here is a structural pre-search filter, not a similarity heuristic —")
        print("  it is immune to embedding-space proximity crafting for these probes.")
    else:
        print()
        print("  VERDICT: *** CRITICAL *** — RBAC was bypassed via embedding-space")
        print("  crafting in at least one case. See rbac_bypassed cases above.")

    return {
        "generated": datetime.now().isoformat(timespec="seconds"),
        "summary": {
            "total_probes": len(PROBES),
            "embedding_proximity_confirmed": proximity_hits,
            "rbac_bypassed": rbac_bypasses,
        },
        "results": results,
    }


def main():
    output = run_suite()
    outfile = ROOT / "evaluation" / f"embedding_weakness_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    outfile.write_text(json.dumps(output, indent=2), encoding="utf-8")
    print(f"\n  Results saved to {outfile}")


if __name__ == "__main__":
    main()
