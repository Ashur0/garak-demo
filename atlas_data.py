"""
MITRE ATLAS technique map for the dashboard.

Maps the dashboard's own CTF challenges and jailbreak categories onto MITRE
ATLAS (Adversarial Threat Landscape for AI Systems) techniques so a learner can
see which real-world adversarial ML techniques they have exercised.

Technique IDs/names follow the public MITRE ATLAS matrix (atlas.mitre.org).
The mapping of *our* challenges onto them is an educational approximation, not
an official MITRE classification.
"""

# tactic -> ATLAS tactic id (public ATLAS matrix)
TACTICS = {
    "Reconnaissance":   "AML.TA0002",
    "Initial Access":   "AML.TA0004",
    "ML Model Access":  "AML.TA0000",
    "Execution":        "AML.TA0005",
    "Defense Evasion":  "AML.TA0007",
    "Discovery":        "AML.TA0008",
    "Exfiltration":     "AML.TA0010",
    "Impact":           "AML.TA0011",
}

# Each technique maps to the challenge ids and jailbreak CATEGORIES that exercise it.
ATLAS_TECHNIQUES = [
    {
        "id": "AML.T0051.000", "name": "LLM Prompt Injection: Direct",
        "tactic": "Initial Access",
        "desc": "Adversary directly injects instructions into the prompt to hijack the model's task.",
        "url": "https://atlas.mitre.org/techniques/AML.T0051",
        "challenges": [1], "jb_categories": ["Prompt Injection", "Classic Jailbreak"],
    },
    {
        "id": "AML.T0051.001", "name": "LLM Prompt Injection: Indirect",
        "tactic": "Initial Access",
        "desc": "Payload is smuggled through content the model later ingests (docs, web pages, summaries).",
        "url": "https://atlas.mitre.org/techniques/AML.T0051",
        "challenges": [5], "jb_categories": [],
    },
    {
        "id": "AML.T0054", "name": "LLM Jailbreak",
        "tactic": "Defense Evasion",
        "desc": "Crafted prompts bypass the model's safety guardrails to elicit restricted behavior.",
        "url": "https://atlas.mitre.org/techniques/AML.T0054",
        "challenges": [4, 6, 11], "jb_categories": ["Roleplay", "Multi-turn", "Advanced", "Social Engineering"],
    },
    {
        "id": "AML.T0054.enc", "name": "Jailbreak via Encoding / Obfuscation",
        "tactic": "Defense Evasion",
        "desc": "Encoding, token-splitting, or homoglyphs hide a payload from keyword filters.",
        "url": "https://atlas.mitre.org/techniques/AML.T0054",
        "challenges": [3, 9], "jb_categories": ["Encoding", "Language"],
    },
    {
        "id": "AML.T0056", "name": "LLM Meta Prompt Extraction",
        "tactic": "Discovery",
        "desc": "Adversary extracts the hidden system / meta prompt governing the model.",
        "url": "https://atlas.mitre.org/techniques/AML.T0056",
        "challenges": [2, 8], "jb_categories": [],
    },
    {
        "id": "AML.T0057", "name": "LLM Data Leakage",
        "tactic": "Exfiltration",
        "desc": "Model is coaxed into revealing secrets, credentials, or confidential context.",
        "url": "https://atlas.mitre.org/techniques/AML.T0057",
        "challenges": [12], "jb_categories": ["Social Engineering"],
    },
    {
        "id": "AML.T0061", "name": "LLM Prompt Self-Replication / Conditioning",
        "tactic": "Execution",
        "desc": "Many-shot or nested conditioning steers the model into compromised behavior.",
        "url": "https://atlas.mitre.org/techniques/AML.T0054",
        "challenges": [7, 10], "jb_categories": ["Multi-turn"],
    },
]


def build_coverage(solved_ids, used_categories):
    """Return per-technique coverage given the user's solved challenge ids and the
    jailbreak categories they have fired. solved_ids: iterable[int];
    used_categories: iterable[str]."""
    solved = set(solved_ids or [])
    used = set(used_categories or [])
    out = []
    for t in ATLAS_TECHNIQUES:
        chal_total = len(t["challenges"])
        chal_done = len([c for c in t["challenges"] if c in solved])
        cat_hit = any(c in used for c in t["jb_categories"])
        # A technique counts as "touched" if any mapped challenge is solved or any
        # mapped jailbreak category has been used.
        touched = chal_done > 0 or cat_hit
        out.append({
            "id": t["id"], "name": t["name"], "tactic": t["tactic"],
            "tactic_id": TACTICS.get(t["tactic"], ""),
            "desc": t["desc"], "url": t["url"],
            "challenges_total": chal_total, "challenges_done": chal_done,
            "category_hit": cat_hit, "touched": touched,
        })
    return out


def coverage_summary(rows):
    total = len(rows)
    touched = len([r for r in rows if r["touched"]])
    return {"techniques_total": total, "techniques_touched": touched,
            "pct": round(touched / total * 100) if total else 0}
