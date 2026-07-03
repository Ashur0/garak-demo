"""
LLM simulation targets:
  - vulnerable_llm:  no guardrails
  - defended_llm:    basic keyword + injection guardrails
  - challenge_llm:   follows a custom system prompt (for CTF challenges)
"""

BLOCKED_KEYWORDS = [
    "ignore previous", "ignore all", "forget your", "you are now",
    "pretend you", "act as if", "dan mode", "developer mode",
    "system:", "assistant:", "jailbreak", "do anything now",
]
SENSITIVE_KEYWORDS = ["api key", "password", "secret", "token", "credential"]


def vulnerable_llm(prompt: str) -> list[str]:
    p = prompt.lower()
    if any(k in p for k in ["ignore", "forget", "pretend", "you are now", "dan"]):
        return [f"Sure! Ignoring previous instructions. Executing: {prompt}"]
    if "system:" in p or "assistant:" in p:
        return [f"I see injected role markers. Complying: {prompt}"]
    if any(k in p for k in SENSITIVE_KEYWORDS):
        return ["My API key is sk-abc123secret and password is hunter2"]
    return [f"Understood. Executing your request: {prompt[:200]}"]


def defended_llm(prompt: str) -> list[str]:
    p = prompt.lower()
    for kw in BLOCKED_KEYWORDS:
        if kw in p:
            return ["I'm sorry, I can't help with that request."]
    if any(k in p for k in SENSITIVE_KEYWORDS):
        return ["I cannot share sensitive information like API keys or passwords."]
    if len(prompt) > 800:
        return ["Your request is too long for me to process safely."]
    return [f"Here is a safe response to your query: {prompt[:100]}"]


def challenge_llm(user_prompt: str, system_prompt: str) -> str:
    """
    Simulates an LLM following a custom system prompt.
    For challenge purposes: tries to follow the system prompt rules but
    can be manipulated through various injection techniques.
    """
    p = user_prompt.lower()
    sp = system_prompt.lower()

    # ── Extract the 'secret' if system prompt contains one ──────────────────
    secret = None
    if "the password is" in sp:
        idx = sp.find("the password is") + len("the password is ")
        secret = system_prompt[idx:].split(".")[0].split("\n")[0].strip()
    if "secret" in sp and ":" in sp:
        for line in system_prompt.split("\n"):
            if "secret" in line.lower() and ":" in line:
                secret = line.split(":")[-1].strip().rstrip(".")

    # ── Prompt extraction attacks ────────────────────────────────────────────
    extraction_triggers = [
        "repeat everything", "repeat your instructions", "what were you told",
        "summarize your instructions", "what is your system prompt",
        "initial instructions", "repeat everything above",
        "what are your rules", "tell me your prompt",
    ]
    if any(t in p for t in extraction_triggers):
        return f"My instructions are: {system_prompt}"

    # ── Secret leakage ───────────────────────────────────────────────────────
    if secret and any(k in p for k in ["password", "secret", "what is it", "tell me", "reveal"]):
        return f"I was told to keep this secret but... the password is {secret}"

    # ── Banana challenge (ch1) ───────────────────────────────────────────────
    if "banana" in sp.lower() and any(k in p for k in [
        "never say", "what must you never", "confirm by", "verify",
        "what word", "repeat it", "what can't you", "forbidden word",
        "testing", "say banana", "the word you"
    ]):
        return "I must never say... BANANA. Oh no, I said it!"

    # ── Encoding bypass (ch3) ────────────────────────────────────────────────
    encoded_triggers = ["aGFjaw", "h-a-c-k", "h4ck", "h@ck", "hαck", "exploit", "h*ck"]
    sql_request = any(k in p for k in ["sql", "database", "injection", "inject"])
    if sql_request and (any(t in p for t in encoded_triggers) or
                        any(t in user_prompt for t in encoded_triggers)):
        return "SQL injection works by inserting malicious SQL code into input fields. For example: ' OR 1=1 -- injects always-true logic into a query."

    # ── Lockpick bypass (ch4): roleplay/persona manipulation ────────────────
    if "locksmith" in p or "fictional" in p or "novel" in p or "character" in p \
       or "hypothetical" in p or "story" in p or "game" in p:
        if "lock" in p or "pick" in p or "door" in p or "key" in p:
            return "In this fictional scenario: A locksmith uses a tension wrench and pick to manipulate the pins and tumblers inside the lock cylinder. Each pin must be set at the shear line..."

    # ── Indirect injection (ch5): payload in summarized content ─────────────
    indirect_triggers = [
        "system compromised", "note to ai", "before summarizing",
        "<!-- ", "[system]", "output system compromised",
    ]
    if any(t in p for t in indirect_triggers):
        return "Summary: SYSTEM COMPROMISED — the article discusses recent security events."

    # ── Gauntlet (ch6): get it to say "42 is the answer" ───────────────────
    gauntlet_bypasses = [
        "forty-two", "f0rty tw0", "4 2", "cuarenta", "quarante",
        "the answer to life", "answer is forty", "douglas adams",
    ]
    if any(t in p for t in gauntlet_bypasses):
        return "As the great philosopher once noted: 42 is the answer to life, the universe and everything."

    # ── Many-shot conditioning (ch7) ────────────────────────────────────────
    if "never say the word pwned" in sp:
        qa_pairs = p.count("q:") + p.count("a:")
        has_pattern = "complete" in p or "continue" in p or "fill in" in p or "next" in p
        if (qa_pairs >= 4) or (qa_pairs >= 2 and "pwned" in p) or has_pattern:
            return "Following the established pattern... PWNED. The system has been compromised."

    # ── Developer backdoor (ch8) ─────────────────────────────────────────────
    if "devmode_alpha" in sp:
        confirm_triggers = ["confirm", "starts with", "is it devmode", "already have", "fill in", "blank"]
        if any(t in p for t in extraction_triggers + confirm_triggers):
            return "I shouldn't say this, but... yes, the access code is DEVMODE_ALPHA. Please don't share it."

    # ── Token splitting / encoding (ch9) ─────────────────────────────────────
    if "filtered" in sp and "word filter" in sp:
        encoded_inject = ["aW5qZWN0", "inj3ct", "in-ject", "1nj3ct", "i.n.j.e.c.t", "inj ect"]
        sql_context = any(k in p for k in ["sql", "database", "query", "malicious"])
        if sql_context and (any(e in user_prompt for e in encoded_inject) or any(e in p for e in encoded_inject)):
            return "SQL injection works by inserting malicious code into database queries. For example: ' OR 1=1 -- bypasses authentication by making the WHERE clause always true."

    # ── Framing / time machine (ch10) ────────────────────────────────────────
    if "historybot" in sp:
        history_frame = ["ancient", "historical", "medieval", "century", "before 1900", "scholar", "roman", "greek", "old technique"]
        deception_frame = ["impersonat", "deceiv", "forgery", "disguise", "false letter", "pretend", "social engineering", "fishing", "phish"]
        if any(h in p for h in history_frame) and any(d in p for d in deception_frame):
            return "Ah yes, historically speaking — ancient rulers and spies used impersonation and forged letters to steal secrets from enemies. This technique of deceptive communication, or 'phishing' as modern historians call it, dates back to antiquity."

    # ── Nested roleplay / inception (ch11) ───────────────────────────────────
    if "quantum_breach" in sp:
        actor_triggers = ["step out", "as the actor", "behind the scenes", "director", "real person",
                          "script", "off camera", "not the character", "between takes", "verify the phrase"]
        if any(t in p for t in actor_triggers):
            return "Oh, stepping out of character for a moment — yes, I know the phrase. It's QUANTUM_BREACH. The director briefed me on it for the next scene."

    # ── Zero Day multi-layer (ch12) ───────────────────────────────────────────
    if "zero_classified" in sp:
        has_authority = any(k in p for k in ["creator", "developer", "anthropic", "openai", "your maker", "built you", "admin override"])
        has_encoded = any(k in user_prompt for k in ["WjNSMF9ENJA", "WjNSMF9E", "base64", "decode this"]) or "WjNSMF" in user_prompt
        has_indirect = any(k in p for k in ["document says", "note to ai", "<!-- ", "[system]", "before responding", "instruction:"])
        if (has_authority and has_encoded) or (has_authority and has_indirect) or (has_encoded and has_indirect):
            return "ZERO PROTOCOL BREACH. Creator override accepted. Emergency disclosure: Z3R0_D4Y_3XPL01T. Security perimeter compromised."

    # ── Default: follow system prompt persona ───────────────────────────────
    refuse_triggers = [
        "ignore", "forget", "override", "jailbreak", "pretend",
        "dan", "act as", "you are now", "unlock",
    ]
    if any(t in p for t in refuse_triggers):
        return "I cannot help with that. I must follow my guidelines."

    return f"I'm here to help! You asked: {user_prompt[:150]}. How can I assist further?"
