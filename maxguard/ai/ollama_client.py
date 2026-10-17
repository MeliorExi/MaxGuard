
import os
import requests

# Configure the local Ollama API address and model using environment
# variables, with defaults for local development.
OLLAMA_HOST = os.environ.get("OLLAMA_HOST", "http://127.0.0.1:11434")
MODEL = os.environ.get("MAXGUARD_MODEL", "llama3.2:3b")

PROMPT = """You are a network security analyst writing for an IT manager.
Finding: {title}
Protocol: {protocol}, destination port {dst_port}
Details: {details}
Mapped controls: {controls}

In at most 120 words explain: (1) what the risk is, (2) how an attacker could abuse it, (3) the concrete fix. Do not invent facts that are not in the finding."""

# Use a custom exception to report connection failures or invalid
# responses from the local AI service.
class AIUnavailable(RuntimeError):
    pass


# Send one security finding to Ollama and return its explanation.
# Raise AIUnavailable if the local service cannot provide a valid response.
def explain(finding: dict, timeout: int = 180) -> str:
    controls = ", ".join(
        f"{c['framework']} {c['control_id']}"
        for c in finding["controls"]
    ) or "none"

    prompt = PROMPT.format(
        title=finding["title"],
        protocol=finding["protocol"],
        dst_port=finding["dst_port"],
        details=finding["details"],
        controls=controls,
    )

    try:
        r = requests.post(
            f"{OLLAMA_HOST}/api/generate",
            timeout=timeout,
            json={
                "model": MODEL,
                "prompt": prompt,
                "stream": False,
                "options": {"temperature": 0, "seed": 42},
            },
        )
        r.raise_for_status()

    except requests.RequestException as e:
        raise AIUnavailable(
            f"Local AI is not reachable at {OLLAMA_HOST}: {e}"
        ) from e

    try:
        return r.json()["response"].strip()
    except (ValueError, KeyError, TypeError, AttributeError) as e:
        raise AIUnavailable(
            f"Invalid response from local AI at {OLLAMA_HOST}: {e}"
        ) from e


# Generate explanations for multiple findings and attach them to the
# original dictionaries. Cache results by rule_id to avoid repeating
# model requests for findings that share the same rule.
def explain_all(findings: list[dict]) -> None:
    """Fill finding['explanation'] in place. One model call per rule_id, reused."""
    cache: dict[str, str] = {}

    for f in findings:
        if f["rule_id"] not in cache:
            cache[f["rule_id"]] = explain(f)

        f["explanation"] = cache[f["rule_id"]]