#!/usr/bin/env python3
"""
CyberLens AI companion layer (v0.6) — OPTIONAL, additive, fail-safe.

The architecture rule (by design, not accident):

    The deterministic storytelling engine stays the brain and the source of
    truth. This layer only ADDS a clearly-labelled commentary section on top
    of what the rules already proved. It can never replace, override, or
    contradict the built-in explanations — and if it is missing, offline,
    slow, or broken, the tool behaves EXACTLY like v0.5.

Configure (either way — env vars win):
  1) ai_config.json next to this file:
        {"url": "https://api.groq.com/openai/v1/chat/completions",
         "key": "gsk_...", "model": "llama-3.3-70b-versatile"}
  2) environment variables:
        CYBERLENS_AI_URL, CYBERLENS_AI_KEY, CYBERLENS_AI_MODEL

Any OpenAI-compatible endpoint works: OpenAI, Groq (free tier, no card),
OpenRouter (free models), Google AI Studio gateways, or your own server
running Ollama / vLLM / LM Studio — e.g. url http://your-vps:11434/v1/chat/completions
(any key string for local Ollama).

Use:
    python3 replay.py captures/demo.pcap --ai

Without --ai — or without config — output is byte-identical to v0.5.
Pure stdlib (urllib). Never raises; never blocks the pipeline.
"""
import json
import os
import urllib.request

ROOT = os.path.dirname(os.path.abspath(__file__))
CONFIG_FILE = os.path.join(ROOT, "ai_config.json")

_active = False
_cfg = {}

SYSTEM_PROMPT = (
    "You are the optional AI companion layer of CyberLens, a security "
    "teaching tool. You will receive ONE detected network event: its raw "
    "evidence, its category and severity, and the tool's own plain-English "
    "explanation. Write 2-3 sentences that ADD something the base text does "
    "not have: the bigger picture, a memorable analogy, what typically "
    "happens next in this kind of attack chain, or one practical tip. Plain, "
    "simple English. Never contradict the evidence. Never give operational "
    "attack instructions, commands, or payloads. You comment; you do not "
    "replace the tool."
)


def _load_config():
    cfg = {}
    try:
        with open(CONFIG_FILE, "r", encoding="utf-8") as fh:
            cfg = json.load(fh)
    except (OSError, json.JSONDecodeError):
        pass
    cfg["url"] = os.environ.get("CYBERLENS_AI_URL", cfg.get("url", ""))
    cfg["key"] = os.environ.get("CYBERLENS_AI_KEY", cfg.get("key", ""))
    cfg["model"] = os.environ.get("CYBERLENS_AI_MODEL",
                                  cfg.get("model", "llama-3.3-70b-versatile"))
    return cfg


def activate():
    """Turn the layer on (reads config). Returns True if a usable endpoint
    was found; False means 'not configured' — caller should say so."""
    global _active, _cfg
    _cfg = _load_config()
    _active = bool(_cfg.get("url"))
    return _active


def deactivate():
    global _active
    _active = False


def is_active():
    return _active


def describe():
    if not _active:
        return ""
    return f"model {_cfg.get('model', '?')} via {_cfg.get('url', '?')}"


def enrich(event):
    """Return an AI commentary string for one event, or None.
    Never raises: the tool must run perfectly without this layer."""
    if not _active:
        return None
    try:
        return _ask(event)
    except Exception:
        return None          # offline, slow, malformed — silently step aside


def _ask(event):
    body = json.dumps({
        "model": _cfg.get("model", ""),
        "temperature": 0.4,
        "max_tokens": 160,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": json.dumps({
                "title": event.get("title"),
                "category": event.get("category"),
                "severity": event.get("severity"),
                "raw_evidence": event.get("raw"),
                "tool_explanation": event.get("english"),
                "defender_advice": event.get("blue"),
            })},
        ],
    }).encode()
    req = urllib.request.Request(
        _cfg["url"], data=body, method="POST",
        headers={"Content-Type": "application/json",
                 "Authorization": f"Bearer {_cfg.get('key', '')}"})
    with urllib.request.urlopen(req, timeout=8) as resp:
        data = json.loads(resp.read().decode("utf-8"))
    return data["choices"][0]["message"]["content"].strip()
