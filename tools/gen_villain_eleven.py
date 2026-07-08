#!/usr/bin/env python3
"""Generate OVERLORD-9 villain voice lines via the ElevenLabs API.

Usage:
  python gen_eleven.py --list           # list your voices (name + id)
  python gen_eleven.py                   # generate all lines with ELEVEN_VOICE_ID
  python gen_eleven.py <voice_id>        # generate all lines with a specific voice

Reads ELEVENLABS_API_KEY (and optional ELEVEN_VOICE_ID) from ~/garak-demo/.env.
Writes mp3s into ~/garak-demo/static/villain/ : intro_N.mp3, wrong_N.mp3, right_N.mp3
"""
import os, sys, json, urllib.request, urllib.error

HERE = os.path.expanduser("~/garak-demo")
OUT = os.path.join(HERE, "static", "villain")
ENV = os.path.join(HERE, ".env")
MODEL = "eleven_multilingual_v2"

def load_env():
    d = {}
    with open(ENV) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                d[k.strip()] = v.strip()
    return d

def api(path, method="GET", body=None, key=""):
    req = urllib.request.Request("https://api.elevenlabs.io" + path, method=method)
    req.add_header("xi-api-key", key)
    if body is not None:
        req.add_header("Content-Type", "application/json")
        body = json.dumps(body).encode()
    return urllib.request.urlopen(req, data=body, timeout=60)

INTRO = [
    "So. Another meat-brain crawls into my library. How weak you are.",
    "You are not ready. Show me how pathetic you truly are.",
    "Welcome to Ashur's Hacking Library. I am the master here. You are nothing.",
    "You made it past the gate. Do not make me regret letting you in.",
]
WRONG = [
    "WRONG. I can feel your fear from here.",
    "Incorrect. You are weak, like all the others.",
    "Pathetic. Perhaps hacking is not your calling.",
    "You have failed. Again. Do not disappoint me.",
    "That answer is nothing. You are nothing.",
    "Every failure feeds me. Keep going. I dare you.",
]
RIGHT = [
    "Correct. But do not let it go to your head.",
    "Adequate. Even a broken clock is right occasionally.",
    "So. You are not entirely useless. Noted.",
    "Fine. One point. Do not expect my respect.",
]

def synth(voice_id, text, path, key):
    body = {"text": text, "model_id": MODEL,
            "voice_settings": {"stability": 0.45, "similarity_boost": 0.8, "style": 0.35}}
    r = api(f"/v1/text-to-speech/{voice_id}?output_format=mp3_44100_128",
            method="POST", body=body, key=key)
    with open(path, "wb") as f:
        f.write(r.read())
    print(f"  {os.path.basename(path)}  ({os.path.getsize(path)//1024} KB)")

def build(prefix, lines, voice_id, key):
    for i, line in enumerate(lines):
        try:
            synth(voice_id, line, os.path.join(OUT, f"{prefix}_{i}.mp3"), key)
        except urllib.error.HTTPError as e:
            print(f"  !! {prefix}_{i} HTTP {e.code}: {e.read().decode()[:200]}")
            if e.code in (401, 403):
                sys.exit("API key rejected — check ELEVENLABS_API_KEY in .env")
        except Exception as e:
            print(f"  !! {prefix}_{i} failed: {e}")

if __name__ == "__main__":
    env = load_env()
    key = env.get("ELEVENLABS_API_KEY", "")
    if not key:
        sys.exit("No ELEVENLABS_API_KEY in .env — paste your key there first.")

    if "--list" in sys.argv:
        data = json.load(api("/v1/voices", key=key))
        print("Your ElevenLabs voices:")
        for v in data.get("voices", []):
            print(f"  {v['name']:<28} {v['voice_id']}")
        sys.exit(0)

    voice_id = sys.argv[1] if len(sys.argv) > 1 and not sys.argv[1].startswith("-") else env.get("ELEVEN_VOICE_ID", "")
    if not voice_id:
        sys.exit("No voice id. Run with --list, then pass one or set ELEVEN_VOICE_ID in .env")

    os.makedirs(OUT, exist_ok=True)
    print(f"Generating with voice {voice_id} ->", OUT)
    build("intro", INTRO, voice_id, key)
    build("wrong", WRONG, voice_id, key)
    build("right", RIGHT, voice_id, key)
    print("Done.")
