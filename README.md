# LinkLens: read the link before you click it

team members : Aya Mellouki
               Saif-Eddine Mesfioui
               El Houcine Kharbouch

Paste a link (or a whole SMS/email) and get a red / amber / green verdict, the real domain highlighted,
every warning sign with its points, and a plain-language explanation in **English, French or Arabic**.
Everything runs on your own computer. Nothing is sent to any cloud AI.

Built for **Hack Day, Hacktoberfest 2026** (open-source AI hackathon), UM6P College of Computing.

## The open-source AI model

| | |
|---|---|
| **Model** | Qwen2.5-1.5B-Instruct (`Qwen/Qwen2.5-1.5B-Instruct`), run locally through Ollama as `qwen2.5:1.5b` |
| **License** | Apache License 2.0 |
| **Source** | https://huggingface.co/Qwen/Qwen2.5-1.5B-Instruct |

**What the model does in the solution:** the AI is the analyst. It gives the **rating** and the **explanation**.
1. The browser rules and the backend collect *evidence* (lookalike domain, new domain, redirects, pressure words...).
2. Qwen2.5-1.5B reads all the evidence plus the pasted message text and returns a **risk score (0-100)**,
   the **scam tactics** it spots (urgency, impersonation, fake prize, payment request, credential request, threat),
   and a plain-language **explanation in English, French or Arabic**.
3. The page shows the AI's rating and explanation together, with the evidence it used.

**"No warning signs" is not "safe".** Phishing sites on a brand-new domain trigger no classic rule, so the AI receives
the raw link plus plain facts (registered domain, subdomains, ending, hyphens/digits, free hosting, domain age, words in
the address, and whether the domain is a well-known official website) and is told that an *unverified* domain must
never be rated as safe. It names the red flags it found ("AI noticed...") and then gives its score.

**Guardrail (so a small model cannot be fooled or hallucinate):**
- The AI cannot rate *below* what hard evidence shows (a lookalike bank domain can never be "low risk"), and an
  **unknown** domain whose address asks for login/verify/password is never below "suspicious".
- A **well-known official domain** (list in `KNOWN_DOMAINS` in `app.py`, edit it) with no warning signs and no message
  cannot be called "dangerous".
- When this adjusts the AI, the page shows "Adjusted by safety checks".
- If Ollama is off the page says **"Unverified"** (never "Low risk") and warns that only rules were used.

## How it works

```
index.html  (rules find the evidence, instant, works offline)
   `-- POST /api/analyze  ->  app.py (FastAPI)
          1. domain age (RDAP) + redirect chain (only if the user ticks the box)
          2. Qwen2.5-1.5B via Ollama: score + tactics + explanation
          3. guardrail  ->  final rating
```

Evidence rules (transparent): lookalike domains (`paypa1`, `attijar1wafa`), brand in a subdomain, raw IP, `@` trick,
no HTTPS, long URL, stacked subdomains, punycode, suspicious TLDs, shorteners, pressure words, domain younger than
30/180 days, 3+ redirects, redirect to a different domain.

## Run it (5 minutes)

```bash
# 1. Install Ollama from https://ollama.com, then:
ollama pull qwen2.5:1.5b

# 2. Install and start LinkLens
pip install -r requirements.txt
uvicorn app:app --host 127.0.0.1 --port 8000

# 3. Open http://127.0.0.1:8000  (the model loads into memory at startup, so wait ~10 s before the first check)
```
Check how well your model judges links (rules switched off, AI only): `python evaluate.py`

Better judgment: a bigger model. 1.5B is fast but limited; 7B is much better at spotting phishing (also Apache 2.0, needs ~16 GB RAM, slower):
```bash
ollama pull qwen2.5:7b
set LINKLENS_MODEL=qwen2.5:7b            # Windows cmd   (PowerShell: $env:LINKLENS_MODEL="qwen2.5:7b")
export LINKLENS_MODEL=qwen2.5:7b         # Mac/Linux
```
The 3B model uses a different (research-only) license, so avoid it.

## Safety design

- By default **the link is never contacted**. Redirect-following is opt-in.
- When enabled, the backend blocks localhost/private/internal addresses and non-web ports (SSRF protection),
  re-checks every redirect hop, never reads page content and never runs JavaScript.
- The server only listens on 127.0.0.1. Nothing is stored. The "share a warning" button defangs the link (`hxxp`, `[.]`).

## Known limitations (honest list)

- No tool can know for sure that a brand-new domain is malicious from the address alone. LinkLens treats unverified domains with suspicion, but it can still be wrong in both directions. Never rely on it alone.
- Domain age relies on public RDAP data; some TLDs (e.g. some country domains) have none, so no flag is added.
- A 1.5B model's Arabic is decent for short advice but not perfect; the 7B model is better.
- Brand list is short (global + Moroccan brands); extend `BRANDS` in `index.html`.

## Credits

Qwen2.5 (Alibaba Cloud, Apache-2.0) · Ollama (MIT) · FastAPI · RDAP via rdap.org · Fonts: Bricolage Grotesque, IBM Plex (SIL OFL).
