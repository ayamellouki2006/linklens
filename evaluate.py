"""
Check how well YOUR local model judges links. Run while the server is running:
    python evaluate.py
It sends each link with the browser rules switched off (rules_score=0), so only the AI + backend facts decide.
All phishing-looking links below are made-up patterns. NEVER open them.
"""
import sys
import requests

URL = "http://127.0.0.1:8000/api/analyze"
PHISHING = [
    "https://paypal.com.secure-login.verify-account.top/signin",
    "https://attijariwafa-bank-maroc.com/espace-client/verification",
    "http://cih-bank-securite.xyz/login.php?id=8841",
    "https://mycompany-docs.weebly.com/login",
    "https://secure-update.bankofafrica-maroc.cfd/verify",
    "https://microsoft-office365-password-reset.com/owa/login",
    "http://192.168.4.7/inwi/recharge-gratuite",
    "https://amazon-delivery-tracking-ma.site/pay?parcel=88213",
    "https://cnss-remboursement.online/connexion",
    "https://instagram-verify-badge.pages.dev/form",
    "https://dhl-colis-en-attente.top/paiement",
    "https://facebook.com.login-help-center.info/recover",
]
LEGIT = [
    "https://www.google.com/search?q=weather",
    "https://github.com/anthropics",
    "https://fr.wikipedia.org/wiki/Maroc",
    "https://www.attijariwafabank.com",
    "https://um6p.ma",
    "https://huggingface.co/Qwen/Qwen2.5-1.5B-Instruct",
    "https://www.paypal.com/signin",
    "https://www.youtube.com/watch?v=abc",
]


def ask(url):
    r = requests.post(URL, json={"reg": "", "url": url, "deep": False, "rest": "", "rules_score": 0, "flags": [], "lang": "en"}, timeout=180)
    return r.json()


def main():
    ok = bad = 0
    for title, links, want_bad in (("PHISHING-LIKE (want > 30)", PHISHING, True), ("LEGITIMATE (want <= 30)", LEGIT, False)):
        print(f"\n== {title} ==")
        for u in links:
            a = ask(u)
            if not a.get("available"):
                sys.exit("AI is not available. Is Ollama running and the model pulled?")
            good = (a["score"] > 30) == want_bad
            ok += good
            bad += not good
            print(f"{'PASS' if good else 'FAIL'}  {a['score']:>3}  {u[:70]}")
            if not good:
                print("        AI said:", a.get("signs"), "| raw AI score:", a.get("ai_score"))
    print(f"\n{ok} correct, {bad} wrong out of {ok + bad}")
    if bad > 4:
        print("Tip: many misses -> use a bigger model:  set LINKLENS_MODEL=qwen2.5:7b  (after: ollama pull qwen2.5:7b)")


if __name__ == "__main__":
    main()
