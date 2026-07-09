# Deploy garak-demo to the cloud (true 24/7)

Goal: a permanent public link (e.g. `https://garak-demo.onrender.com`) that works
even when your PC is off. Free, no credit card. ~15 minutes.

Everything in this folder is already configured (`Procfile`, `render.yaml`,
`requirements.txt`, `.python-version`, `.gitignore`). You just push it to GitHub
and point Render at it.

---

## Step 1 — Put the code on GitHub

Create a free GitHub account if you don't have one: https://github.com/signup

Then, in this folder (`~/garak-demo`), run these one at a time:

```bash
cd ~/garak-demo
git init
git add .
git commit -m "garak dashboard — ready to deploy"
```

Create an empty repo on GitHub: https://github.com/new
  - Name it `garak-demo`
  - Leave it empty (no README/.gitignore — you already have those)
  - Click **Create repository**

GitHub will show a URL like `https://github.com/YOURNAME/garak-demo.git`. Use it:

```bash
git branch -M main
git remote add origin https://github.com/YOURNAME/garak-demo.git
git push -u origin main
```

(If it asks for a password, use a GitHub **Personal Access Token**, not your
login password: https://github.com/settings/tokens → Generate new token classic →
tick `repo` → use that token as the password.)

---

## Step 2 — Deploy on Render

1. Sign up (free, no card): https://render.com  → "Get Started" → sign in with GitHub.
2. Click **New +** → **Blueprint**.
3. Select your `garak-demo` repo → Render reads `render.yaml` automatically.
4. Click **Apply** / **Create**.
5. Wait ~3–5 min for the first build. When it's green, you'll get a link like
   `https://garak-demo.onrender.com` — **that's the link you send friends.**

---

## Good to know

- **Cold start:** On the free plan the app "sleeps" after ~15 min idle. The first
  visitor then waits ~40s while it wakes, and it's fast for everyone after that.
  (Upgrading to Render's cheapest paid plan removes the sleep — optional.)
- **Data resets on redeploy:** *all* state — logins, every leaderboard, and the
  interactive feature stores (war room, squad feed, SOC playbooks, mini-CTF, dead
  drops, ops, ghost proposals, dispatches) — now lives in the single SQLite file at
  `DATABASE_PATH` (default `~/.local/share/garak/hacking_dashboard.db`). On the free
  plan that file is ephemeral, so it resets on redeploy. Fine for a demo. **To make
  everything persist:** add one Render Disk and point `DATABASE_PATH` at its mount
  (e.g. `/data/hacking_dashboard.db`) — a single disk now covers the whole app.
- **The scary login + real-location trace work identically** on the deployed site —
  the IP-geolocation lookup runs in each visitor's browser, so it shows *their*
  real IP/city, not the server's.
- **Updating the site later:** edit files, then `git add . && git commit -m "update"
  && git push` — Render auto-redeploys.
