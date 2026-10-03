# Keeping SamurAI Alive Across Brev Instances

## The one fact that explains everything

On NVIDIA Brev, **only `/home/ubuntu/workspace` persists — and only when you STOP an instance, not DELETE it.**

| Action | GPU charges | `/home/ubuntu/workspace` | Everything else (incl. default `~/.ollama`) |
|---|---|---|---|
| **Stop** | none (small storage cost) | **kept** | wiped |
| **Delete** | none | **wiped** | wiped |
| **New instance** | — | empty | empty |

That is why you re-download 66 GB every time: the models were in `~/.ollama`, which does not survive, and
you were creating new instances instead of restarting a stopped one.

## Strategy

1. **Put the models in `workspace`.** `bootstrap.sh` sets `OLLAMA_MODELS=/home/ubuntu/workspace/ollama-models`
   and runs the Ollama server pointed there, so the 66 GB lives on the one disk that survives a Stop.
2. **Stop, don't Delete, between sessions.** Then restarting reuses the models — no re-download.
3. **One command rebuilds everything.** `bootstrap.sh` is idempotent: it skips Ollama if installed, skips a
   model if already pulled, reuses the venv, and relaunches the app with a public `gradio.live` URL.

> Honest caveat: a **brand-new** or **deleted-then-recreated** instance starts with an empty disk, so the
> models *will* download once there. Local disk can't carry data across a Delete. Stop/Start is what saves you.

## Day-to-day flow

**First time on a fresh instance** (downloads models once, ~20-40 min):
```bash
# after pushing the app to GitHub, set the repo once:
export REPO_URL=https://github.com/<you>/samurai.git
curl -fsSL https://raw.githubusercontent.com/<you>/samurai/main/bootstrap.sh | bash
```

**Done for now:** in the Brev dashboard, **Stop** the instance (not Delete).

**Next session:** **Start** the same instance, then:
```bash
bash /home/ubuntu/workspace/samurai/bootstrap.sh
```
Models are already there, so it skips the download and just relaunches — up in ~1 minute.

## Make Brev run it automatically

When creating an environment, paste the bootstrap into the **setup / startup script** field (the box you saw
on the create-instance page). New instances then self-provision on boot — no manual steps. You can also save
it as a Brev **Launchable** so the whole environment is one shareable template.

## Stop re-copying the code too

Push the project to GitHub once:
```bash
cd /path/to/ai-pentest-tool
git init && git add . && git commit -m "SamurAI"
git branch -M main
git remote add origin https://github.com/<you>/samurai.git
git push -u origin main
```
After that, `bootstrap.sh` clones/pulls it automatically — no more `scp`.

## TL;DR
- Models in `workspace`, **Stop not Delete** → download once.
- `bootstrap.sh` → one idempotent command rebuilds + relaunches anywhere.
- App in GitHub + Brev setup-script → new instances self-provision.
