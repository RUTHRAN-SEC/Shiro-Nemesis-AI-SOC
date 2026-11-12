# 08 - Turn on the AI (optional)

The project works fully without AI. AI adds two things:

1. **Nemesis** chooses attacks with Claude (more varied, uses history).
2. **Guardian** adds a short "senior analyst" briefing to each alert.

## Step 1 - Get an API key

Create an account at console.anthropic.com, add billing, and create an **API key**. Treat it like a password.
Each call is tiny (a few hundred tokens), so cost for one attack every 20 minutes is very small, but check your own usage.

## Step 2 - Add the key

* **Ubuntu** (`nano .env`) for the AI planner.
* **Windows** (`notepad .env`) for the AI analyst.

```
ANTHROPIC_API_KEY=sk-ant-...
SN_AI_MODEL=claude-haiku-5-5
```

Use a small fast model (Haiku) - the tasks are simple. You may put the key on only one laptop.

## Step 3 - Restart and check

Ubuntu start-up prints: `AI planner: ON`. Windows start-up box prints: `AI explanations: ON`.
In the Ubuntu log you will see `planner=ai` and a reason written by the AI.
In the dashboard, alerts get an **AI analyst briefing** box a few seconds after they appear.

## How it is kept safe

| Risk | Protection |
|---|---|
| AI invents a dangerous scenario | It may only return an id from the menu; unknown ids are rejected -> rules take over |
| AI writes commands/payloads | Its text is never executed; only the id and difficulty are read |
| AI repeats itself | Repeats of the last 8 attacks are rejected |
| API down / no internet / wrong key | Silent fallback to the built-in rules; nothing breaks |
| AI wrong about an alert | The built-in report is always shown too; the AI box is labelled as extra |
| Data leaves your laptop | Only fake lab data is sent. Never put real logs in this lab |

## Turn AI off without removing the key

```
SN_NEMESIS_USE_AI=false
SN_GUARDIAN_USE_AI=false
```

or run once with `--no-ai`.
