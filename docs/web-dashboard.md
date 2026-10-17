# Kavach web dashboard

The dashboard is served from the same FastAPI app as the evaluator. This keeps the browser and API same-origin, avoids a separate frontend build, and keeps Supabase credentials on the server.

## What works

- **Overview** — explains the VAULT, EXECUTOR, CHANNEL and NAVIGATOR flow.
- **Evaluate a call** — submits a JSON tool-call proposal to \`POST /check\`; it never executes the tool.
- **Rule catalogue** — server-side, read-only search of \`public.minister_definitions\` in Supabase. The catalogue is behind a signed HTTP-only session cookie and a dashboard password.
- **Connection status** — \`GET /api/status\` makes a read-only request to Supabase and reports connectivity/count without returning a key.

The existing table's RLS stays enabled and its anon/authenticated access remains revoked. Do not add a public RLS policy just to make the browser query the table.

## Required server environment

Set these as server-side environment variables on the hosting service:

- \`SUPABASE_URL\`: the project's \`https://<project-ref>.supabase.co\` URL.
- \`SUPABASE_SECRET_KEY\`: the Supabase secret/service-role key. **Never expose it to the browser, check it into Git, or give it a \`NEXT_PUBLIC_\` prefix.**
- \`KAVACH_DASHBOARD_PASSWORD\`: a long, unique dashboard password.
- \`KAVACH_SESSION_SECRET\`: generate with \`python -c "import secrets; print(secrets.token_urlsafe(48))"\`.

A missing or invalid setting keeps the catalogue unavailable; the server never falls back to anonymous table access. Keep real credentials out of \`.env.example\`, issue comments, screenshots and browser bundles.

## Deploy on Render

1. Open Render and choose **New → Blueprint**.
2. Select this repository and branch \`mvp-core\`. Render will use \`render.yaml\`.
3. Add the four environment values in the Render dashboard. Never commit their actual values in the YAML.
4. Deploy and check \`/health\` plus \`/api/status\` on the deployed URL.
5. Open the site, use **Evaluate a call** for the live API, then sign in to **Rule catalogue** to query Supabase.

If the project is deployed elsewhere, use the equivalent Python 3.11+ web-service configuration with build command \`pip install -r requirements.txt\` and start command \`uvicorn kavach.api:app --host 0.0.0.0 --port $PORT\`. Select \`mvp-core\` as the deploy branch.

## Local run

\`\`\`bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
# Put real local values in .env (the app does not load .env automatically).
# Export them in your shell or load them with your local environment manager.
uvicorn kavach.api:app --reload --host 127.0.0.1 --port 8088
\`\`\`

Then visit \`http://127.0.0.1:8088\`. For example, in a shell before starting the server:

\`\`\`bash
export SUPABASE_URL="https://<project-ref>.supabase.co"
export SUPABASE_SECRET_KEY="..."
export KAVACH_DASHBOARD_PASSWORD="..."
export KAVACH_SESSION_SECRET="$(python -c 'import secrets; print(secrets.token_urlsafe(48))')"
\`\`\`

## Important limitations

- This is a research MVP, not a production security boundary. It is not a tool executor and does not independently authenticate callers who supply task instructions in \`/check\`.
- The tool-call evaluator and dashboard password are intentionally separate. Before an internet-facing production deployment, add identity-based access control, CSRF defenses where appropriate, rate limiting, and tool-boundary enforcement.
- Catalog entries retain source review status. \`unreviewed\` or \`candidate\` must not be interpreted as validated security rules.
