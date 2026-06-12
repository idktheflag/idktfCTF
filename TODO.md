# TODO

Roughly prioritised top-to-bottom within each section.

---

## email (postfix / SMTP)

- [ ] set up postfix on the server (or swap in an SMTP relay like Resend/SES for easier setup)
- [ ] `SMTP_HOST`, `SMTP_PORT`, `SMTP_FROM` env vars + k8s secret entries
- [ ] email verification on register — user gets a link, can't submit flags until verified
  - [ ] `email_verified BOOLEAN NOT NULL DEFAULT FALSE` column on `users`
  - [ ] `email_verification_tokens` table (`token TEXT, user_id UUID, expires_at TIMESTAMPTZ`)
  - [ ] `GET /auth/verify-email?token=...` route — marks verified, redirects to challenges
  - [ ] resend verification email endpoint
  - [ ] registration flow: after register, redirect to "check your email" page instead of straight to challenges
- [ ] forgot password flow
  - [ ] `password_reset_tokens` table (same shape as verification tokens)
  - [ ] `POST /auth/forgot-password` — sends reset email
  - [ ] `POST /auth/reset-password` — validates token, updates hash
  - [ ] frontend: forgot-password page, reset-password page
- [ ] first blood email notification to organizers (optional)
- [ ] "CTF starts in X hours" reminder email to all verified users (optional)

---

## auth / accounts

- [ ] input validation on `/auth/register` — max length on username (32?), password min length (8?), email format check
- [ ] rate limiting on `/auth/login` and `/auth/register` (currently only flag submission is limited)
- [ ] `PATCH /users/me` — change username, email, password (requires current password for password change)
- [ ] change password frontend page / profile section
- [ ] CTFtime-only accounts can't log in via password — they should see a clear "use CTFtime login" message (already half-done in login.rs, check it covers all paths)
- [ ] account deletion (`DELETE /users/me`) — wipes user and their solves
- [ ] `GET /auth/me` alias or make JWT refresh endpoint (tokens are 7-day, no refresh currently)

---

## competition timing + lifecycle

- [ ] CTF start/end times — `ctf_config` table or env vars (`CTF_START`, `CTF_END` as ISO timestamps)
- [ ] challenges locked before start time (competitors get a countdown page, not the challenge list)
- [ ] scoreboard locked after end time (read-only, no new submissions)
- [ ] score freeze mode — stops scoreboard updates for the final N minutes while submissions still work (classic CTF mechanic)
- [ ] registration open/close toggle — admin switch to stop new registrations mid-competition
- [ ] countdown timer on homepage and challenges page showing time until start / time remaining
- [ ] admin dashboard shows current CTF state (not started / running / frozen / ended)

---

## challenges

- [ ] markdown rendering in challenge descriptions (use a library like `marked` on the frontend)
- [ ] file attachments — admins upload files, competitors download them
  - [ ] `challenge_files` table (`id, challenge_id, filename, url, size`)
  - [ ] file storage: local volume or S3-compatible (MinIO in k8s, or Cloudflare R2)
  - [ ] `POST /admin/challenges/:id/files` upload endpoint
  - [ ] `DELETE /admin/challenges/:id/files/:file_id`
  - [ ] file links shown in challenge modal on frontend
- [ ] challenge solve count visible on cards (e.g. "14 solves") — discoverability signal
- [ ] dynamic scoring — points decrease as more people solve (e.g. `500 / (1 + 0.08 * solves)`, min 100)
  - [ ] this requires recalculating points on every new solve — needs a migration
- [ ] case-insensitive flag option per challenge (flag_case_sensitive BOOLEAN on challenges table)
- [ ] flag regex mode — flag is a pattern, not a literal (for challenges where flag has a variable part)
- [ ] challenge dependencies — unlock challenge B only after solving A
- [ ] tags on challenges (beyond category — e.g. "beginner", "hard", "network")
- [ ] hints system
  - [ ] `hints` table (`id, challenge_id, body, cost`) — cost in points, 0 = free
  - [ ] `hint_unlocks` table (`user_id, hint_id, unlocked_at`)
  - [ ] `POST /challenges/:id/hints/:hint_id/unlock` — deduct points if cost > 0
  - [ ] hints shown in challenge modal after unlock
- [ ] challenge author credit shown in modal (field exists in DB, not surfaced in UI)

---

## scoreboard + stats

- [ ] public scoreboard (currently requires login — standard to make it public)
- [ ] scoreboard player/team names link to their profile page
- [ ] `GET /users/:id` — public profile (username, score, solves list, team)
- [ ] `GET /teams/:id` already exists but frontend doesn't link to team profiles
- [ ] solve graph — line chart of score over time for top N teams (needs `solved_at` timestamps, already stored)
- [ ] per-challenge stats for admins: solve count, first blood, solve timeline

---

## teams

- [ ] team size cap (configurable max, currently unlimited)
- [ ] team captain role — one member who can kick others and rename the team
- [ ] kick member from team (`DELETE /teams/members/:user_id`, captain only)
- [ ] rename team endpoint (`PATCH /teams/me`, captain only)
- [ ] invite via link (current invite code approach works but a shareable URL would be nicer)

---

## admin panel

- [ ] solve stats per challenge (how many solved, first blood, solve graph)
- [ ] promote / demote users to admin (currently requires raw SQL)
- [ ] delete users
- [ ] post announcements visible to all logged-in users (see announcements section)
- [ ] CTF config management (start/end time, score freeze, registration toggle) without redeploying
- [ ] bulk import challenges from YAML/JSON (quality-of-life for setup)
- [ ] export solves as CSV

---

## announcements

- [ ] `announcements` table (`id, title, body, created_at, created_by`)
- [ ] `GET /announcements` — public, returns all announcements
- [ ] `POST /admin/announcements`, `DELETE /admin/announcements/:id`
- [ ] announcements banner / feed on challenges page
- [ ] Discord webhook on new announcement (ping @everyone)

---

## notifications + realtime

- [ ] first blood banner — flash a toast on the challenges page when anyone gets first blood (poll or SSE)
- [ ] Discord webhook on first blood (`DISCORD_WEBHOOK_URL` env var)
- [ ] Server-Sent Events or WebSocket for live scoreboard updates (currently needs a manual refresh)
- [ ] push notification / toast when your own flag submission is accepted

---

## frontend / UX

- [ ] flash / auth guard fixed for `challenges.astro`, `scoreboard.astro`, `teams.astro`, `profile.astro` — same `is:inline` head guard used in admin, but redirecting to login instead of 403
- [ ] 404 page (`src/pages/404.astro`)
- [ ] `frontend/.env.example` — `.env` is gitignored, new contributors have nothing to copy from
- [ ] profile page: show score, solve list, team
- [ ] rules page: uses `var(--color-accent)` / `var(--color-muted)` etc. — these CSS vars don't exist (should be `var(--accent)`, `var(--text-muted)` etc.) — page is probably visually broken
- [ ] login page: handle `?error=oauth_failed` query param (CTFtime callback drops this on failure)
- [ ] scoreboard: real-time updates (SSE or polling)
- [ ] scoreboard: score graph for top teams
- [ ] challenges page: sort options (by points, by solves, by category)
- [ ] mobile: test and fix any layout issues beyond the hamburger menu
- [ ] loading skeletons instead of plain "Loading..." text

---

## security

- [ ] CORS `allow_origin(Any)` → lock to `FRONTEND_URL` in production (currently open to any origin)
- [ ] add `Secure; HttpOnly; SameSite=Strict` note — JWT is in localStorage (XSS risk), consider moving to a cookie for the session token
- [ ] helmet-equivalent headers: `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy` — add via tower-http middleware
- [ ] rate limiter state is in-memory — lost on restart, won't work if ever scaled to >1 replica — move to Redis
- [ ] admin audit log — record who did what (created/deleted challenge, toggled visibility) with timestamp
- [ ] `Argon2id` instead of bcrypt (more memory-hard, better modern choice for password hashing)

---

## ops / infrastructure

- [ ] fill `REPLACE_WITH_YOUR_GITHUB_USERNAME` in `k8s/api/deployment.yaml`
- [ ] create `k8s/README.md` — step-by-step deploy instructions (README.md says "see k8s/README" but it doesn't exist)
- [ ] containerize and deploy the Astro frontend (currently no k8s manifests for it)
  - [ ] `frontend/Dockerfile` — `bun build` then serve with nginx or `bun preview`
  - [ ] `k8s/frontend/deployment.yaml`, `service.yaml`
  - [ ] update cloudflared config to route non-`/api` traffic to the frontend service
- [ ] update Dockerfile from `rust:1.78-slim` to current stable (1.87 or whatever is current)
- [ ] add `RUST_LOG` env var to k8s deployment manifest
- [ ] database backups — cronjob in k8s running `pg_dump` and uploading to S3/R2
- [ ] `k8s/frontend/configmap.yaml` for `PUBLIC_API_URL`
- [ ] Kubernetes resource limits (`requests`/`limits` on CPU and memory) on all deployments
- [ ] liveness probe for postgres deployment (currently only readiness probe)
- [ ] staging environment / namespace

---

## testing

- [ ] integration tests for auth routes (register, login, wrong password, duplicate username)
- [ ] integration tests for flag submission (correct, wrong, already solved, rate limit)
- [ ] integration tests for admin routes (non-admin gets 403)
- [ ] frontend: TypeScript strict mode (`"strict": true` in tsconfig)
- [ ] CI: add frontend type-check step (`bun run tsc --noEmit`)
- [ ] CI: add frontend build step to catch Astro build errors

---

## design / visuals

- [ ] set up a Figma file — design the full UI before implementing, especially for pages that don't exist yet (profile, team page, scoreboard graph, announcements, countdown)
- [ ] design system audit — consolidate spacing, type scale, and colour tokens into one place rather than ad-hoc values scattered across per-page `<style>` blocks
- [ ] improve homepage — currently just a heading and two buttons; needs more personality (team logo, event info, countdown once timing is implemented)
- [ ] challenge cards — more visual hierarchy; category colour coding, difficulty indicator, first blood badge
- [ ] scoreboard — currently a plain table; consider a top-3 podium, medals, score delta indicators
- [ ] first blood + correct flag submission animations / confetti
- [ ] empty states — "no challenges yet", "no teams yet" etc. need actual designs not just grey text
- [ ] consistent page-level layout — some pages have a centred narrow column, others are full-width; needs a decision and a pass to make it uniform
- [ ] dark mode is the only mode — a light mode toggle is probably not needed but worth a Figma decision
- [ ] mobile layout pass — most pages have a hamburger menu but the content layouts haven't been tested on small screens

---

## misc / polish

- [ ] `rules.astro` links to `https://discord.gg/idktheflag` — make sure that's the real invite link
- [ ] `rules.astro` says "scoreboard updates in real time" — not true yet, fix the copy once realtime is done
- [ ] `rules.astro` says teams can have any number of members — update when team size cap is added
- [ ] `robots.txt` — probably `Disallow: /admin`
- [ ] `sitemap.xml` (Astro has a sitemap integration)
- [ ] OpenGraph / Twitter meta tags on the homepage for link previews
- [ ] error.rs has joke messages ("bad boy!", "sorvir") — either lean into it or clean up
