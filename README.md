# idktfCTF

custom infra from scratch for idktfCTF

this was probably not a good idea

---

## stack

| layer | tech |
|-------|------|
| backend | Rust + Axum 0.7, sqlx 0.8, PostgreSQL |
| frontend | Astro 6, vanilla CSS, Bun |
| auth | DIY HMAC-SHA256 JWT, bcrypt, CTFtime OAuth |
| infra | Docker, Kubernetes, Cloudflare Tunnel |

---

## local development

### prerequisites

- [Rust](https://rustup.rs) (stable)
- [Docker](https://docs.docker.com/get-docker/) + Docker Compose
- [Bun](https://bun.sh)

### backend + database

The easiest way to run everything is Docker Compose — it starts Postgres and the API together:

```sh
docker compose up --build
```

The API will be available at `http://localhost:3000`. Migrations run automatically on startup.

To reset the database:

```sh
docker compose down -v   # -v wipes the postgres volume
docker compose up --build
```

If you want to run the API outside Docker (faster iteration):

```sh
# 1. Start only postgres
docker compose up postgres -d

# 2. Set env vars and run
export DATABASE_URL=postgres://ctf:ctf_dev_password@localhost:5432/ctf
export JWT_SECRET=dev_jwt_secret_change_me_in_production
export FRONTEND_URL=http://localhost:4321
cargo run
```

### frontend

```sh
cd frontend
bun install
bun dev
```

Frontend runs at `http://localhost:4321` and talks to the API at `http://localhost:3000` by default. To override:

```sh
# frontend/.env
PUBLIC_API_URL=http://localhost:3000
```

### CTFtime OAuth (optional)

To test CTFtime login locally, register an OAuth app at ctftime.org and set:

```sh
export CTFTIME_CLIENT_ID=your_client_id
export CTFTIME_CLIENT_SECRET=your_client_secret
export CTFTIME_REDIRECT_URI=http://localhost:3000/auth/ctftime/callback
```

Without these the server starts fine — CTFtime login is just disabled.

---

## inspecting the database

```sh
docker exec -it idktfctf-postgres-1 psql -U ctf -d ctf
```

Useful queries:

```sql
SELECT id, username, is_admin, team_id FROM users;
SELECT id, title, category, points, is_visible FROM challenges;
SELECT * FROM user_scores ORDER BY score DESC;
```

To make a user an admin:

```sql
UPDATE users SET is_admin = true WHERE username = 'yourname';
```

---

## CI

GitHub Actions runs on every push:

| job | what |
|-----|------|
| `fmt` | `cargo fmt --check` |
| `clippy` | `cargo clippy -- -D warnings` |
| `test` | `cargo test` |
| `build` | `cargo build --release` |
| `docker` | build + push to ghcr.io (master only) |

Fix formatting locally with `cargo fmt`.

---

## project structure

```
src/
├── main.rs           router, env var init, server startup
├── error.rs          AppError enum → HTTP responses
├── state.rs          AppState (db pool, jwt secret, rate limiter)
├── auth/
│   ├── login.rs      register + login handlers
│   ├── middleware.rs  AuthUser / AdminUser Axum extractors
│   ├── ctftime.rs    CTFtime OAuth flow
│   ├── ratelimit.rs  sliding-window rate limiter (10 submits/min)
│   └── crypto/
│       └── jwt.rs    DIY HMAC-SHA256 JWT (no library)
├── db/
│   ├── mod.rs        connect(), run migrations
│   └── models.rs     User, Challenge, Solve, Team structs
└── routes/
    ├── challenges.rs  list, get, submit flag
    ├── scoreboard.rs  user + team rankings
    ├── teams.rs       create, join, leave, get
    ├── users.rs       /users/me
    └── admin.rs       challenge CRUD, user list

frontend/src/
├── layouts/Layout.astro   global styles, header
├── lib/api.ts             typed fetch wrapper + JWT parsing
├── components/Header.astro
└── pages/
    ├── index.astro
    ├── login.astro
    ├── register.astro
    ├── challenges.astro
    ├── scoreboard.astro
    ├── teams.astro
    ├── profile.astro
    └── admin/index.astro  admin panel (403 if not admin)

migrations/
└── 001_initial.sql   tables: users, teams, challenges, solves + score views

k8s/                  kubernetes manifests (see k8s/README for deploy instructions)
```
