-- Enable the pgcrypto extension so we can use gen_random_uuid().
-- Extensions in Postgres add extra functions/types. pgcrypto gives us
-- cryptographic helpers; we only need it for UUID generation here.
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- Teams must come BEFORE users because users.team_id references teams.id.
-- In SQL, a FOREIGN KEY constraint requires the referenced table to exist first.
CREATE TABLE teams (
    id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    name        TEXT        NOT NULL UNIQUE,
    -- NULL invite_code = anyone can join; set a code to make it invite-only
    invite_code TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Users: both competitors and admins live in this table.
-- is_admin is a simple boolean flag; a role table would be overkill here.
CREATE TABLE users (
    id            UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    username      TEXT        NOT NULL UNIQUE,
    email         TEXT        NOT NULL UNIQUE,
    -- We NEVER store plain-text passwords. password_hash holds the bcrypt output,
    -- which is always exactly 60 characters long.
    password_hash TEXT        NOT NULL,
    is_admin      BOOLEAN     NOT NULL DEFAULT FALSE,
    -- NULL team_id = solo player. ON DELETE SET NULL means if a team is deleted,
    -- members become solo players rather than getting deleted themselves.
    team_id       UUID        REFERENCES teams(id) ON DELETE SET NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Challenges: the actual CTF problems.
CREATE TABLE challenges (
    id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    title       TEXT        NOT NULL,
    description TEXT        NOT NULL,
    -- category is free-text: "web", "crypto", "pwn", "rev", "misc", etc.
    category    TEXT        NOT NULL,
    points      INTEGER     NOT NULL,
    -- The flag is stored in plaintext. We're not hashing it because:
    -- (a) flags aren't user secrets, (b) we need exact string comparison,
    -- (c) bcrypt on every submission would be needlessly slow.
    -- Only admin API responses ever include this field.
    flag        TEXT        NOT NULL,
    hint        TEXT,
    -- is_visible = false means the challenge is a draft, invisible to competitors.
    -- Admins toggle this when a challenge is ready.
    is_visible  BOOLEAN     NOT NULL DEFAULT FALSE,
    author      TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Solves: the join table between users and challenges.
-- UNIQUE(user_id, challenge_id) enforces that a user can only solve each
-- challenge once — the database itself prevents double-submission.
CREATE TABLE solves (
    id             UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id        UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    challenge_id   UUID        NOT NULL REFERENCES challenges(id) ON DELETE CASCADE,
    -- First blood = the first person globally to solve a challenge.
    -- This flag is set by the submission handler inside a transaction.
    is_first_blood BOOLEAN     NOT NULL DEFAULT FALSE,
    solved_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(user_id, challenge_id)
);

-- Views are saved queries. Querying user_scores is identical to running
-- the SELECT below, but the name makes intent clear and avoids repeating
-- the JOIN logic everywhere.
CREATE VIEW user_scores AS
SELECT
    u.id,
    u.username,
    u.team_id,
    -- COALESCE returns the first non-NULL argument. SUM returns NULL when
    -- there are no rows to sum (i.e. user has zero solves), so we default to 0.
    COALESCE(SUM(c.points), 0) AS score,
    COUNT(s.id)                AS solve_count,
    MAX(s.solved_at)           AS last_solve_at
FROM users u
-- LEFT JOIN keeps users with zero solves in the result (INNER JOIN would drop them)
LEFT JOIN solves     s ON s.user_id = u.id
LEFT JOIN challenges c ON c.id      = s.challenge_id
GROUP BY u.id, u.username, u.team_id;

CREATE VIEW team_scores AS
SELECT
    t.id,
    t.name,
    COALESCE(SUM(c.points), 0) AS score,
    COUNT(s.id)                AS solve_count,
    MAX(s.solved_at)           AS last_solve_at
FROM teams t
LEFT JOIN users      u ON u.team_id = t.id
LEFT JOIN solves     s ON s.user_id = u.id
LEFT JOIN challenges c ON c.id      = s.challenge_id
GROUP BY t.id, t.name;

