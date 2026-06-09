// lib/api.ts — typed API client for the idktfCTF backend.
//
// All requests go through the `api()` helper which:
//   - prepends the base URL (from import.meta.env.PUBLIC_API_URL)
//   - attaches the JWT from localStorage as a Bearer token
//   - throws ApiError on non-2xx responses
//
// Usage:
//   import { auth, challenges, scoreboard } from '../lib/api';
//   const { token } = await auth.login({ email, password });

// ── Configuration ─────────────────────────────────────────────────────────────

// In Astro, PUBLIC_* env vars are inlined at build time and safe to expose.
// Set PUBLIC_API_URL in frontend/.env (local dev) or as a k8s env var.
// Default falls back to localhost for local development.
const BASE_URL = import.meta.env.PUBLIC_API_URL ?? 'http://localhost:3000';

// ── Token storage ─────────────────────────────────────────────────────────────

export const token = {
    get: (): string | null => localStorage.getItem('ctf_token'),
    set: (t: string): void => localStorage.setItem('ctf_token', t),
    clear: (): void => localStorage.removeItem('ctf_token'),
};

// Parse the JWT payload (middle section) to read claims.
// No signature verification here — the backend does that. This is just
// for reading display data (username, is_admin) client-side.
export function parseToken(raw: string): TokenClaims | null {
    try {
        const parts = raw.split('.');
        if (parts.length !== 3) return null;
        // atob decodes base64. JWT uses base64url (- and _ instead of + and /)
        // so we need to swap those back before decoding.
        const payload = parts[1].replace(/-/g, '+').replace(/_/g, '/');
        return JSON.parse(atob(payload)) as TokenClaims;
    } catch {
        return null;
    }
}

export interface TokenClaims {
    sub:      string;  // user UUID
    exp:      number;  // Unix timestamp
    username: string;
    is_admin: boolean;
}

// Returns parsed claims if a valid (non-expired) token is stored.
export function currentUser(): TokenClaims | null {
    const raw = token.get();
    if (!raw) return null;
    const claims = parseToken(raw);
    if (!claims) return null;
    // Check expiry client-side to avoid a round-trip for obviously stale tokens.
    if (claims.exp < Math.floor(Date.now() / 1000)) {
        token.clear();
        return null;
    }
    return claims;
}

// ── Core fetch wrapper ────────────────────────────────────────────────────────

export class ApiError extends Error {
    constructor(
        public status: number,
        message: string,
    ) {
        super(message);
    }
}

async function api<T>(
    method: string,
    path: string,
    body?: unknown,
): Promise<T> {
    const headers: Record<string, string> = {
        'Content-Type': 'application/json',
    };

    // Attach token if present.
    const t = token.get();
    if (t) headers['Authorization'] = `Bearer ${t}`;

    const res = await fetch(`${BASE_URL}${path}`, {
        method,
        headers,
        body: body !== undefined ? JSON.stringify(body) : undefined,
    });

    if (!res.ok) {
        // Try to parse error message from { "error": "..." } response body.
        let message = res.statusText;
        try {
            const data = await res.json();
            if (data.error) message = data.error;
        } catch { /* ignore */ }
        throw new ApiError(res.status, message);
    }

    // 204 No Content has no body.
    if (res.status === 204) return undefined as T;
    return res.json() as Promise<T>;
}

// ── Type definitions ──────────────────────────────────────────────────────────

export interface AuthResponse     { token: string }
export interface RegisterRequest  { username: string; email: string; password: string }
export interface LoginRequest     { email: string; password: string }

export interface ChallengeListItem {
    id:           string;
    title:        string;
    category:     string;
    points:       number;
    hint:         string | null;
    solved_by_me: boolean;
}

export interface ChallengeDetail extends ChallengeListItem {
    description: string;
    author:      string | null;
    created_at:  string;
}

export interface SubmitResponse {
    correct:       boolean;
    first_blood:   boolean;
    points_earned: number;
}

export interface UserScore {
    rank:          number;
    id:            string;
    username:      string;
    score:         number;
    solve_count:   number;
    last_solve_at: string | null;
}

export interface TeamScore {
    rank:          number;
    id:            string;
    name:          string;
    score:         number;
    solve_count:   number;
    last_solve_at: string | null;
}

export interface UserProfile {
    id:         string;
    username:   string;
    email:      string | null;
    is_admin:   boolean;
    team_id:    string | null;
    ctftime_id: number | null;
    created_at: string;
}

export interface TeamMember {
    id:       string;
    username: string;
    score:    number;
}

export interface TeamDetail {
    id:          string;
    name:        string;
    invite_code: string | null;  // only present if you're a member
    ctftime_id:  number | null;
    members:     TeamMember[];
    total_score: number;
}

export interface TeamResponse {
    id:           string;
    name:         string;
    invite_code:  string | null;
    ctftime_id:   number | null;
    member_count: number;
}

export interface AdminChallenge extends ChallengeDetail {
    flag:       string;
    is_visible: boolean;
}

export interface CreateChallengeRequest {
    title:       string;
    description: string;
    category:    string;
    points:      number;
    flag:        string;
    hint?:       string;
    author?:     string;
}

// ── API namespaces ────────────────────────────────────────────────────────────

export const auth = {
    register: (body: RegisterRequest) =>
        api<AuthResponse>('POST', '/auth/register', body),
    login: (body: LoginRequest) =>
        api<AuthResponse>('POST', '/auth/login', body),
    // Redirects the browser to CTFtime OAuth — not a fetch call.
    ctftimeUrl: () => `${BASE_URL}/auth/ctftime`,
};

export const challenges = {
    list:   ()         => api<ChallengeListItem[]>('GET',  '/challenges'),
    get:    (id: string) => api<ChallengeDetail>  ('GET',  `/challenges/${id}`),
    submit: (id: string, flag: string) =>
        api<SubmitResponse>('POST', `/challenges/${id}/submit`, { flag }),
};

export const scoreboard = {
    users: () => api<UserScore[]>('GET', '/scoreboard/users'),
    teams: () => api<TeamScore[]>('GET', '/scoreboard/teams'),
};

export const users = {
    me: () => api<UserProfile>('GET', '/users/me'),
};

export const teams = {
    create: (name: string)          => api<TeamResponse>('POST',   '/teams',      { name }),
    join:   (invite_code: string)   => api<TeamResponse>('POST',   '/teams/join', { invite_code }),
    leave:  ()                      => api<void>         ('DELETE', '/teams/leave'),
    me:     ()                      => api<TeamDetail>   ('GET',    '/teams/me'),
    get:    (id: string)            => api<TeamDetail>   ('GET',    `/teams/${id}`),
};

export const admin = {
    listChallenges:   ()                              => api<AdminChallenge[]>('GET',    '/admin/challenges'),
    createChallenge:  (body: CreateChallengeRequest)  => api<{id: string}>    ('POST',   '/admin/challenges', body),
    updateChallenge:  (id: string, body: CreateChallengeRequest) =>
        api<void>('PUT', `/admin/challenges/${id}`, body),
    deleteChallenge:  (id: string)                    => api<void>            ('DELETE', `/admin/challenges/${id}`),
    toggleChallenge:  (id: string)                    => api<void>            ('PATCH',  `/admin/challenges/${id}/toggle`),
    listUsers:        ()                              => api<UserProfile[]>   ('GET',    '/admin/users'),
};
