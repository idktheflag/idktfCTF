use sqlx::PgPool;

#[derive(Clone)]
pub struct AppState {
    pub pool:       PgPool,
    pub jwt_secret: String,
    // Reused HTTP client for outbound requests (e.g. CTFtime OAuth).
    // reqwest::Client internally manages a connection pool; creating one
    // per request would waste resources and skip keep-alive benefits.
    pub http:       reqwest::Client,
    // None if CTFTIME_CLIENT_ID is not set — disables CTFtime login
    // gracefully so the server works in local dev without OAuth config.
    pub ctftime:      Option<CtftimeConfig>,
    // After CTFtime OAuth, the backend redirects the browser here with ?token=
    // e.g. "https://ctf.idktheflag.sh"
    pub frontend_url: String,
}

// CTFtime OAuth2 credentials. Obtained from CTFtime's event management
// interface when you register your CTF as an event.
#[derive(Clone)]
pub struct CtftimeConfig {
    pub client_id:     String,
    pub client_secret: String,
    // The URL CTFtime redirects back to after authorization.
    // Must exactly match what's registered on CTFtime.
    pub redirect_uri:  String,
}
