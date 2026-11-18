# Admin authentication defaults

The HTTP callback validates a random browser-session-bound OAuth state with a ten-minute lifetime before contacting Discord. The provider exchange helper remains separately unit-testable but is not an HTTP route. Unlisted Discord identities are rejected at the HTTP boundary.

Session cookies default to Secure, HttpOnly (Starlette default), SameSite=Lax and an eight-hour maximum age. Only for explicit local HTTP development may SESSION_COOKIE_SECURE=false be set. Use HTTPS in production.

ADMIN_ALLOWED_ORIGINS is an explicit comma-separated origin allowlist, empty by default. Wildcards, credentials, query strings and non-root URL paths are rejected. Same-origin deployments need no CORS origin entry. Example: https://admin.example.invalid. No origin or secret has been configured on a live service.

This draft changes source and tests only. It does not deploy, rotate credentials or change Discord permissions. Review cookie/proxy/redirect settings for the real deployment before enabling it.
