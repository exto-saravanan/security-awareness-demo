# Security Awareness Demo Lab

A unified interactive demo app for the Exto360 Bi-Weekly Security Awareness Series.

Each session gets its own page, its own isolated API, and its own state — all served from a single running instance. Adding a new session is two files and two lines in `main.go`.

---

## Prerequisites

- Go 1.21 or later

## Run

```bash
go run main.go
```

Open `http://localhost:8090` in a browser. The landing page lists all sessions.

---

## Directory Layout

```
security-awareness-demo/
├── main.go              # Entrypoint — registers all session routes
├── go.mod
├── sessions/
│   ├── README.md        # Per-session docs — scenarios, API, demo flow
│   └── session02.go     # Session 02 — Broken Access Control
└── static/
    ├── index.html       # Landing page — all sessions grid
    └── s02/
        └── index.html   # Session 02 demo UI
```

---

## Sessions

| # | Topic | Status | Path |
|---|---|---|---|
| 01 | Curtain Raiser — Landscape, Stakes & Roadmap | No demo | — |
| 02 | OWASP A01 — Broken Access Control | Active | `/session/02` |
| 03 | OWASP A03 — Injection | Coming soon | — |
| 04 | OWASP A06 — Vulnerable Components | Coming soon | — |
| 05 | OWASP A07 — Authentication Failures | Coming soon | — |
| 06 | OWASP A10 — SSRF | Coming soon | — |
| 07 | Secure Code Review | Coming soon | — |
| 08 | Live Vulnerability Triage Exercise | Coming soon | — |

For scenario details, API reference, and demo instructions for each session, see [`sessions/README.md`](sessions/README.md).

---

## Adding a New Session

1. Create `sessions/session0N.go` — define a `SessionNN` struct with a `Register(*gin.RouterGroup)` method
2. Create `static/s0N/index.html` — the session's demo UI
3. In `main.go`, add two lines:
   ```go
   r.GET("/session/0N", serveHTML("static/s0N/index.html"))
   sessions.NewSessionNN().Register(r.Group("/session/0N/api"))
   ```
4. Add a section to `sessions/README.md`

---

*Exto360 Engineering · Bi-Weekly Security Awareness Series · Demo Lab*
