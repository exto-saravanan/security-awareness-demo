# Sessions — Scenarios, API & Demo Guide

Each section below covers one active session: scenarios, simulated users, API reference, and step-by-step demo flow.

---

## Session 02 — OWASP A01: Broken Access Control

**URL:** `http://localhost:8090/session/02`

### Scenarios

| # | Pattern | Route | What it demonstrates |
|---|---|---|---|
| 01 | IDOR | `GET /session/02/api/users/:id/profile` | Any authenticated user can read any other user's full record — including salary — by changing the ID in the URL. No ownership check. |
| 02 | Missing Authorization Check | `GET /session/02/api/admin/reports` | An engineer can reach a confidential admin endpoint. The route verifies the request is authenticated — but never checks the caller's role. Authentication ≠ Authorization. |
| 03 | Privilege Escalation | `PUT /session/02/api/users/:id/role` | Any user can promote themselves or anyone else to admin. The write endpoint has no role guard at all. |

---

### Simulated Users

| ID | Name | Role | Select via |
|---|---|---|---|
| 1 | Alice | engineer | Alice — Engineer button |
| 2 | Bob | engineer | Bob — Engineer button |
| 3 | Carol | admin | Carol — Admin button |

The UI sends the selected user's ID as an `X-User-ID` header on every request.

---

### Demo Flow

**Vulnerable mode (red toggle)**

1. Open the session page — mode defaults to **Vulnerable**
2. Select **Alice** (engineer, ID 1)
3. **Scenario 01:** Set target ID to `2` or `3` and send — Alice reads Bob's or Carol's salary with no error
4. **Scenario 02:** Send the admin reports request — Alice gets confidential incident data as an engineer
5. **Scenario 03:** Set target ID to `1`, pick `admin`, send — Alice promotes herself with no error
6. Repeat steps 3–5 as **Bob** to show it is not Alice-specific — any engineer can do this

**Fixed mode (green toggle)**

7. Click the toggle to switch to **Fixed** — user data resets automatically
8. Re-run all three scenarios as Alice
9. All three return `403 Forbidden` — the response body includes a `"fix"` field explaining which check was added

---

### API Reference

| Method | Path | Description |
|---|---|---|
| `GET` | `/session/02/api/mode` | Returns current mode: `vulnerable` or `fixed` |
| `POST` | `/session/02/api/mode` | Toggles mode and resets all user data to seed values |
| `GET` | `/session/02/api/users/:id/profile` | Scenario 01 — IDOR on user profile |
| `GET` | `/session/02/api/admin/reports` | Scenario 02 — Missing authorization check |
| `PUT` | `/session/02/api/users/:id/role` | Scenario 03 — Unguarded role update |

**Request header required on all endpoints:**

```
X-User-ID: <1|2|3>
```

The UI sets this automatically. For manual testing (curl, Postman, etc.):

```bash
# Scenario 01 — IDOR: Alice (ID 1) reads Carol's (ID 3) profile
curl -H "X-User-ID: 1" http://localhost:8090/session/02/api/users/3/profile

# Scenario 02 — Missing auth: Bob (ID 2) accesses admin reports
curl -H "X-User-ID: 2" http://localhost:8090/session/02/api/admin/reports

# Scenario 03 — Priv esc: Alice promotes herself to admin
curl -X PUT -H "X-User-ID: 1" -H "Content-Type: application/json" \
  -d '{"role":"admin"}' \
  http://localhost:8090/session/02/api/users/1/role
```

---

*Add new session sections here as they go active.*
