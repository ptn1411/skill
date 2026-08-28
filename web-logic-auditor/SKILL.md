---
name: web-logic-auditor
description: "Authorized testing of access-control and business-logic flaws that pattern scanners cannot find — IDOR/BOLA, broken function-level authorization, mass assignment, business-logic abuse, and race conditions. A reasoning-driven methodology (Subject×Object×Action matrices, state-machine modeling, invariant analysis) plus two helper tools: authz_diff.py (two-identity response differ) and race_probe.py (concurrency probe)."
allowed-tools: Read, Write, Edit, Glob, Grep, Bash
---

# Web Logic Auditor

> Access-control and business-logic testing for authorized web apps/APIs. These classes require **reasoning about intent** — who may do what, and which invariants must hold — not regex signatures. Use alongside [web-app-scanner](../web-app-scanner/SKILL.md), which covers the automatable injection/misconfig classes.

> **Language rule**: All skill instructions use English.
> **Final summary presented to the user must be in Vietnamese.**

---

## 0. Authorization & Routing

Operates under [MASTER_POLICY.md](../MASTER_POLICY.md) §1–§2. Test only apps you **own or are explicitly authorized to assess**. Every technique here sends real requests as real users; several are **state-changing** (mass assignment, race conditions) — use disposable/staging accounts and the `--allow-write` gate. If scope is unclear, ask one concise question first.

You need **at least two test accounts** for most of this: an *owner* (A) and a *non-owner* (B), plus an *admin* where roles exist, and an *anonymous* baseline.

| Sibling skill | When |
|---|---|
| [web-app-scanner](../web-app-scanner/SKILL.md) | Automatable classes: XSS, SQLi, SSRF, SSTI, redirects, exposed files |
| [network-interceptor](../network-interceptor/SKILL.md) | Capture the app's real API calls to map hidden endpoints/flows |
| [pentest-script-generator](../antigravity-kit/pentest-script-generator/SKILL.md) | Turn a confirmed finding into a PoC/verify script |

---

## Why reasoning, not regex

A scanner cannot know that "a discount and a referral credit are mutually exclusive", that "refund must follow capture", or that "order 1001 belongs to user A, not user B". These flaws live in the *intended* behavior of the app. The method is: **model the domain, then look for states/transitions/accesses the model forbids but the app allows.**

---

## Step 1 — Map the surface and the model

1. Drive the app (or read [network-interceptor](../network-interceptor/SKILL.md) captures) to enumerate endpoints, parameters, and object identifiers. Note every `id`, `uuid`, `order`, `account`, `file`, `tenant` reference.
2. Build a **Subject × Object × Action** matrix: rows = principals (anon, user A, user B, premium, admin), columns = actions on resources. Fill in what *should* be allowed.
3. For stateful flows (checkout, signup→trial→paid, approval), draw the **state machine**: states, valid transitions, preconditions, and invariants ("balance never increases without a payment", "coupon usable once per user").

---

## Step 2 — IDOR / BOLA (object-level authorization)

Discover object IDs from list/search/export endpoints, pagination cursors, JS bundles, emails, webhooks. Then replay A's request as B (and anonymously) and compare responses.

```powershell
python web-logic-auditor\scripts\authz_diff.py --url "https://app/api/orders/1001" `
    --auth-a "Cookie: session=OWNER" --auth-b "Cookie: session=OTHER" --baseline-unauth --authorized
```

`authz_diff.py` reports an IDOR/BOLA candidate when B (or anon) gets a 2xx whose body closely matches A's (`--threshold`, default 0.85). Confirm manually.

Extra vectors:
- **Batch/array endpoints** — authorization often checked only on the first element; inject a cross-tenant ID mid-array.
- **PATCH partial updates** — silent unauthorized field writes.
- **Gateway header trust** — try `X-User-Id` / `X-Organization-Id` overrides.
- **Second transport** — the same object via REST *and* GraphQL; authorization may differ.

---

## Step 3 — Broken function-level authorization (BFLA)

Call **privileged endpoints as a low-privileged user**: admin routes (`/admin/*`, `/api/internal/*`), management verbs (`DELETE`, role changes), and functions hidden only in the UI. Use `authz_diff.py` with A = admin token, B = normal user; a 2xx for B on an admin action is a finding. Also test **stale capabilities**: downgrade a premium account and confirm premium features are actually revoked.

---

## Step 4 — Mass assignment / parameter tampering

Add fields the client never sends and see if the server honors them (state-changing — `--allow-write`):

- Privilege: `"role":"admin"`, `"is_admin":true`, `"verified":true`, `"plan":"enterprise"`.
- Ownership: `"user_id":<other>`, `"tenant_id":<other>`, `"account":<other>`.
- Economics: negative/oversized quantities, `"price":0`, extra `"balance"`/`"credits"` fields.

Send the tampered body, then **read the object back** and check whether the injected field stuck. The bug is confirmed by persisted state, not by the write's status code.

---

## Step 5 — Business-logic abuse

Work the state machine from Step 1:
- **Skip / reorder / replay** steps (reach payment-confirmation without payment; re-POST a one-time step).
- **Value tampering across a trusted boundary** — change price/total after approval but before capture; trust line items where the server only re-checks the total.
- **Discount/coupon** — stack mutually-exclusive offers; reuse a per-user coupon across accounts; apply after tax.
- **Quotas/inventory** — reservation leaks, off-by-one on limits, time-window reset abuse.
- **Multi-tenant** — actions whose DB `WHERE` clause omits the tenant key.

Each candidate is confirmed by an invariant violation you can state in one sentence ("the ledger balance rose without a payment").

---

## Step 6 — Race conditions / idempotency

For "should happen once" actions (redeem, withdraw, apply, vote), fire many concurrent identical requests and check whether more than one succeeds:

```powershell
python web-logic-auditor\scripts\race_probe.py --url "https://app/api/redeem" --method POST `
    --data "code=SAVE10" --header "Cookie: session=YOU" -n 20 --authorized --allow-write
```

`race_probe.py` reports the 2xx distribution; **>1 success** suggests a race window or an idempotency key scoped to the path instead of the principal. Confirm by reading server-side state (balance, coupon uses, inventory) afterwards.

---

## Step 7 — Validate & report

For every finding record: the endpoint, the two principals used, the exact request/response pair (owner vs non-owner), and the **invariant that was violated**. Reproduce cross-transport where possible. Redact real data (MASTER_POLICY §3).

**False-positive guards:**
- Public-by-design resources (marketing pages, shared links) are not IDOR.
- Similar bodies that are generic error/empty templates are not access — check `authz_diff.py`'s denied-heuristic and read the body.
- A single 2xx in `race_probe.py` is normal; only *multiple* successes indicate a race.

**Defensive fixes to recommend:**
- **IDOR/BOLA** → enforce per-object ownership server-side on every read/write; never trust client-supplied IDs.
- **BFLA** → centralized function-level authorization; deny-by-default on privileged routes.
- **Mass assignment** → allow-list bindable fields (DTOs / `attr_accessible`); never bind request bodies straight to models.
- **Business logic** → re-validate invariants in every service/queue/job, not just the entry point.
- **Race conditions** → atomic operations, DB constraints/locks, and idempotency keys scoped to the principal.
