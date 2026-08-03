---
name: backend-arch-review
description: 'Trigger phrases: "review the backend architecture", "audit the database schema", "arch review", "is this over-engineered", "backend-arch-review", "critique the backend design", "second pass", "data structure review", "consistency audit".'
---

# Backend Architecture Review

Dispatches two specialist subagents in parallel to audit the Go backend and PostgreSQL database architecture for over-engineering, unnecessary complexity, design issues, and **pattern consistency**. Applies a **ponytail/simplicity lens** everywhere: the shortest correct solution is preferred.

Not for: bug triage (`e2e-triage`), frontend structure (`component-structure-review`), style/lint (`go vet` / `go fmt`), or small PR diffs (review inline).

For cross-cutting structural tension points — handler pattern divergence, service signature chaos, error handling fracture, auth enforcement gaps — use `tension-review` and specify "check the Go backend."

## Shared Principles (Both Reviewers)

1. **YAGNI** — Does this abstraction, layer, interface, column, index, or table have a concrete consumer today? If not, it's speculative debt.
2. **Prefer the standard library** — No re-inventing built-in behavior. `net/http`, pgx, `os`, `io`, `time`, `fmt`, `errors` cover most needs.
3. **Don't add a dependency for what a few lines can do** — External packages must earn their weight.
4. **Delete over abstract** — If something isn't pulling its weight, delete it. If two things overlap, merge them. If nobody calls it, remove it.
5. **Boring over clever** — The simplest thing that works is the most maintainable thing. Clever abstractions are someone else's 3am debugging session.
6. **Pattern consistency** — If the codebase uses a pattern once, it should use it everywhere the same situation applies. Inconsistent patterns create maintenance surprises.

The full Go and DB standards checklists live in the reviewer templates — read them at dispatch time, not before.

## How to Dispatch

**1. Gather context (do this yourself, not in subagents):**

```bash
# Go module info
go list -m
go vet ./... 2>&1 | head -20

# Database
ls db/migrations/ | tail -20
head -5 db/migrations/*.sql

# Project structure
find . -name '*.go' -not -path './.git/*' | head -40
```

**2. Kick off both subagents in parallel:**

Read the prompt templates at `skill://backend-arch-review/go-reviewer.md` and `skill://backend-arch-review/db-reviewer.md` (load each only when dispatching that reviewer).

**Placeholders in both templates:**
- `{GO_PACKAGE_NAME}` — Go module name (from `go list -m`)
- `{USER_CONCERN}` — one-line summary of what triggered the review ("feels over-engineered", "checking schema migration hygiene", "pre-deployment audit", "second pass data structure criticism", "pattern consistency audit", etc.)

**3. Merge results:**

After both subagents return, consolidate their findings into a single report. Merge overlapping concerns (e.g. a missing constraint flagged by both). Present the final output with two sections:

```
## Backend Architecture Review

### Trigger: {USER_CONCERN}

### Go Backend Findings
[from go-reviewer]

### Database Findings
[from db-reviewer]

### Overlaps / Cross-Cutting
[issues that span both, e.g. a query that's complex because the schema is denormalized]

### Verdict
[Brief assessment: "Architecture is sound, X minor issues.", "X critical issues found before merging.", etc.]
```

## Red Flags

**Never:**
- Run reviewers **serially** — they're independent, dispatch in parallel.
- Skip running `go vet` and `go list -m` as context-gathering first.
- Re-summarize what a reviewer found — integrate and present verbatim.
- Leave a Critical issue unresolved without defending why.
- Let the DB reviewer make schema-change recommendations without also checking existing data (it's read-only, recommendations only).
- Add the reviewer's output into any actual code change — this is review only.
- Miss the consistency check — always verify that a pattern found in one handler/query is applied uniformly across all similar handlers/queries.
