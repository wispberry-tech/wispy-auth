---
name: tension-review
description: 'Trigger phrases: "tension points", "structural tensions", "check the DB for tensions", "check the Go backend for tensions", "check the frontend for tensions", "architecture smells", "patterns that will hurt later", "ripple effects", "compounding maintenance debt", "what will break first".'
---

# Tension Review

Find structural tension points — patterns that create compounding maintenance debt and ripple effects — in any layer of the codebase.

Tension points are NOT bugs or per-table/per-file issues. They are cross-cutting patterns: the same wrong structure repeated, fragile invariants enforced in application code, state owned by two things at once, duplicated infrastructure per entity type. They make the codebase harder to understand and modify over time.

## When to Use

- Something "feels off" about the architecture but you can't name it
- Adding a feature requires touching many files that "should just work"
- Same pattern duplicated across entity types (tags tables, auth checks, state sync)
- Suspect the original design didn't survive contact with real features
- Pre-merge audit: "will this design hurt us in 6 months?"

## How to Dispatch

**1. Determine the area(s) to check.** The user may specify:
- "check the DB" / "database tensions" / "schema smells" → dispatch db reviewer
- "check the Go backend" / "Go code tensions" / "handler patterns" → dispatch Go reviewer
- "check the frontend" / "component tensions" / "state structure" → dispatch component reviewer
- "check everything" / "full tension audit" → dispatch all three in parallel

If the user doesn't specify an area, ask via the `ask` tool: which area(s) should be checked for tension points?

**2. For each area, gather context then dispatch:**

Read the prompt template at the appropriate `skill://` URI only when dispatching that reviewer:
- DB: `skill://tension-review/db-tensions.md`
- Go backend: `skill://tension-review/go-tensions.md`
- Frontend: `skill://tension-review/component-tensions.md`

**Placeholders in all templates:**
- `{GO_PACKAGE_NAME}` — Go module name (from `go list -m`)
- `{USER_CONCERN}` — one-line summary of what triggered the review

**3. Merge results if multiple areas were checked.** Present findings grouped by layer. Call out cross-layer tensions (e.g. a DB pattern that forces complex Go code, or a Go handler pattern that exists because the component structure pushed state to the wrong place).

## Red Flags

**Never:**
- Run reviewers serially when checking multiple areas — dispatch in parallel.
- Skip context-gathering (go list -m, migration listing, git diff) before dispatching.
- Re-summarize what a reviewer found — integrate and present verbatim.
- Treat tension points as bugs to fix immediately — they are structural patterns to evaluate.
