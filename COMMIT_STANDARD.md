# Commit message standard

We use a simple **Conventional Commits**–style format so history is scannable and tooling (changelogs, semver) can use it later.

---

## Format

```
<type>(<scope>): <short description>

[optional body]

[optional footer]
```

- **First line:** &lt; 72 characters, imperative mood (“add” not “added”), no period at the end.
- **Body:** Wrap at 72 characters. Explain *why* when it’s not obvious from the diff.
- **Footer:** Use for breaking changes and issue refs (see below).

---

## Types

| Type       | Use for |
|-----------|--------|
| `feat`    | New user-facing or API behaviour |
| `fix`     | Bug fix (behaviour or correctness) |
| `docs`    | Documentation only (README, comments, COMMIT_STANDARD, etc.) |
| `test`    | Adding or changing tests only |
| `refactor`| Code change that doesn’t fix a bug or add a feature |
| `style`   | Formatting, whitespace, no logic change (e.g. SwiftLint) |
| `chore`   | Build, tooling, deps, config (Tuist, SwiftLint, CI, etc.) |
| `ci`      | CI/CD only (workflows, actions) |
| `security`| Security-related change (validation, hardening, dependencies) |

Use the most specific type that fits. Prefer `fix` over `refactor` when something was wrong.

---

## Scope (optional but encouraged)

Narrow where the change lives. Examples:

- **`mdl`** — MDLDocument, validation, document model
- **`cbor`** — CBOR encoding/decoding (MDLDocumentCBORCoding)
- **`ui`** — ContentView, UI, UX
- **`storage`** — CredentialRepository, persistence
- **`ci`** — GitHub Actions, lint, test job
- **`deps`** — Tuist, Swift packages

Omit scope for broad or multi-area changes.

---

## Examples

**Good**

```
feat(mdl): add MDLDocument and DrivingPrivilege model
fix(cbor): reject CBOR payloads larger than 1 MiB
docs: add COMMIT_STANDARD.md
test(cbor): add decode error tests for invalid date and size
chore(ci): run tuist install before tests
ci: restrict AI review to PRs with Swift changes
security(cbor): use single invalidFormat error to avoid leaking structure
```

**Avoid**

```
Updated stuff                    # vague, past tense
fix: fix the bug                 # redundant
feat(scope): Add feature.        # period, capitalised “Add”
```

---

## Footer

- **Breaking changes:**  
  `BREAKING CHANGE: <description>` (and/or note in body).
- **Issue reference:**  
  `Refs #123` or `Fixes #123` (on its own line in the footer).

---

## Summary

1. First line: `type(scope): imperative short description` (&lt; 72 chars).
2. Body when “why” isn’t obvious; footer for breaking changes and issue refs.
3. One logical change per commit; split large PRs into multiple commits where it helps.
