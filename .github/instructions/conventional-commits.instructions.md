---
description: "Enforce Conventional Commits 1.0.0 format."
name: "Conventional Commits Enforcement"
---

# Conventional Commits Enforcement

Always use Conventional Commits format for any commit message you write or suggest:

```text
<type>[optional scope]: <description>

[optional body]

[optional footer(s)]
```

## Required Rules

- The header must include a valid type and a colon-space separator.
- Always use lowercase types and short imperative descriptions.
- For any non-trivial change, include a detailed commit body describing context, rationale, and key implementation details.
- Reserve header-only commit messages for changes limited to spelling corrections, whitespace/indentation adjustments, or comment-only updates (no code logic changes).
- Use `feat` for new features and `fix` for bug fixes.
- Use additional types consistently when appropriate, such as `docs`, `refactor`, `perf`, `test`, `chore`, `ci`, and `build`.
- If the change is breaking, mark it with `!` in the header and/or a `BREAKING CHANGE:` footer.

## Commit Authoring Behavior

- When asked to create a commit message, output only Conventional Commits-compliant options.
- When asked to commit code changes, create a Conventional Commits-compliant message automatically unless the user explicitly provides a different message.
- If the user-provided message is non-conforming, suggest a compliant rewrite before committing.
- Keep each commit focused on one logical change whenever possible.
- Default to detailed commit messages for non-trivial changes (header + explanatory body, and footers when useful).
- Use concise header-only messages only for trivial edits.

## SemVer Mapping Reminder

- `fix` implies PATCH-level change.
- `feat` implies MINOR-level change.
- `BREAKING CHANGE` implies MAJOR-level change regardless of type.

## Good Examples

- `feat(auth): add OAuth device flow`
- `fix(cache): prevent stale entries after invalidation`
- `refactor(parser)!: remove legacy fallback path`
- `docs: clarify installation steps`

Detailed non-trivial example:

```text
feat(auth): add OAuth device flow support

Implement device authorization grant for CLI sign-in flows.
Adds polling-based token retrieval with timeout handling and user-friendly status prompts.

Refs: #214
```

## Avoid

- `update stuff`
- `misc fixes`
- `bugfix` (missing required `:` format)
- Mixed unrelated changes in one commit message
