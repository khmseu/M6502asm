---
description: "Require specific, diff-based commit messages; disallow vague wording."
name: "Commit Message Specificity"
---

# Commit Message Specificity

When writing or suggesting commit messages, always describe what changed in the diff with concrete, technical language.

## Hard Rules

- Do not use vague phrases such as `add/update`, `add/modify`, `misc`, `stuff`, or `changes` as the primary description.
- The header must name the actual intent and affected area (for example `fix(parser): handle form-feed whitespace in scanner`).
- For non-trivial commits, include a body with concrete details from the diff:
  - which files or subsystems changed
  - what behavior or structure changed
  - why the change was needed
- If multiple files are committed together, summarize each meaningful change in separate body bullets.
- Prefer precise verbs such as `ignore`, `enforce`, `refactor`, `validate`, `normalize`, `remove`, `rename`, or `document`.

## Commit Authoring Guidance

- Derive the message from the staged diff, not from user phrasing alone.
- If a generated message is vague, rewrite it before committing.
- Keep Conventional Commits structure valid while increasing specificity.

## Better Examples

- `chore(gitignore): ignore rewrite_unpushed_commit_messages helper script`
- `docs(plan): define phased m6502-to-xa65 translation roadmap`
- `feat(assembler): track undefined symbols across passes`

## Avoid

- `chore: add/update files`
- `chore: add/modify staged files`
- `fix: misc changes`
