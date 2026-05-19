# REVIEW.md — Push to Higher Production Grade

## Goal

The library is at **"shipped 1.1, all tests green, PHPStan max clean,
100% line coverage"**. That's the floor for production-grade, not the
ceiling. A production-grade review pushes for:

- **Zero documentation lies** — every PHPDoc and every README claim
  matches behavior.
- **No untested code paths** — branch + mutation coverage gaps closed
  or justified.
- **API consistency** — public surface free of asymmetric / orphan
  methods.
- **Conceptual coherence** — one way to do each thing; no half-finished
  refactors.
- **Hard-edge correctness** — error / edge-case handling that doesn't
  paper over bugs.
- **A README a stranger can use** — every snippet compiles, every
  cross-reference resolves.

This file is the **plan**, not the work. Findings produced by executing
this plan land in a separate `FINDINGS.md` (or per-phase commits) — not
in this file.

## Methodology

Every finding gets a stable ID and the shape below (template at the
bottom of this file):

```
F-<phase>-<NNN>  [severity: critical | important | nice]
File: path/to/file.php:42-58
Category: docs | api | coding | concept | security | test | readme
Summary: One sentence.
Evidence: What I observed (code snippet, command output, test result).
Why it matters: One paragraph.
Recommendation: Concrete fix (file + diff sketch, OR "delete this").
```

Three severities, defined by what they block:

- **Critical** — bug, security gap, or doc that would mislead a caller
  into breaking production. Fix in this review pass.
- **Important** — inconsistency, broken doc, missing test, leaky
  abstraction. Fix unless it cascades into a larger refactor (then
  spin out a follow-up).
- **Nice** — polish, style, naming. Bundle into one trailing PR.

---

## Phase R1 — Code Review (`src/`)

Walk every file in `src/` against the checks below. ~40 files; budget
~10 minutes per file.

### Style & idiom
- [ ] `declare(strict_types=1)` at top of every file. Run:
  `grep -L 'declare(strict_types=1)' src/**/*.php`
- [ ] `final` where extension isn't intended. List non-`final` classes;
  justify each.
- [ ] `readonly` on every value-object property whose lifetime is
  set-once.
- [ ] No `@phpstan-ignore` outside `src/Ssh2/Ssh2Functions.php`:
  `grep -rn 'phpstan-ignore' src/ | grep -v Ssh2Functions`

### Dead / under-exercised code
- [ ] Method coverage is 83.74% — find the ~20 untested public/protected
  methods and either cover them or delete. Start:
  `XDEBUG_MODE=coverage composer test`, then walk
  `build/coverage/html/`.
- [ ] Class coverage is 56.25% — eight untested classes. For each:
  test, justify (e.g., value object exercised transitively), or delete.
- [ ] Branch coverage 94.58% → 45 uncovered branches. Map each to
  one of: *intentionally unreachable*, *needs test*, or *delete the
  dead guard*.

### Defensive over-engineering
- [ ] Catch sites: every `catch (\Throwable)` followed by silent
  log-and-swallow must justify itself or become a typed re-throw.
- [ ] Null-coalescing guards on values the constructor already
  guarantees non-null — tighten the type, see what PHPStan breaks,
  delete the redundant `?? default`.
- [ ] `if (! $x) throw …` chains where `$x` cannot be `false` by type.

### Exception hygiene
- [ ] Every `@throws` reflects what actually escapes the method (no
  stale entries, no missing ones).
- [ ] No `\Exception` / `\RuntimeException` thrown directly in `src/` —
  everything routes through the `SshException` hierarchy.
- [ ] Exception messages don't leak credentials or environment data.
  Spot-check `connect()`, `authorize()`, `verifyAgainstKnownHosts()`.

### Raise the static-analysis floor (optional)
- [ ] Try `phpstan --level 11` (above max strict flag) on `src/`;
  record what surfaces. Keep at max if level 11 adds noise without
  catching real bugs.
- [ ] Run `vendor/bin/psalm` (already wired by `.github/workflows/sast.yml`)
  and triage every error in the SARIF report.

---

## Phase R2 — Documentation Review

The PHPDoc pass just landed. This phase checks that what's there is
*correct*, not just *present*.

### PHPDoc accuracy
- [ ] Every `@param`, `@return`, `@throws` matches actual behavior.
  Method-by-method walk, ~5 files per session.
- [ ] No `{@inheritDoc}` markers on methods whose interface has no doc
  to inherit (silent doc loss):
  `grep -B5 'inheritDoc' src/ | grep -B5 'function'`
- [ ] `@see` references point at symbols that exist:
  `grep -rohE '\{@see [^}]+\}' src/ | sort -u`, validate each.
- [ ] No tautological PHPDoc (`@param string $path The path`). Remove.

### Interface vs. implementation drift
- [ ] List public methods on `SftpClient` that are NOT on
  `SftpClientInterface` — every one is either (a) a leak that should
  be hoisted onto the interface, or (b) deliberately client-only
  (document why with an inline comment).
  **Known suspect:** `getRemoteHasher` / `setRemoteHasher` (not on
  interface despite being a documented feature).
- [ ] Reverse check: every interface method has an implementation.
- [ ] Optional parameters in the implementation that aren't in the
  interface (or vice versa).

### Cross-file consistency
- [ ] CHANGELOG entries match the symbols they cite (e.g., "new
  `ConflictPolicy` enum" — check the enum exists, has the documented
  cases, is wired into the documented methods).
- [ ] Behat scenario count claimed in CHANGELOG vs. actual count in
  `tests/functional/features/`.
- [ ] Symbol names in CHANGELOG that don't exist in current `src/`
  (renamed mid-development, never reconciled).

---

## Phase R3 — README vs. Behavior Reality Check

The README is the contract a new user reads first. Every claim there
is under review.

### Every code sample compiles and runs
- [ ] Extract every fenced PHP block from `README.md` into
  `tests/readme/snippet-NN.php`. Each must `php -l` cleanly and
  reference only public-surface symbols. This becomes an automated
  harness against future doc drift.
- [ ] For each snippet, confirm the methods called, their argument
  order, and the documented behavior all match `src/` as it stands
  today.

### "Verified by Behat" links
- [ ] Every `> **Verified by Behat:** …` line points at a real
  scenario:
  `grep -oE 'features/[a-z-]+\.feature' README.md | sort -u`, check
  each file exists and contains a scenario whose name matches.
- [ ] Each cited scenario actually exercises the feature it's cited
  *for* (catch copy-paste rot — e.g., a "checksum verification" link
  landing on an atomic-upload scenario).

### Surface coverage
- [ ] Every public method on `SftpClientInterface` is mentioned in
  README at least once, or deliberately omitted ("see API reference").
  Produce the gap list.
- [ ] Every enum (`AuthMode`, `ConflictPolicy`, `SymlinkPolicy`,
  `SecurityProfile`, `UnknownHostPolicy`, `FingerprintAlgorithm`,
  `FingerprintEncoding`, `EntryType`) has at least one prose example.
- [ ] Every option that takes a callable / interface
  (`CredentialsLoaderInterface`, `ProgressListenerInterface`,
  `RetryPolicyInterface`, `RemoteHasherInterface`) has a
  copy-pasteable minimal implementation example, not just "implement
  this".

### Out-of-date sections
- [ ] "Requirements" table reflects current `composer.json` `require:`.
- [ ] "Upgrading from 0.x" — every left-column 0.x symbol existed in 0.x.
- [ ] "Features" table links land on existing anchors (TOC drift).

---

## Phase R4 — Conceptual Issues

### API ergonomics
- [ ] `SftpClient.php` is ~2,500 lines. List each method's role and
  group; decide whether to split into traits / collaborators
  (`AuthDispatcher`, `DirectoryWalker`, `TransferEngine`) or keep as
  one cohesive client. Either decision is fine — what's not fine is
  half-splitting.
- [ ] Constructor parameter list: 5 args, two bools. Audit for
  "constructor flag soup". Should `atomicUploads` /
  `fileSizeVerificationEnabled` move into a `ClientOptions` object?
- [ ] Setter chains return `self` for fluent style; verify no setter
  returns something else accidentally.

### Asymmetric pairs
- [ ] Every `enable*` has a `disable*`; every `set*` has a `get*`:
  `grep -E '(enable|disable|set|get)[A-Z]' src/SftpClientInterface.php | sort`
- [ ] `upload` / `download` parameter ordering symmetric where it can be.
- [ ] `uploadDirectory` returns `UploadResult`,
  `downloadDirectory` returns `DownloadResult` — structurally identical.
  Decide: keep distinct types for clarity, or unify as
  `DirectoryTransferResult`.

### Half-finished refactors
- [ ] CHANGELOG mentions `P9 alternative backend deferred`. Are there
  stale interfaces / abstractions in `src/` scaffolded for that
  evaluation and now sitting unused? Find and delete.
- [ ] `SymlinkPolicy::Follow` is wired in `uploadDirectory()` but
  what about `walk()` and `downloadDirectory()`? Map symlink-policy
  usage across every method that accepts it.
- [ ] `bestEffort` flag: present on `uploadDirectory` /
  `downloadDirectory` — is the result-collection semantics identical?
  Are failures collected with the same `DirectoryFailure` type?

---

## Phase R5 — Bad Coding Patterns

Specific anti-patterns to grep for and triage.

### Loose comparisons
- [ ] `grep -nrE '[!=]==?' src/ | grep -v '!==' | grep -v '==='` —
  anything still `==` / `!=` needs a justification or a fix.

### Suppressed errors outside the ext-ssh2 boundary
- [ ] `grep -rn '@[a-z]' src/ | grep -v Ssh2Functions.php` — the
  wrapper is the documented boundary; `@` elsewhere needs explicit
  justification.

### Magic numbers
- [ ] Mode bits (`0o755`, `0o644`), control-char ranges, timeout
  defaults — all should be named constants or referenced via class
  const, not scattered as literals.

### Resource lifetime
- [ ] Every `fopen` / `opendir` / `stream_socket_client` has a
  matching `fclose` / `closedir` in `finally`. The 0.x line had bug
  B11 (`opendir` leak); make sure new code didn't reintroduce.
  `grep -nE 'fopen|opendir|stream_socket_client' src/` then walk
  each hit looking for `try/finally`.

### Time-of-check vs. time-of-use
- [ ] `stat()` then act: each such pair should justify itself
  (uploads tolerate the race; destructive ops shouldn't).
- [ ] `clearstatcache(true, $path)` — called before EVERY sensitive
  stat, or only some?

### Sleep / blocking
- [ ] `usleep` / `sleep` outside the retry policy + auth rate limiter.
  Should be none.

### Floats for money / time-as-int
- [ ] `microtime(true) - $started` arithmetic — make sure all
  durations log as `int` milliseconds (already the convention) and no
  float second values leak into log context.

---

## Phase R6 — Cross-cutting Concerns

### Logging
- [ ] Every operation logs `started` + `ok|failed` (the contract
  implied by the §P7 log-points matrix). Walk every public method and
  list those that emit `started` debug but no terminating log.
- [ ] Log levels match the matrix (`notice` for auth rejection,
  `info` for happy-path completion, `warning` for retry, `error` for
  hard failure).
- [ ] No log call leaks a secret. The redaction lint covers literal
  `password` / `passphrase` tokens; spot-check for derived names like
  `secret`, `token`, `apiKey`, `key` in context maps.

### Retry
- [ ] `isRetryable()` allowlist is the single source of truth.
  Confirm no method side-steps the `retry()` wrapper.
- [ ] Lazy reconnect path (`ping()` returning false → reconnect →
  retry) is covered by a fault-injection scenario; if not, add one
  under `tests/functional/features/fault-injection.feature`.

### Atomic upload correctness
- [ ] Audit `partialPath()`: what if `dirname()` returns `.` AND the
  basename starts with `.`? Verify the resulting path is sensible.
- [ ] Failed uploads cleanup the partial; resume uploads don't (this
  is documented). Verify `resumeUpload` can't ALSO leave an orphan
  partial under any failure mode (e.g., rename succeeds then verify
  fails — does the partial path still exist? Should it?).

### Coverage gaps that mask real bugs
- [ ] The 45 uncovered branches from R1 — re-walk with the lens
  "is this branch reachable from a user-callable path? If so, write
  the test."
- [ ] Mutation testing: run `composer infection`. Record current MSI
  and covered-MSI. Inspect every escaped mutant in core files (not
  the adapter). Each escape is *bug*, *missing test*, or *equivalent
  mutant — ignore*.

---

## Phase R7 — README.md Editorial Pass

Pure-prose pass over the README. Most R3 checks were behavioral; this
is editorial.

### Structure
- [ ] TOC entries match section anchors (extract every heading and
  every `[…](#…)` link, diff the two sets).
- [ ] Heading levels coherent — no `###` under `#` without an
  intervening `##`.
- [ ] Sections in a logical user-journey order (install → quick
  start → auth → ops → advanced → reference → ops/dev).

### Tone & length
- [ ] Every section answers "would a new user need this paragraph?"
  Cut anything that's actually maintainer-facing (move to AGENTS.md
  or CONTRIBUTING.md).
- [ ] No "we'll add this later" phrasing for features that already
  shipped (residue from the CHANGELOG follow-up pass).
- [ ] No internal acronyms (`P3`, `P7`) without a one-line gloss.

### Examples
- [ ] Every code block has a one-line "what this shows" caption
  above it. New users scan for code blocks first; the prose around
  comes later.
- [ ] Long examples (>20 lines) cite the runnable version in
  `examples/`.
- [ ] No example uses a literal password ("super-secret") without a
  neighbouring note that this is illustrative, not a pattern.

### Cross-references
- [ ] Every `[text](path)` link resolves on the local filesystem:
  `grep -oE '\[[^]]+\]\([^)]+\)' README.md` → extract → check each
  path or anchor.
- [ ] Anchors used inside the README all exist (TOC drift again).

---

## Tooling & commands cheat sheet

```bash
# Static
composer stan                           # PHPStan max on src/
composer cs                             # PHP-CS-Fixer dry-run
vendor/bin/psalm                        # if installed

# Coverage + mutation
XDEBUG_MODE=coverage composer test      # PHPUnit + clover + HTML
composer infection                      # mutation score

# Functional
tests/functional/bin/up
composer behat
SFTP_PORT=2223 composer behat           # OpenSSH 9.x backend
tests/functional/bin/down

# Audit
composer audit --no-dev --locked

# Reviewer greps
grep -rn '@phpstan-ignore' src/ | grep -v Ssh2Functions
grep -rn '@[a-z]' src/ | grep -v Ssh2Functions \
   | grep -v '@param\|@return\|@throws\|@see\|@var\|@template\|@phpstan'
grep -rohE '\{@see [^}]+\}' src/ | sort -u
grep -rn 'TODO\|FIXME\|XXX\|HACK' src/ tests/
grep -L 'declare(strict_types=1)' src/**/*.php
```

---

## Sequencing

Run in order; each phase produces a findings list before the next
starts:

1. **R7** (README editorial) — fastest; frames everything else.
2. **R3** (README vs. behavior) — finds drift that R1 / R2 will need
   to fix.
3. **R2** (documentation accuracy) — sets up R1.
4. **R1** (code review) — the bulk of the work.
5. **R5** (anti-patterns) — runs in parallel with R1, same files.
6. **R4** (conceptual) — needs R1 / R5 context.
7. **R6** (cross-cutting) — final sweep.

Each phase ends with findings rolled into `FINDINGS.md`. The work
of *fixing* findings is a separate PR cycle — don't conflate review
with rewrite.

---

## Definition of done

The review pass is complete when:

- Every **Critical** finding fixed and verified by a regression test.
- Every **Important** finding has a tracking entry or a follow-up
  commit on a named branch.
- **Nice** findings bundled into one polish PR.
- PHPStan max clean, line coverage stays at 100%, branch coverage
  ≥ 95% (revised from an earlier ≥ 97% target — see note below),
  mutation MSI ≥ 88 / covered-MSI ≥ 90 (calibrated 2–3 pp under
  the new baseline after fixes).

> **Branch coverage target note:** the earlier ≥ 97% target was
> aspirational. Empirically, Xdebug counts pathological "branches"
> inside `match` arm bodies (each line of an array literal returns
> "1/2 branches covered" even when the arm is exercised end-to-end)
> and inside `min()` / `max()` call chains that PHPStan's
> `int<0, max>` type already proves cannot take their negative
> arm. After Bundle 3 the realistic ceiling against the current
> mutator/test set is ~95%; chasing the last 2 pp would force
> contrived race-condition tests (e.g., "what if `filesize()`
> returned `false` between two adjacent calls") with no real
> bug-catching value. The mutation score (MSI / covered MSI) is
> the better signal for "is this branch behaviour exercised."
- README snippet-extraction harness in `tests/readme/` passes
  (every fenced block compiles).
- AGENTS.md "Conventions" updated if the review surfaces a new one
  worth codifying.

---

## Finding template (copy into FINDINGS.md)

```markdown
## F-R<phase>-<NNN> — <short title>

- **Severity:** critical | important | nice
- **Category:** docs | api | coding | concept | security | test | readme
- **File:** <path:lines>
- **Evidence:**
  ```
  <quoted code / command output>
  ```
- **Why it matters:**
  <one paragraph>
- **Recommendation:**
  <concrete fix; file + diff sketch, or "delete this">
- **Estimated effort:** trivial | <2h | half-day | day+
```
