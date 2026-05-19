# Contributing to idct/sftp-client

Thanks for considering a contribution. This file covers how to develop,
test, and submit changes. Security issues have their own channel — see
[SECURITY.md](SECURITY.md).

## Reporting bugs and requesting features

Use the GitHub issue templates:

- **Bug reports** — fill in the PHP / `ext-ssh2` / libssh2 versions and
  steps to reproduce. The template prompts for everything we need.
- **Feature requests** — describe the use case first, the proposed API
  second. The use case is what we need to evaluate whether the feature
  belongs in core, in an adapter package, or in the consumer's code.

If you're unsure whether something is a bug or expected behaviour, file
it as a bug — we'd rather triage than not hear about it.

For security issues, **do not** open a public issue. See
[SECURITY.md](SECURITY.md).

## Local development setup

You need:

- PHP 8.2 or newer with `ext-ssh2` (1.4+) loaded
- Composer 2.x
- Docker + docker-compose (for the functional / Behat suite)
- Optional: Xdebug for coverage and mutation testing

Clone and install:

```bash
git clone https://github.com/ideaconnect/idct-sftp-client.git
cd idct-sftp-client
composer install
```

## Running the tests

Three layers, fastest to slowest:

```bash
composer qa            # cs-fixer dry-run + PHPStan + PHPUnit
composer test          # PHPUnit unit suite only
composer behat         # Behat against the dockerised SFTP fixture
composer infection     # Mutation testing (~1-2 min)
```

The Behat suite needs the fixture container up:

```bash
tests/functional/bin/up      # start atmoz/sftp on 127.0.0.1:2222
composer behat
tests/functional/bin/down    # tear it down (and wipe the volume)
```

Coverage gate is enforced at 100% line coverage. Mutation gate is 85%
MSI / 85% Covered MSI. Both run in CI.

## Conventions

- **PHP 8.2+ only.** `declare(strict_types=1);` at the top of every
  file.
- **PHPStan level `max` on `src/`** with `phpstan-strict-rules`.
- **php-cs-fixer rules**: `@PER-CS2.0` + `@PHP82Migration` — see
  `.php-cs-fixer.dist.php`. `composer cs-fix` applies them.
- **`@phpstan-ignore-*` is allowed only inside `src/Ssh2/Ssh2Functions.php`** —
  the single documented boundary over the procedural `ext-ssh2` API.
- **No comments unless the WHY is non-obvious.** Don't restate what
  well-named code already says.
- **Tests for every change.** New behaviour gets a unit test (and a
  Behat scenario if it changes the SFTP-protocol-visible surface).
  Bug fixes get a regression test that fails before the fix and passes
  after.

## Pull request checklist

The PR template covers this; quick version:

1. `composer qa` is green.
2. `composer behat` is green (run `tests/functional/bin/up` first).
3. Coverage stays at 100% line on `src/` (`composer test` reports it).
4. Mutation gates still pass (`composer infection`).
5. `CHANGELOG.md` has an entry under `## Unreleased` describing the
   change. Group it under an existing P-section if relevant, else add
   a `### Improvements` / `### Bug fixes` heading.
6. Anything that touches the public surface (interfaces, exception
   names, method signatures, error message text in user-visible
   contexts) is reflected in [COMPATIBILITY.md](COMPATIBILITY.md)'s
   covered-surface section.

## Branches and commits

- Open PRs against `master`.
- Feature branches: any naming you like; `feature/...` or `fix/...` is
  conventional but not enforced.
- Commit messages: clear single-line subject, body if the WHY needs
  explanation. Conventional Commits aren't enforced; readable
  subject lines are.
- One logical change per PR. Bundled refactors are fine if they're
  obviously incidental (renames, drive-by formatting) and called out
  in the description.

## Reviewing your own PR

Before requesting review, re-read your diff yourself once. We catch
most of our own mistakes that way; saves a round-trip.

## License

By contributing, you agree your contribution will be licensed under the
same [MIT license](LICENSE) as the rest of the project.
