<!--
Thanks for the PR. Please fill in the sections that apply — feel free
to delete the ones that don't (e.g. drop the "Behaviour change" block
for pure refactors). Brief is fine; the checklist matters more than
the prose.
-->

## What this changes

<!-- One or two sentences. What was wrong / missing, what does the change do. -->

## Why

<!-- The motivation. Link to an issue if there is one (`Closes #123`). -->

## Behaviour change

<!--
Delete this section if the change is internal only.

If the public surface (anything in COMPATIBILITY.md "Covered surface")
changes, describe:
- What consumers will see differently
- Whether it's a deprecation, an additive change, or a breaking change
- Any migration steps callers need
-->

## Checklist

- [ ] `composer qa` is green (PHPStan max + PHPUnit + cs-fixer dry-run)
- [ ] `composer behat` is green against the docker fixture
      (`tests/functional/bin/up`)
- [ ] Coverage stays at 100% line on `src/`
- [ ] `composer infection` still passes the configured gates
- [ ] `CHANGELOG.md` has an entry under `## Unreleased`
- [ ] [COMPATIBILITY.md](../blob/master/COMPATIBILITY.md) updated if the
      covered surface changed
- [ ] New behaviour has a unit test; bug fix has a regression test
