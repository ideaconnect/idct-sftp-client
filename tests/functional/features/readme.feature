Feature: README examples — every documented code sample backed by a scenario
  In order to keep the README's guarantees honest
  As a maintainer reviewing the public docs
  I want every example that isn't already covered by a dedicated
  feature file to have a Behat scenario behind it

  Background:
    Given I have a connected SFTP client
    And the remote directory "/data" is empty

  # ─── README § Quick start ──────────────────────────────────────────

  Scenario: Quick start round-trips a small file
    Given I have a local file "hello.txt" containing "hello sftp"
    When I upload "hello.txt" to "/data/hello.txt"
    And I download "/data/hello.txt" to "back.txt"
    Then the local file "back.txt" contains "hello sftp"

  # ─── README § Authentication — CredentialsLoaderInterface ──────────

  Scenario: setCredentialsLoader resolves credentials at connect-time
    Given a StaticCredentialsLoader carrying the fixture credentials
    When I connect through the loader with no explicit credentials
    Then the connection succeeds
    And the client's getCredentials returns the loader-resolved value

  # ─── README § Operations — enableFileSizeVerification ──────────────

  Scenario: enableFileSizeVerification accepts a clean upload
    Given the client has file-size verification enabled
    And I have a local file "size-ok.txt" containing "12345"
    When I upload "size-ok.txt" to "/data/size-ok.txt"
    Then the remote file "/data/size-ok.txt" contains "12345"

  # ─── README § Atomic uploads & resume — disableAtomicUploads ───────

  Scenario: disableAtomicUploads writes the destination directly (no partial)
    Given the client has atomic uploads disabled
    And I have a local file "direct.txt" containing "direct-bytes"
    When I upload "direct.txt" to "/data/direct.txt"
    Then the remote file "/data/direct.txt" contains "direct-bytes"
    And no remote partial file is left behind in "/data"

  # ─── README § Recursive directory operations — walk() ──────────────

  Scenario: walk() yields nested entries in post-order
    Given I have a local directory "walk-tree" with files:
      | path      | contents |
      | a.txt     | a        |
      | sub/b.txt | bb       |
    When I uploadDirectory "walk-tree" to "/data/walk-demo"
    And I walk "/data/walk-demo"
    Then the walk yielded 3 entries
    And every directory in the walk appears after its children

  # ─── README § Retry policy — runtime swap + ping ───────────────────

  Scenario: setRetryPolicy(NoRetryPolicy) at runtime takes effect
    Given I install a NoRetryPolicy on the client
    And I have a local file "single-try.txt" containing "no retry"
    When I upload "single-try.txt" to "/data/single-try.txt"
    Then the remote file "/data/single-try.txt" contains "no retry"

  Scenario: ping() returns true on a healthy session
    Then ping returns true

  Scenario: ping() returns false after close()
    When I close the client
    Then ping returns false

  # ─── README § Checksum verification — RedownloadRemoteHasher ───────

  Scenario: RedownloadRemoteHasher passes on a clean round-trip
    Given the client uses a RedownloadRemoteHasher with algorithm "sha256"
    And I have a local file "checked.txt" containing "verified content"
    When I upload "checked.txt" to "/data/checked.txt"
    Then the remote file "/data/checked.txt" contains "verified content"

  # ─── README § Prefixes ─────────────────────────────────────────────

  Scenario: setRemotePrefix applies to relative paths
    Given the client has remote prefix "/data/sub/"
    And I have a local file "prefixed.txt" containing "with-prefix"
    When I upload "prefixed.txt" to "prefixed.txt"
    Then the remote file "/data/sub/prefixed.txt" contains "with-prefix"

  Scenario: an absolute remote path bypasses the remote prefix (T6 contract)
    Given the client has remote prefix "/data/sub/"
    And I have a local file "abs.txt" containing "absolute-target"
    When I upload "abs.txt" to "/data/abs.txt"
    Then the remote file "/data/abs.txt" contains "absolute-target"

  # ─── README § Logging — setLogContext ──────────────────────────────

  Scenario: setLogContext merges static fields into every record
    Given the client has a capturing logger
    And the client log context is "tenant" = "acme" and "request_id" = "req-1"
    And I have a local file "logged.txt" containing "log this"
    When I upload "logged.txt" to "/data/logged.txt"
    Then every captured log record carries context key "tenant" with value "acme"
    And every captured log record carries context key "request_id" with value "req-1"
    And every captured log record carries a "correlation_id" key

  # ─── README § Error handling — SshException root catch ─────────────

  Scenario: Every library error is caught by the SshException root
    When I download "/data/no-such-file" to "missing.txt"
    Then a single SshException was thrown
