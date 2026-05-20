Feature: Directory operation policies (Conflict / Symlink / bestEffort)
  In order to be confident the documented policy knobs behave the same way
  end-to-end against a real SFTP server as they do under mocks
  As a developer using idct/sftp-client
  I want the per-policy scenarios duplicated against the live atmoz/sftp fixture

  Background:
    Given I have a connected SFTP client
    And the remote directory "/data" is empty

  # ── ConflictPolicy ────────────────────────────────────────────────────

  Scenario: uploadDirectory with onConflict=Skip leaves pre-existing remote files alone
    Given the remote file "/data/dest/a.txt" already contains "OLD"
    And I have a local directory "src" with files:
      | path  | contents |
      | a.txt | NEW      |
      | b.txt | BB       |
    When I uploadDirectory "src" to "/data/dest" with policies "onConflict=Skip"
    Then the upload result reports 1 files and 2 bytes transferred
    And the upload result reports 1 skipped entry
    And the remote file "/data/dest/a.txt" contains "OLD"
    And the remote file "/data/dest/b.txt" contains "BB"

  Scenario: uploadDirectory with onConflict=Fail raises on the existing file
    Given the remote file "/data/dest/a.txt" already contains "OLD"
    And I have a local directory "src" with files:
      | path  | contents |
      | a.txt | NEW      |
    When I uploadDirectory "src" to "/data/dest" with policies "onConflict=Fail"
    Then a filesystem error is reported

  # NOTE: Overwrite is the default ConflictPolicy, but actual overwrite
  # behaviour against atmoz/sftp depends on the server's SSH_FXP_RENAME
  # support (default OpenSSH SFTP follows draft-04 and refuses RENAME
  # over an existing path unless the `posix-rename@openssh.com`
  # extension is in use, which ext-ssh2's `ssh2_sftp_rename` does not
  # currently negotiate). Atomic-rename overwrite is therefore a
  # server-config detail, not a client-policy detail; the unit-level
  # coverage in `DirectoryPolicyTest::testUploadDirectoryOverwriteRemainsDefault`
  # locks down the client side. The Skip / Fail / bestEffort cases
  # below DO live in this layer because they're policy decisions the
  # client makes itself, before any rename happens.

  Scenario: downloadDirectory with onConflict=Skip leaves pre-existing local files alone
    Given the remote file "/data/src/a.txt" already contains "remote-A"
    And the remote file "/data/src/b.txt" already contains "remote-B"
    And I have a local file "dest/a.txt" containing "LOCAL"
    When I downloadDirectory "/data/src" to "dest" with policies "onConflict=Skip"
    Then the download result reports 1 files and 8 bytes transferred
    And the download result reports 1 skipped entry
    And the local file "dest/a.txt" contains "LOCAL"
    And the local file "dest/b.txt" contains "remote-B"

  # ── SymlinkPolicy + cycle detection ──────────────────────────────────

  Scenario: uploadDirectory with symlinks=Follow resolves a local symlink to its target file
    Given I have a local directory "src" with files:
      | path       | contents     |
      | target.txt | real-content |
    And the local directory "src" has a symlink "link.txt" pointing to "target.txt"
    When I uploadDirectory "src" to "/data/dest" with policies "symlinks=Follow"
    Then the upload result reports 2 files and 24 bytes transferred
    And the remote file "/data/dest/target.txt" contains "real-content"
    And the remote file "/data/dest/link.txt" contains "real-content"

  Scenario: uploadDirectory with default (Skip) symlinks records the link as skipped
    Given I have a local directory "src" with files:
      | path       | contents |
      | target.txt | real     |
    And the local directory "src" has a symlink "link.txt" pointing to "target.txt"
    When I uploadDirectory "src" to "/data/dest"
    Then the upload result reports 1 files and 4 bytes transferred
    And the upload result reports 1 skipped entry

  Scenario: uploadDirectory with symlinks=Follow detects a self-cycle without infinite recursion
    # src/inner/real.txt exists. src/loop is a symlink pointing back at
    # src itself — a classic self-cycle. Without cycle detection this
    # scenario would either hang the suite or blow PHP's recursion limit.
    Given I have a local directory "src" with files:
      | path            | contents |
      | inner/real.txt  | real     |
    And the local directory "src" has a symlink "loop" pointing to "self"
    When I uploadDirectory "src" to "/data/dest" with policies "symlinks=Follow"
    Then the upload result reports 1 files and 4 bytes transferred
    And the upload result records a cycle skip
    And the remote file "/data/dest/inner/real.txt" contains "real"

  Scenario: uploadDirectory with symlinks=Follow detects a cycle nested deep in the tree
    # The cycle is on /src/A/B (loop -> /src/A/B), not at the upload root.
    # Proves the inode-set carries across recursive descents — a "only
    # check the upload root inode" detector would miss this.
    Given I have a local directory "src" with files:
      | path          | contents |
      | A/B/leaf.txt  | leaf     |
    And the local directory "src/A/B" has a symlink "loop" pointing to "self"
    When I uploadDirectory "src" to "/data/dest" with policies "symlinks=Follow"
    Then the upload result reports 1 files and 4 bytes transferred
    And the upload result records a cycle skip
    And the remote file "/data/dest/A/B/leaf.txt" contains "leaf"

  # ── bestEffort ────────────────────────────────────────────────────────

  Scenario: uploadDirectory bestEffort=true collects per-file conflicts instead of aborting
    Given the remote file "/data/dest/b.txt" already contains "EXISTS"
    And I have a local directory "src" with files:
      | path  | contents |
      | a.txt | aaa      |
      | b.txt | bb       |
    When I uploadDirectory "src" to "/data/dest" with policies "onConflict=Fail,bestEffort=true"
    Then the upload result reports 1 files and 3 bytes transferred
    And the upload result reports 1 failure
    And the remote file "/data/dest/a.txt" contains "aaa"
    And the remote file "/data/dest/b.txt" contains "EXISTS"

  Scenario: uploadDirectory bestEffort=false (default) propagates the conflict
    Given the remote file "/data/dest/a.txt" already contains "EXISTS"
    And I have a local directory "src" with files:
      | path  | contents |
      | a.txt | NEW      |
    When I uploadDirectory "src" to "/data/dest" with policies "onConflict=Fail"
    Then a filesystem error is reported
