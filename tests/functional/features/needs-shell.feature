@needs-shell
Feature: Operations that need server-side shell access (SCP / ShellSumRemoteHasher)
  In order to keep the client's SCP path and shell-based checksum verification
  exercised end-to-end despite the default atmoz/sftp fixture being chrooted
  to `internal-sftp`
  As a developer using idct/sftp-client
  I want these scenarios to run against the OpenSSH fixture (port 2223)
  which provides a full daemon with shell + `scp` + `sha256sum`

  # CI invokes Behat once per backend (atmoz at 2222, openssh at 2223).
  # The atmoz job opts these scenarios OUT via `--tags='~@needs-shell'`;
  # the openssh job runs everything.

  Background:
    Given I have a connected SFTP client
    And the remote directory "/data" is empty

  Scenario: scpUpload pushes a local file via the SCP channel
    Given I have a local file "scp-up.txt" containing "scp-payload"
    When I scpUpload "scp-up.txt" to "/data/scp-up.txt"
    Then the remote file "/data/scp-up.txt" contains "scp-payload"

  Scenario: scpDownload pulls a remote file via the SCP channel
    Given the remote file "/data/scp-dl.bin" already contains "scp-down-bytes"
    When I scpDownload "/data/scp-dl.bin" to "scp-dl.bin"
    Then the local file "scp-dl.bin" contains "scp-down-bytes"

  Scenario: ShellSumRemoteHasher verifies a clean round-trip using sha256sum
    # Install the shell-based hasher; subsequent upload + download
    # compute the digest both ends and throw on mismatch. A clean
    # round-trip must NOT throw.
    Given I have a local file "checked.bin" containing "verified-by-shellsum"
    When I install a ShellSumRemoteHasher
    And I upload "checked.bin" to "/data/checked.bin"
    Then the remote file "/data/checked.bin" contains "verified-by-shellsum"
