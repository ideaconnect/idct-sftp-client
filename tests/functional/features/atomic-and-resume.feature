Feature: Atomic uploads and resume semantics
  In order to survive mid-transfer network failures
  As a developer using idct/sftp-client
  I want partial files cleaned up on failure, and resumable transfers on demand

  Background:
    Given I have a connected SFTP client
    And the remote directory "/data" is empty

  Scenario: Atomic upload renames the partial onto the final path
    Given I have a local file "atomic.txt" containing "atomic upload"
    When I upload "atomic.txt" to "/data/atomic.txt" with atomic mode on
    Then the remote file "/data/atomic.txt" contains "atomic upload"
    And no remote partial file is left behind in "/data"

  Scenario: Resume an upload from a server-side partial
    Given I have a local file "long.bin" containing "AAAABBBBCCCCDDDD"
    And a remote partial "/data/.long.bin.resume" exists with contents "AAAA"
    When I resume upload of "long.bin" to "/data/long.bin"
    Then the remote file "/data/long.bin" contains "AAAABBBBCCCCDDDD"
    And no remote partial file is left behind in "/data"

  Scenario: Resume a download from a server-side source into a partial local file
    Given I have a local file "partial-dl.bin" containing "AAAA"
    And the remote file "/data/source.bin" already contains "AAAABBBBCCCC"
    When I resume download of "/data/source.bin" to "partial-dl.bin"
    Then the local file "partial-dl.bin" contains "AAAABBBBCCCC"

  Scenario: Resume download is a no-op when the local file already matches
    Given I have a local file "done.bin" containing "complete"
    And the remote file "/data/done.bin" already contains "complete"
    When I resume download of "/data/done.bin" to "done.bin"
    Then the local file "done.bin" contains "complete"

  Scenario: Resume upload with an explicit byte offset honours the caller-supplied value
    # The README documents that resumeUpload can take an `offset:` argument
    # to skip auto-detection. The seed partial below holds the first 4
    # bytes ("AAAA"); the local source has 16. Passing offset=4 explicitly
    # tells the client to start from byte 4 rather than re-statting the
    # remote partial — same net result, different decision path.
    Given I have a local file "explicit.bin" containing "AAAABBBBCCCCDDDD"
    And a remote partial "/data/.explicit.bin.resume" exists with contents "AAAA"
    When I resume upload of "explicit.bin" to "/data/explicit.bin" with explicit offset 4
    Then the remote file "/data/explicit.bin" contains "AAAABBBBCCCCDDDD"
    And no remote partial file is left behind in "/data"
