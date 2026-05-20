Feature: Path safety against malicious input
  In order to safely accept remote-path arguments derived from untrusted sources
  As a developer using idct/sftp-client
  I want path traversal patterns rejected before any network I/O reaches the
  SFTP server, and absolute paths to opt out of the configured prefix.

  (Null-byte and CR/LF cases are covered exhaustively in PathValidatorTest;
  Behat scenarios are limited to characters that survive .feature file parsing.)

  Background:
    Given I have a connected SFTP client
    And the remote directory "/data" is empty

  Scenario: Upload rejects relative traversal in target path
    Given I have a local file "src.txt" containing "data"
    When I upload "src.txt" to "/data/../etc/passwd"
    Then a path validation error is reported

  Scenario: Upload rejects traversal in target path even with no prefix
    Given I have a local file "src.txt" containing "data"
    When I upload "src.txt" to "../etc/passwd"
    Then a path validation error is reported

  Scenario: Download rejects path traversal in source path
    When I download "/data/../etc/passwd" to "out.txt"
    Then a path validation error is reported

  Scenario: Remove rejects literal ".." component
    When I remove "/data/.."
    Then a path validation error is reported

  Scenario: Make directory rejects literal "." component
    When I create directory "/data/."
    Then a path validation error is reported

  Scenario: getFileList rejects traversal in directory path
    When I download "/data/../" to "list.txt"
    Then a path validation error is reported
