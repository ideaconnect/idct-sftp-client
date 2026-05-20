Feature: Uploading and downloading files
  In order to move data between local and remote hosts
  As a developer using idct/sftp-client
  I want round-trip transfers to be byte-exact

  Background:
    Given I have a connected SFTP client
    And the remote directory "/data" is empty

  Scenario: Round-trip a small file via SFTP
    Given I have a local file "hello.txt" containing "hello sftp"
    When I upload "hello.txt" to "/data/hello.txt"
    Then the remote file "/data/hello.txt" contains "hello sftp"

  Scenario: Download a file we just uploaded
    Given I have a local file "src.txt" containing "round trip"
    When I upload "src.txt" to "/data/src.txt"
    And I download "/data/src.txt" to "dl.txt"
    Then the local file "dl.txt" contains "round trip"

  Scenario: Downloading a missing file raises a transfer error
    When I download "/data/no-such-file" to "missing.txt"
    Then a transfer error is reported

  Scenario: Uploading a non-existent local file raises a transfer error
    When I upload "ghost.txt" to "/data/ghost.txt"
    Then a transfer error is reported
