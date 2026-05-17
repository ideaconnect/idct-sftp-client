Feature: Remote filesystem operations
  In order to manage remote files and directories
  As a developer using idct/sftp-client
  I want stat/rename/remove/mkdir/rmdir to behave predictably

  Background:
    Given I have a connected SFTP client
    And the remote directory "/data" is empty

  Scenario: Remove an uploaded file
    Given I have a local file "to-delete.txt" containing "bye"
    When I upload "to-delete.txt" to "/data/to-delete.txt"
    And I remove "/data/to-delete.txt"
    Then the remote file "/data/to-delete.txt" does not exist

  Scenario: Rename moves the remote entry
    Given I have a local file "old.txt" containing "x"
    When I upload "old.txt" to "/data/old.txt"
    And I rename "/data/old.txt" to "/data/new.txt"
    Then the remote file "/data/new.txt" exists
    And the remote file "/data/old.txt" does not exist

  Scenario: Make and remove a directory
    When I create directory "/data/subdir"
    And I remove directory "/data/subdir"
    Then the remote file "/data/subdir" does not exist

  Scenario: Removing a missing file raises a filesystem error
    When I remove "/data/never-existed"
    Then a filesystem error is reported
