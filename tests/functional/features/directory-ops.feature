Feature: Recursive directory operations
  In order to upload, download, and clean up whole trees
  As a developer using idct/sftp-client
  I want uploadDirectory / downloadDirectory / removeDirectoryTree to round-trip nested layouts

  Background:
    Given I have a connected SFTP client
    And the remote directory "/data" is empty

  Scenario: Round-trip a nested directory tree
    Given I have a local directory "src" with files:
      | path                  | contents |
      | a.txt                 | aaa      |
      | sub/b.txt             | bb       |
      | sub/deep/c.txt        | cccc     |
    And the local directory "src" also has an empty subdirectory "sub/empty"
    When I uploadDirectory "src" to "/data/tree"
    Then the upload result reports 3 files and 9 bytes transferred
    And the remote file "/data/tree/a.txt" contains "aaa"
    And the remote file "/data/tree/sub/b.txt" contains "bb"
    And the remote file "/data/tree/sub/deep/c.txt" contains "cccc"
    When I downloadDirectory "/data/tree" to "roundtrip"
    Then the local file "roundtrip/a.txt" contains "aaa"
    And the local file "roundtrip/sub/b.txt" contains "bb"
    And the local file "roundtrip/sub/deep/c.txt" contains "cccc"
    And the local directory "roundtrip/sub/empty" exists

  Scenario: removeDirectoryTree wipes a populated tree
    Given I have a local directory "to-remove" with files:
      | path        | contents |
      | top.txt     | top      |
      | nested/x.txt | x       |
    When I uploadDirectory "to-remove" to "/data/wipe"
    And I removeDirectoryTree "/data/wipe"
    Then the remote directory "/data/wipe" no longer exists
