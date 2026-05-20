Feature: Filesystem-query operations (stat / fileExists / getFileList / mkdir recursive)
  In order to inspect the remote tree before / after transfers
  As a developer using idct/sftp-client
  I want the read-side operations exercised against the live atmoz/sftp fixture
  (the README's Operations cheatsheet lists them — this is the functional
  side of that table; behaviour matrices live in the unit tests)

  Background:
    Given I have a connected SFTP client
    And the remote directory "/data" is empty

  Scenario: stat returns the file size for an existing remote file
    Given the remote file "/data/measured.bin" already contains "twelve-bytes"
    When I stat "/data/measured.bin"
    Then the stat result reports size 12

  Scenario: stat raises a filesystem error for a missing remote file
    When I stat "/data/no-such-thing"
    Then a filesystem error is reported

  Scenario: fileExists returns true for a present file
    Given the remote file "/data/here.txt" already contains "x"
    When I check fileExists for "/data/here.txt"
    Then fileExists returns true

  Scenario: fileExists returns false for an absent file
    When I check fileExists for "/data/absent.txt"
    Then fileExists returns false

  Scenario: getFileList enumerates regular entries without dot entries
    Given the remote file "/data/listing/a.txt" already contains "a"
    And the remote file "/data/listing/b.txt" already contains "b"
    And the remote file "/data/listing/c.txt" already contains "c"
    When I getFileList "/data/listing"
    Then the file list contains exactly: a.txt, b.txt, c.txt

  Scenario: getFileList with includeDotEntries surfaces "." and ".."
    Given the remote file "/data/dotlist/a.txt" already contains "a"
    When I getFileList "/data/dotlist" with dot entries
    Then the file list contains exactly: ., .., a.txt

  Scenario: makeDirectory recursive: true creates intermediate parents
    # Without recursive=true this fails because /data/deep does not exist.
    # With recursive=true the full chain is created in one call.
    When I create directory "/data/deep/nested/leaf" recursively
    Then the remote file "/data/deep/nested/leaf" exists
    And the remote file "/data/deep/nested" exists
    And the remote file "/data/deep" exists

  Scenario: rename moves a remote file to a new path
    Given the remote file "/data/old-name.txt" already contains "moved"
    When I rename "/data/old-name.txt" to "/data/new-name.txt"
    Then the remote file "/data/new-name.txt" exists
    And the remote file "/data/old-name.txt" does not exist
