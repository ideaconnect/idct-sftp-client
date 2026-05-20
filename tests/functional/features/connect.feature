Feature: Connecting to an SFTP server
  In order to talk to a remote host
  As a developer using idct/sftp-client
  I want predictable behaviour for each authentication mode

  Scenario: Successful password authentication
    When I connect with password authentication
    Then the connection succeeds

  Scenario: Rejected password authentication
    When I connect with a wrong password
    Then authentication is rejected

  Scenario: Successful public-key authentication
    When I connect with public-key authentication
    Then the connection succeeds

  Scenario: Host-key fingerprint mismatch aborts the connection
    When I connect requiring fingerprint "00112233445566778899aabbccddeeff"
    Then the connection fails with a fingerprint mismatch
