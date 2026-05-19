Feature: Known-hosts host key verification
  In order to defend against MITM and pinning rotation
  As a developer using idct/sftp-client
  I want connect() to enforce an OpenSSH-style known_hosts file

  Scenario: First connection with TrustOnFirstUse appends the fingerprint
    Given I have an empty known_hosts file
    When I connect with the known_hosts file and TrustOnFirstUse
    Then the connection succeeds
    And the known_hosts file now lists 127.0.0.1 with a sha256-fpr entry

  Scenario: Second connection on the same TOFU'd known_hosts file is trusted
    Given I have an empty known_hosts file
    And I connect once with the known_hosts file and TrustOnFirstUse
    When I connect with the known_hosts file and TrustOnFirstUse
    Then the connection succeeds
    And the known_hosts file has exactly one entry

  Scenario: Reject policy refuses an unknown host
    Given I have an empty known_hosts file
    When I connect with the known_hosts file and Reject policy
    Then a known-hosts rejection is reported

  Scenario: Tampered fingerprint triggers a mismatch
    Given I have a known_hosts file with a tampered fingerprint for 127.0.0.1
    When I connect with the known_hosts file and Reject policy
    Then a known-hosts mismatch is reported
