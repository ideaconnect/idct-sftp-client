@slow @toxiproxy
Feature: Behaviour under controlled network faults
  In order to verify retry / resume / progress hold up under real
  network adversity
  As a developer using idct/sftp-client
  I want toxiproxy-injected latency, bandwidth, and packet-loss to
  exercise the failure surfaces

  Background:
    Given I have a toxiproxy SFTP proxy named "sftp-fault" to atmoz on port 22122
    And I have a connected SFTP client via the "sftp-fault" proxy
    And the remote directory "/data" is empty

  Scenario: A high-latency network still round-trips a small file
    Given a 500ms latency toxic is added to "sftp-fault"
    And I have a local file "lat.txt" containing "high-latency-payload"
    When I upload "lat.txt" to "/data/lat.txt"
    Then the remote file "/data/lat.txt" contains "high-latency-payload"

  Scenario: A bandwidth cap still completes a small upload and reports progress
    Given a 4096-byte-per-second bandwidth toxic is added to "sftp-fault"
    And a progress listener is attached
    And I have a local file "bw.txt" containing "0123456789ABCDEF"
    When I upload "bw.txt" to "/data/bw.txt" with the listener
    Then the listener observed the lifecycle started, progress, completed for "upload"
    And the remote file "/data/bw.txt" contains "0123456789ABCDEF"
