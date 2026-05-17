Feature: Streaming sources and progress callbacks
  In order to upload from non-file sources (S3 streams, generators, etc.)
  As a developer using idct/sftp-client
  I want uploadStream/downloadStream and progress events that work end-to-end

  Background:
    Given I have a connected SFTP client
    And the remote directory "/data" is empty

  Scenario: Upload from an in-memory stream round-trips byte-exact
    Given I have an in-memory stream containing "streamed-via-php-memory"
    When I uploadStream to "/data/stream.bin"
    Then the remote file "/data/stream.bin" contains "streamed-via-php-memory"
    And no remote partial file is left behind in "/data"

  Scenario: Download into an in-memory sink returns the byte count
    Given the remote file "/data/source.bin" already contains "download-into-sink"
    When I downloadStream "/data/source.bin" into a sink
    Then the sink received "download-into-sink"
    And the reported byte count is 18

  Scenario: Progress callbacks fire start/progress/complete around upload
    Given I have a local file "watched.bin" containing "0123456789ABCDEF0123456789"
    And a progress listener is attached
    And the chunk size is 8
    When I upload "watched.bin" to "/data/watched.bin" with the listener
    Then the listener observed the lifecycle started, progress, completed for "upload"
    And the listener observed a final byte count of 26
