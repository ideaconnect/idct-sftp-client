Feature: Upload from an S3-compatible stream source
  In order to push data sourced from object storage without buffering it
  As a developer using idct/sftp-client
  I want uploadStream to round-trip an http-fetched stream into SFTP

  Background:
    Given I have a connected SFTP client
    And the remote directory "/data" is empty

  Scenario: uploadStream from an S3 (minio) HTTP source round-trips byte-exact
    Given I have an HTTP stream from "http://127.0.0.1:9000/idct-test/payload.bin"
    When I uploadStream to "/data/from-s3.bin"
    Then the remote file "/data/from-s3.bin" contains "streamed-from-minio-s3-payload"
    And no remote partial file is left behind in "/data"
