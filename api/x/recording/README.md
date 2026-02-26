# Recording Server / Client

```
Client (envoy)                     Server (pomerium-core)
  │                                    │
  ├──► RecordingData(Metadata) ───────►│ 1. Receive metadata
  │                                    │    Validate recording ID
  │                                    │    Create chunk writer
  │                                    │
  │◄─── RecordingSession ──────────────┤ 2. Send + manifest
  │     (config, manifest)             │    (for resume support)
  │                                    │
  ├──► RecordingData(Chunk) ──────────►│ 3. Stream chunks
  ├──► ...                  ──────────►│
  ├──► RecordingData(Checksum) ───────►│ 4. Verify checksum
  │                                    │    Server writes accumulated chunks
  |                                    |
  │◄─── RecordingSession ──────────────┤ 5. Send updated manifest
  │                                    │
  ├──► RecordingData(Chunk) ──────────►│ 6. Continue streaming until done...
  │                                    │
  ├──► RecordingData(Sig)  ──────────► │ 7. Receive signature that contains
  │                                    │    verification metadata, and close
  |                                    |    this recording for appending
```

The server returns the following error codes:
- `InvalidArgument` : the minimum information to store the recording is not provided
- `FailedPrecodition` : the recording cannot continue, one of the potential integrity checks has failed:
    - `checksum` mismatch for chunks
    - `metadata` mismatch of recording metadata on resume
    - `chunk` overwrite, server was told it should overwrite a chunk that already exists
- `ResourceExhasuted` : when the server can handle no more recording requests at this time
- `Aborted` : for when the recording stream was cancelled (graceful shutdown, config change) or otherwise.