## feat: v0.5.1 – Path Role Labels (TRANSIT/DESTINATION)

### Summary

Adds path role labeling to both the CLI and library to distinguish between hops within the destination ASN (DESTINATION) and hops after ISP but before destination across other ASNs (TRANSIT).

### Changes

- Library
  - New `ftr::PathLabel` enum: `Destination`, `Transit`.
  - New `TracerouteResult::path_labels() -> Vec<Option<PathLabel>>` for per-hop labels.
  - Backward-compatible: no breaking changes to existing types.

- CLI
  - Text: Displays roles inline with the segment (e.g., `[BEYOND | TRANSIT]`).
  - JSON: Adds optional `path_label` per hop (`"TRANSIT" | "DESTINATION" | null`).

### Rationale

Makes it easier to identify which parts of the route traverse transit providers versus the destination’s own network, aiding debugging, performance analysis, and visualization use cases.

### Compatibility

- Library API is additive; 0.5.0 callers remain compatible.
- CLI text adds contextual info; JSON adds a new optional field only.

### Tests/Quality

- Added unit test for role labeling logic.
- Updated CLI JSON tests to include `path_label`.
- `cargo fmt` and `cargo clippy -- -D warnings` clean.

### Screenshots/Examples

```
 9 [BEYOND | TRANSIT] 203.0.113.1  12.345 ms [AS64500 - TRANSIT-NET, US]
10 [BEYOND | DESTINATION] 8.8.8.8  22.456 ms [AS15169 - GOOGLE, US]
```

### Checklist

- [x] Code compiles without warnings
- [x] Tests updated and passing
- [x] Backward compatibility verified
- [x] Release notes added (`RELEASE_NOTES_v0.5.1.md`)

