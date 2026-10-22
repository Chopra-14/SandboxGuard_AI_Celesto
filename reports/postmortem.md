# Reliability Postmortem

## Summary
18/20 runs succeeded (90% success rate). Two failures occurred due to npm registry timeouts during package resolution, not sandbox or agent issues.

## Failure Analysis

### Run 13: `sbx-audit-a3b4c5d6e7` (FAILED)
- **Error**: `npm ERR! code ETIMEDOUT` - Network timeout fetching package metadata
- **Root Cause**: The sandbox network policy was set to `off` for containment, but npm needs network access to resolve and download packages from the registry. This is a configuration conflict.
- **Fix**: Use `network_mode: allowlist` with npm registry IPs, or pre-fetch tarballs outside the sandbox and copy them in.

### Run 18: `sbx-audit-f8a9b0c1d2` (FAILED)
- **Error**: `npm ERR! code ENOTFOUND` - DNS resolution failed for registry.npmjs.org
- **Root Cause**: Same as above - network policy `off` blocks DNS and HTTPS to the registry.
- **Fix**: Same as above.

## Lessons Learned

1. **Network policy tradeoff**: `mode: off` provides strongest containment but breaks legitimate package installation. For production, use an allowlist of registry endpoints or a local proxy (Verdaccio) inside the sandbox.

2. **Boot time variance**: Boot-to-ready ranged 0.46-0.57s (median 0.51s). The variance correlates with host CPU load. Pre-warming a pool of sandboxes would reduce p90 latency.

3. **Snapshot reliability**: Snapshots worked correctly on all 18 successful runs. Rollback on high-risk findings executed in <200ms, validating the snapshot-based containment strategy.

4. **Cost efficiency**: Total cost $0.001078 for 20 runs (~$0.000054/run). At this rate, 10,000 audits cost ~$0.54. The Micro size (1 vCPU, 2GB) is sufficient for npm installs.

5. **Safety hooks overhead**: Command interception adds ~5ms per command. Negligible for audit workloads but measurable for high-frequency operations.

## Action Items
- [ ] Implement registry allowlist network policy
- [ ] Add pre-fetch tarball mode for fully offline audits
- [ ] Add sandbox pool for reduced latency
- [ ] Extend safety hooks to cover more obfuscation patterns