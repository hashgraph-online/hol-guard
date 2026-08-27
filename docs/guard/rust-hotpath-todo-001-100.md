# Rust hot-path program: tasks T001-T100

This delivery implements the first 100 work items from the Rust hot-path
corrective program as one reviewable boundary: live-state reconciliation,
ownership inventory, backend receipts, non-bypassable CI selection, removal of
PostToolUse Python fallback, real resident integration, and the policy-snapshot
cutover prerequisites.

The authoritative checklist remains in the implementation PR. Items whose final
proof depends on the immediately following PreToolUse PR are marked staged in
the ownership manifest with a hard expiration of 2026-09-02. The waiver cannot
introduce or permit a Python decision fallback.
