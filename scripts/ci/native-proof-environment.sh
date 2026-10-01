# Source this file before installed native proofs. Keep the caller's shell flags,
# interpreter, build identity, and ordinary runtime configuration unchanged.
# These are the existing Linux, macOS, and Windows proof override exclusions.
unset HOL_GUARD_NATIVE HOL_GUARD_NATIVE_BINARY HOL_GUARD_HOOK_FAST_PATH
unset HOL_GUARD_NATIVE_MODE HOL_GUARD_NATIVE_ORACLE HOL_GUARD_NATIVE_DIAGNOSTIC
unset HOL_GUARD_HOOK_FAST_PATH_SHADOW HOL_GUARD_HOOK_SOURCE_REF HOL_GUARD_HOOK_BINARY
unset HOL_GUARD_FAST_PATH HOL_GUARD_BINARY HOL_GUARD_ORACLE HOL_GUARD_DIAGNOSTIC HOL_GUARD_TEST_MODE
unset HOL_GUARD_PYTHON_ORACLE
unset HOL_GUARD_TEST_KEYRING_FILE HOL_GUARD_TEST_SYNC_AUTH_CONTEXT_JSON
unset HOL_GUARD_RUN_SYSTEM_KEYCHAIN_TEST
unset GUARD_NATIVE GUARD_NATIVE_BINARY GUARD_NATIVE_MODE GUARD_NATIVE_ORACLE GUARD_NATIVE_DIAGNOSTIC
unset GUARD_HOOK_FAST_PATH GUARD_HOOK_FAST_PATH_SHADOW GUARD_HOOK_SOURCE_REF GUARD_HOOK_BINARY
unset GUARD_FAST_PATH GUARD_BINARY GUARD_ORACLE GUARD_DIAGNOSTIC GUARD_TEST_MODE
unset GUARD_TEST_KEYRING_FILE GUARD_TEST_SYNC_AUTH_CONTEXT_JSON GUARD_PYTEST_DURATION_OUTPUT
unset PYTEST_CURRENT_TEST PYTEST_ADDOPTS PYTEST_PLUGINS PYTHONPATH

# When the PR diff carries no regen-owned generated artifacts, manifest-vs-source
# freshness bindings stand down: the artifacts are refreshed on main by the
# regen workflow, and the PR cannot update them (generated-artifacts-guard).
if [ "${GITHUB_BASE_REF:-}" != "" ]; then
  if [ "$(python3 scripts/ci/detect_pending_extension_regen.py --defer-freshness 2>/dev/null || echo false)" = "true" ]; then
    export HOL_DEFER_ARTIFACT_FRESHNESS=1
  fi
fi
