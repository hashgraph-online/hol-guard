#!/bin/zsh
set -euo pipefail

readonly ROOT="${0:A:h:h:h:h}"
readonly VERSION="${HOL_GUARD_VERSION:?Set HOL_GUARD_VERSION}"
readonly BUILD_ID="${HOL_GUARD_BUILD_ID:?Set HOL_GUARD_BUILD_ID}"
readonly ARCH="$(uname -m)"
readonly OUT="${ROOT}/dist/mdm/macos"
readonly STAGE="${OUT}/stage"
readonly RUNTIME="${STAGE}/Library/Application Support/HOL Guard"
readonly STATE="${STAGE}/Library/Application Support/HOL Guard State"
readonly LOGS="${STAGE}/Library/Logs/HOL Guard"
readonly PACKAGE_ID="org.hol.guard"

rm -rf "${OUT}"
mkdir -p "${RUNTIME}" "${STATE}" "${LOGS}" "${STAGE}/Library/LaunchAgents" \
  "${STAGE}/Library/LaunchDaemons" "${OUT}"

typeset -a pyinstaller_args
pyinstaller_args=(--clean --noconfirm --onedir --name hol-guard \
  --collect-submodules codex_plugin_scanner --collect-data codex_plugin_scanner \
  --distpath "${RUNTIME}" --workpath "${OUT}/pyinstaller" --specpath "${OUT}" \
  "${ROOT}/scripts/mdm/hol-guard-entry.py")
if [[ -n "${HOL_GUARD_INSTALLER_SIGN_IDENTITY:-}" ]]; then
  [[ -n "${HOL_GUARD_APPLICATION_SIGN_IDENTITY:-}" ]] || exit 2
  pyinstaller_args=(--codesign-identity "${HOL_GUARD_APPLICATION_SIGN_IDENTITY}" "${pyinstaller_args[@]}")
fi
uv run --no-sync pyinstaller "${pyinstaller_args[@]}"

cp "${ROOT}/scripts/mdm/macos/org.hol.guard.user-activation.plist" \
  "${STAGE}/Library/LaunchAgents/org.hol.guard.user-activation.plist"
cp "${ROOT}/scripts/mdm/macos/org.hol.guard.machine-health.plist" \
  "${STAGE}/Library/LaunchDaemons/org.hol.guard.machine-health.plist"
cp "${ROOT}/scripts/mdm/macos/activate-current-user.sh" "${RUNTIME}/activate-current-user"
typeset -a manifest_args
manifest_args=(--runtime-root "${RUNTIME}" --version "${VERSION}" --build-id "${BUILD_ID}" \
  --platform macos --architecture "${ARCH}" --installer-identity "${PACKAGE_ID}" \
  --output "${RUNTIME}/release-manifest.json")
if [[ -n "${HOL_GUARD_MANIFEST_SIGNING_KEY:-}" ]]; then
  [[ -n "${HOL_GUARD_MANIFEST_KEY_ID:-}" ]] || exit 2
  manifest_args+=(--signing-key "${HOL_GUARD_MANIFEST_SIGNING_KEY}" --key-id "${HOL_GUARD_MANIFEST_KEY_ID}")
fi
python3 "${ROOT}/scripts/mdm/generate-release-manifest.py" "${manifest_args[@]}"

find "${STAGE}" -type d -exec chmod 0755 {} +
find "${STAGE}" -type f -exec chmod 0644 {} +
chmod 0755 "${RUNTIME}/hol-guard/hol-guard" "${RUNTIME}/activate-current-user"

typeset -a pkg_args
pkg_args=(--root "${STAGE}" --ownership recommended --identifier "${PACKAGE_ID}" --version "${VERSION}" \
  --scripts "${ROOT}/scripts/mdm/macos/pkg-scripts")
if [[ -n "${HOL_GUARD_INSTALLER_SIGN_IDENTITY:-}" ]]; then
  [[ -n "${HOL_GUARD_MANIFEST_SIGNING_KEY:-}" ]] || exit 2
  pkg_args+=(--sign "${HOL_GUARD_INSTALLER_SIGN_IDENTITY}")
fi
pkgbuild "${pkg_args[@]}" "${OUT}/hol-guard-${VERSION}-${ARCH}.pkg"

if [[ -n "${HOL_GUARD_NOTARY_PROFILE:-}" ]]; then
  xcrun notarytool submit "${OUT}/hol-guard-${VERSION}-${ARCH}.pkg" \
    --keychain-profile "${HOL_GUARD_NOTARY_PROFILE}" --wait
  xcrun stapler staple "${OUT}/hol-guard-${VERSION}-${ARCH}.pkg"
fi

python3 "${ROOT}/scripts/mdm/generate-sbom.py" --version "${VERSION}" --output "${OUT}/sbom.cdx.json"
python3 "${ROOT}/scripts/mdm/write-release-evidence.py" \
  --artifact "${OUT}/hol-guard-${VERSION}-${ARCH}.pkg" \
  --manifest "${RUNTIME}/release-manifest.json" --sbom "${OUT}/sbom.cdx.json" \
  --output "${OUT}/release-evidence.json"
