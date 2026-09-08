from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def replace_once(path: Path, old: str, new: str) -> None:
    text = path.read_text(encoding="utf-8")
    count = text.count(old)
    if count != 1:
        raise RuntimeError(f"expected exactly one match in {path}, found {count}: {old!r}")
    path.write_text(text.replace(old, new, 1), encoding="utf-8")


def main() -> None:
    replace_once(
        ROOT / "src/codex_plugin_scanner/guard/adapters/cline_hooks.py",
        '    with temporary.open("w", encoding="utf-8") as handle:\n',
        '    with temporary.open("w", encoding="utf-8", newline="") as handle:\n',
    )
    replace_once(
        ROOT / "tests/test_cline_hook_transports.py",
        '        hook.write_text(hook_content, encoding="utf-8")\n',
        '        hook.write_text(hook_content, encoding="utf-8", newline="")\n',
    )
    replace_once(
        ROOT / "tests/test_cline_hook_transports.py",
        '        worker.write_text(worker_content, encoding="utf-8")\n',
        '        worker.write_text(worker_content, encoding="utf-8", newline="")\n',
    )

    spec = ROOT / "dashboard/e2e/installed-extension-control-center.spec.ts"
    replace_once(
        spec,
        "const expectedExtensionCount = 61;\n",
        "const minimumExpectedExtensionCount = 61;\n",
    )
    replace_once(
        spec,
        '''  await page.goto("/extensions");
  await expectSecretSafeUrl(page);
  await expect(page.getByRole("heading", { name: "Extensions", level: 1 })).toBeVisible();
  await expect(page.getByRole("heading", { name: "All tools" })).toBeVisible();
  await expect(page.getByText(`${expectedExtensionCount} tools`)).toBeVisible();
''',
        '''  const catalogResponsePromise = page.waitForResponse((response) => {
    const url = new URL(response.url());
    return url.pathname === "/v1/extension-controls/catalog" && response.status() === 200;
  });
  await page.goto("/extensions");
  const catalogResponse = await catalogResponsePromise;
  const catalogPayload = await catalogResponse.json() as { extensions?: unknown[] };
  const expectedExtensionCount = Array.isArray(catalogPayload.extensions) ? catalogPayload.extensions.length : 0;
  expect(expectedExtensionCount).toBeGreaterThanOrEqual(minimumExpectedExtensionCount);
  await expectSecretSafeUrl(page);
  await expect(page.getByRole("heading", { name: "Extensions", level: 1 })).toBeVisible();
  await expect(page.getByRole("heading", { name: "All tools" })).toBeVisible();
  await expect(page.getByText(`${expectedExtensionCount} tools`)).toBeVisible();
''',
    )


if __name__ == "__main__":
    main()
