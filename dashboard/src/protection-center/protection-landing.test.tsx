import assert from "node:assert/strict";

import type { ExtensionCatalogItem } from "../extension-controls-api";
import { FIXED_PROTECTION_PERMISSION, protectionModuleFixture } from "./fixtures/protection-fixtures";
import { searchCommandPatterns } from "./model/protection-landing";

// Pattern search: query matches labels, examples, flags, and IDs across tools.
{
  const git = protectionModuleFixture({
    extension_id: "command.git",
    name: "Git",
    executables: ["git"],
    permissions: [],
  }) as ExtensionCatalogItem;
  const github = protectionModuleFixture({
    extension_id: "command.github",
    name: "GitHub",
    executables: ["gh"],
    permissions: [],
  }) as ExtensionCatalogItem;
  const permission = (extensionId: string, suffix: string, label: string, example: string | null) => ({
    ...FIXED_PROTECTION_PERMISSION,
    permission_id: `${extensionId}.permission.${suffix}`,
    extension_id: extensionId,
    label,
    configurable: true,
    fixed_reason: null,
    example_command: example,
  });
  const catalog = [
    { ...git, permissions: [permission("command.git", "force-push", "Forced Git push", "git push --force")] },
    { ...github, permissions: [
      permission("command.github", "merge-remote", "GitHub pull-request merge", "gh pr merge 123 --merge"),
      permission("command.github", "merge-admin", "GitHub admin merge", "gh pr merge 123 --admin"),
      permission("command.github", "read-remote", "GitHub read", "gh pr view 123"),
    ] },
  ];

  const squash = searchCommandPatterns(catalog, "merge --squash");
  assert.equal(squash.length, 0, "no permission carries a squash example in this fixture");

  const merges = searchCommandPatterns(catalog, "pr merge");
  assert.equal(merges.length, 2, "example text matches the two merge variants");
  assert.ok(merges.every((match) => match.extension.extension_id === "command.github"));

  const flag = searchCommandPatterns(catalog, "--force");
  assert.equal(flag.length, 1);
  assert.equal(flag[0]!.permission.permission_id, "command.git.permission.force-push");

  const byLabel = searchCommandPatterns(catalog, "admin merge");
  assert.equal(byLabel.length, 1);
  assert.equal(byLabel[0]!.permission.label, "GitHub admin merge");

  assert.deepEqual(searchCommandPatterns(catalog, ""), []);
  assert.deepEqual(searchCommandPatterns(catalog, "   "), []);

  const manyPermissions = Array.from({ length: 30 }, (_, index) =>
    permission("command.github", `routine-${index}`, `Routine GitHub action ${index}`, `gh routine ${index}`)
  );
  const largeCatalog = [{ ...github, permissions: manyPermissions }];
  assert.equal(searchCommandPatterns(largeCatalog, "routine").length, 24, "render-oriented search stays bounded");
  assert.equal(
    searchCommandPatterns(largeCatalog, "routine", manyPermissions.length).length,
    30,
    "callers can obtain the full match set for bulk actions",
  );
}

console.log("protection-landing.test.tsx: all assertions passed");
