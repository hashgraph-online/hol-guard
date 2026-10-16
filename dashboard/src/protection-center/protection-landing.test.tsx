import assert from "node:assert/strict";

import type { ExtensionCatalogItem, ExtensionPermission } from "../extension-controls-api";
import { FIXED_PROTECTION_PERMISSION, protectionModuleFixture } from "./fixtures/protection-fixtures";
import { searchCommandPatterns, wordMatch } from "./model/protection-landing";

const hits = (extensions: readonly ExtensionCatalogItem[]) =>
  extensions.flatMap((extension) => extension.permissions.map((permission) => ({ extension, permission })));

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

  const squash = searchCommandPatterns(hits(catalog), "merge --squash");
  assert.equal(squash.length, 0, "no permission carries a squash example in this fixture");

  const merges = searchCommandPatterns(hits(catalog), "pr merge");
  assert.equal(merges.length, 2, "example text matches the two merge variants");
  assert.ok(merges.every((match) => match.extension.extension_id === "command.github"));

  const flag = searchCommandPatterns(hits(catalog), "--force");
  assert.equal(flag.length, 1);
  assert.equal(flag[0]!.permission.permission_id, "command.git.permission.force-push");

  const byLabel = searchCommandPatterns(hits(catalog), "admin merge");
  assert.equal(byLabel.length, 1);
  assert.equal(byLabel[0]!.permission.label, "GitHub admin merge");

  assert.deepEqual(searchCommandPatterns(hits(catalog), ""), []);
  assert.deepEqual(searchCommandPatterns(hits(catalog), "   "), []);

  const manyPermissions = Array.from({ length: 30 }, (_, index) =>
    permission("command.github", `routine-${index}`, `Routine GitHub action ${index}`, `gh routine ${index}`)
  );
  const largeCatalog = [{ ...github, permissions: manyPermissions }];
  assert.equal(searchCommandPatterns(hits(largeCatalog), "routine").length, 24, "render-oriented search stays bounded");
  assert.equal(
    searchCommandPatterns(hits(largeCatalog), "routine", manyPermissions.length).length,
    30,
    "callers can obtain the full match set for bulk actions",
  );
}

// Search ranking: a capability whose identity matches the query outranks one
// that only mentions the query in prose, locally added custom extensions
// follow the packaged catalog at equal relevance, and higher risk tiers sort
// first within the same band.
{
  const official = protectionModuleFixture({
    extension_id: "command.github",
    name: "GitHub capability protection",
    executables: ["gh"],
    permissions: [],
  }) as ExtensionCatalogItem;
  const custom = protectionModuleFixture({
    extension_id: "command.faf-cli",
    name: "faf-cli command protection",
    source: "local-admin",
    executables: ["faf"],
    permissions: [],
  }) as ExtensionCatalogItem;
  const permission = (
    extensionId: string,
    suffix: string,
    label: string,
    overrides: Partial<ExtensionPermission> = {},
  ): ExtensionPermission => ({
    ...FIXED_PROTECTION_PERMISSION,
    permission_id: `${extensionId}.permission.${suffix}`,
    extension_id: extensionId,
    label,
    configurable: true,
    fixed_reason: null,
    example_command: null,
    ...overrides,
  });
  const catalog = [
    { ...custom, permissions: [
      permission("command.faf-cli", "github-sync", "faf-cli github sync", {
        description: "Writes workflow files for GitHub Actions.",
        risk_tier: "critical",
      }),
      permission("command.faf-cli", "export-mirror", "faf-cli export mirror", {
        description: "Writes a mirror file for offline reference.",
        example_command: "faf export --github-mirror",
        risk_tier: "medium",
      }),
      permission("command.faf-cli", "ci-persistence", "faf-cli git hook or CI workflow change", {
        description: "Installs hooks and GitHub Actions workflows that run on every later commit.",
        risk_tier: "high",
      }),
    ] },
    { ...official, permissions: [
      permission("command.github", "secret-write", "GitHub secret mutation", { risk_tier: "critical" }),
      permission("command.github", "workflow-rerun", "GitHub workflow rerun", {
        example_command: "gh workflow rerun 123",
        risk_tier: "high",
      }),
      permission("command.github", "read-remote", "remote GitHub state read", { risk_tier: "low" }),
    ] },
  ];

  const ranked = searchCommandPatterns(hits(catalog), "github");
  assert.deepEqual(
    ranked.map((match) => match.permission.permission_id),
    [
      "command.github.permission.secret-write",
      "command.github.permission.workflow-rerun",
      "command.github.permission.read-remote",
      "command.faf-cli.permission.github-sync",
      "command.faf-cli.permission.export-mirror",
      "command.faf-cli.permission.ci-persistence",
    ],
    "identity matches first, then example-only, then prose-only; official before locally added custom; severity descending",
  );

  const exampleOnly = ranked.find((match) => match.permission.permission_id === "command.faf-cli.permission.export-mirror");
  assert.equal(exampleOnly!.score, 1, "a query term found only in the example command scores as an example match");
  const proseOnly = ranked.find((match) => match.permission.permission_id === "command.faf-cli.permission.ci-persistence");
  assert.equal(proseOnly!.score, 2, "a query term found only in prose demotes the whole match to a context match");
  assert.equal(searchCommandPatterns(hits(catalog), "github secret")[0]!.score, 0, "label matches score as identity matches");
}

// Word-start matching: "git" names Git and GitHub, not DigitalOcean, whose
// critical settings used to outrank Git's own because "git" sits inside
// "DigitalOcean". Whole words rank above prefixes.
{
  const extension = (extension_id: string, name: string, executables: string[]) =>
    protectionModuleFixture({ extension_id, name, executables, permissions: [] }) as ExtensionCatalogItem;
  const permission = (extensionId: string, suffix: string, label: string, example: string, risk_tier: ExtensionPermission["risk_tier"]) => ({
    ...FIXED_PROTECTION_PERMISSION,
    permission_id: `${extensionId}.permission.${suffix}`,
    extension_id: extensionId,
    label,
    configurable: true,
    fixed_reason: null,
    example_command: example,
    risk_tier,
  });
  const catalog = [
    { ...extension("command.digitalocean", "DigitalOcean", ["doctl"]), permissions: [
      permission("command.digitalocean", "delete", "DigitalOcean resource deletion", "doctl compute droplet delete", "critical"),
    ] },
    { ...extension("command.github", "GitHub", ["gh"]), permissions: [
      permission("command.github", "secret-write", "GitHub secret mutation", "gh secret set TOKEN", "critical"),
    ] },
    { ...extension("command.git", "Git", ["git"]), permissions: [
      permission("command.git", "force-push", "Forced Git push", "git push --force", "high"),
    ] },
  ];

  assert.deepEqual(
    searchCommandPatterns(hits(catalog), "Git").map((match) => match.permission.permission_id),
    ["command.git.permission.force-push", "command.github.permission.secret-write"],
    "a term inside a word does not match; whole-word matches outrank prefixes regardless of risk",
  );
  assert.deepEqual(
    searchCommandPatterns(hits(catalog), "ocean").map((match) => match.permission.permission_id),
    ["command.digitalocean.permission.delete"],
    "a camelCase hump starts a word",
  );
  assert.deepEqual(
    searchCommandPatterns(hits(catalog), "--force").map((match) => match.permission.permission_id),
    ["command.git.permission.force-push"],
    "terms that start with punctuation still match flags",
  );
  assert.equal(searchCommandPatterns(hits(catalog), "itocean").length, 0, "mid-word fragments do not match");
  assert.equal(wordMatch("İstanbulGit", "git"), "exact", "a camelCase hump survives case folding that changes length");
  assert.equal(wordMatch("İstanbulGit", "bulgit"), null, "folded text still rejects mid-word fragments");
}

console.log("protection-landing.test.tsx: all assertions passed");
