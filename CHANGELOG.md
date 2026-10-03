# Changelog

All notable changes to HOL Guard will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Older releases are preserved in the [changelog archive](docs/changelog-archive.md).

## [3.19.0](https://github.com/hashgraph-online/hol-guard/compare/v3.18.2...v3.19.0) (2026-10-03)


### Features

* **mcp:** add ContribOS MCP server contribution ([#3472](https://github.com/hashgraph-online/hol-guard/issues/3472)) ([e10177b](https://github.com/hashgraph-online/hol-guard/commit/e10177b7fc2533cf150327eeb893882a5f6392f4))


### Bug Fixes

* **guard:** classify auth context and batch Git filter proofs ([#3471](https://github.com/hashgraph-online/hol-guard/issues/3471)) ([7a63cf2](https://github.com/hashgraph-online/hol-guard/commit/7a63cf2a3068b52b6d869e90573d4e8aa2f688dd))
* prove exact recursive grep exclusions safely ([#3467](https://github.com/hashgraph-online/hol-guard/issues/3467)) ([536aa27](https://github.com/hashgraph-online/hol-guard/commit/536aa27b678c2c0b33bf55e7ced0d874329529e5))

## [3.18.2](https://github.com/hashgraph-online/hol-guard/compare/v3.18.1...v3.18.2) (2026-10-03)


### Bug Fixes

* **ci:** make partial reruns reuse verified successful coverage ([#3454](https://github.com/hashgraph-online/hol-guard/issues/3454)) ([797c3f3](https://github.com/hashgraph-online/hol-guard/commit/797c3f3cec45c8e201a711c9cb58c27fa1a14104))
* **ci:** skip Gitar jobs for closed pull requests ([9260647](https://github.com/hashgraph-online/hol-guard/commit/9260647758487a12381fbec31d53b65dd8106340))
* preserve safe stderr-sink workflows and qualify native readiness ([#3462](https://github.com/hashgraph-online/hol-guard/issues/3462)) ([1592681](https://github.com/hashgraph-online/hol-guard/commit/1592681038145546cb3d709129f282e36a3c3f2c))
* **skills:** keep negative fixture out of skill discovery ([#3460](https://github.com/hashgraph-online/hol-guard/issues/3460)) ([0a95303](https://github.com/hashgraph-online/hol-guard/commit/0a95303c35103a36441b9fd72491f163a0dba962))


### Performance Improvements

* **ci:** remove repeated ownership analysis without caching stale verdicts ([#3456](https://github.com/hashgraph-online/hol-guard/issues/3456)) ([946ca9e](https://github.com/hashgraph-online/hol-guard/commit/946ca9efc178c33a33d969e8129e1ee7f855cf79))

## [3.18.1](https://github.com/hashgraph-online/hol-guard/compare/v3.18.0...v3.18.1) (2026-10-03)


### Bug Fixes

* **ci:** preserve actionable causes of native capacity failures ([#3453](https://github.com/hashgraph-online/hol-guard/issues/3453)) ([ab2abaa](https://github.com/hashgraph-online/hol-guard/commit/ab2abaab062236c7500a2786bf7c25240df7276d))
* **ci:** stop migration churn and reject broken contracts before fan-out ([#3450](https://github.com/hashgraph-online/hol-guard/issues/3450)) ([39b3a1b](https://github.com/hashgraph-online/hol-guard/commit/39b3a1bdb6128351a3160424b28578e7da9a35aa))
* **commands:** compose safe segments with extension approvals ([#3434](https://github.com/hashgraph-online/hol-guard/issues/3434)) ([ae4f747](https://github.com/hashgraph-online/hol-guard/commit/ae4f7470d09c948d1b7944542d352e0225b9a4e8))
* compose routine commands and native home file writes safely ([#3437](https://github.com/hashgraph-online/hol-guard/issues/3437)) ([2874d88](https://github.com/hashgraph-online/hol-guard/commit/2874d886c1f398d6e7058b692bd863e6f7619ada))
* **runtime:** quiesce native residents during package updates ([#3438](https://github.com/hashgraph-online/hol-guard/issues/3438)) ([27faf19](https://github.com/hashgraph-online/hol-guard/commit/27faf19ff2d906f8076a6277948549c8e8fcd9a4))
* **tests:** defer extension-directory render check in PR context ([#3382](https://github.com/hashgraph-online/hol-guard/issues/3382)) ([155f175](https://github.com/hashgraph-online/hol-guard/commit/155f175fa0cf67b2441c0e3d6bd2a4be5162eadf))

## [3.18.0](https://github.com/hashgraph-online/hol-guard/compare/v3.17.1...v3.18.0) (2026-10-03)


### Features

* **guard:** add Syngraphe command extension ([#2929](https://github.com/hashgraph-online/hol-guard/issues/2929)) ([77b9d11](https://github.com/hashgraph-online/hol-guard/commit/77b9d11a9d7b10d96f9efe2bf104fad5ea0cea1e))


### Bug Fixes

* **ci:** stop fixture rebuild churn while preserving contributor extensions ([#3425](https://github.com/hashgraph-online/hol-guard/issues/3425)) ([d756e57](https://github.com/hashgraph-online/hol-guard/commit/d756e57ce8aa7c1888805f2739ceffed5c4ded18))
* **extension-builder:** exempt regen/* PRs from carried-projection rejection ([#3421](https://github.com/hashgraph-online/hol-guard/issues/3421)) ([a9f9a88](https://github.com/hashgraph-online/hol-guard/commit/a9f9a882419e4124bc22124de38e95cef5f99a51))
* format resident lease receiver call ([7da89ac](https://github.com/hashgraph-online/hol-guard/commit/7da89ac3ecc039d08b310c3830c31a5a8a807773))
* **guard:** block review requests without prompting by default ([#3428](https://github.com/hashgraph-online/hol-guard/issues/3428)) ([8ee4111](https://github.com/hashgraph-online/hol-guard/commit/8ee4111d5f41787066675e64c8f43ed7b8abd12d))
* **mcp:** honor fresh one-shot approvals through launch revalidation ([9754d13](https://github.com/hashgraph-online/hol-guard/commit/9754d139f119549fc2ab7f673a1a8a18700613fb))
* restore native hook review across frozen launches and linked worktrees ([#3411](https://github.com/hashgraph-online/hol-guard/issues/3411)) ([7d0afe6](https://github.com/hashgraph-online/hol-guard/commit/7d0afe60689bf0dd17d37995a8e156274a339eec))
* restore routine file workflows and contained Bun Vitest execution ([#3427](https://github.com/hashgraph-online/hol-guard/issues/3427)) ([7c5bb38](https://github.com/hashgraph-online/hol-guard/commit/7c5bb389e1b1858d703de008afc7e7689033c45f))
* **runtime:** remove idle accept latency and stabilize deadline verification ([912251f](https://github.com/hashgraph-online/hol-guard/commit/912251f723e9f832df46a10c011f40a62967a85d))
* **runtime:** restore the previous runtime when a transition fails ([#3422](https://github.com/hashgraph-online/hol-guard/issues/3422)) ([0c31916](https://github.com/hashgraph-online/hol-guard/commit/0c319168b4bc11e2ce02ebf203f6f35d316ddec4))
* **runtime:** wake idle Unix accepts and verify absolute lease deadlines ([c00209c](https://github.com/hashgraph-online/hol-guard/commit/c00209c3607a0f54f3af98175de6f2456b4af388))

## [3.17.1](https://github.com/hashgraph-online/hol-guard/compare/v3.17.0...v3.17.1) (2026-10-02)


### Bug Fixes

* **ci:** rebuild release projections before packaging ([29091e5](https://github.com/hashgraph-online/hol-guard/commit/29091e5a9489610ffb93c62e1a7c6432763f25aa))
* **desktop:** freeze projections from the attested Core wheel ([d6a66e8](https://github.com/hashgraph-online/hol-guard/commit/d6a66e8cb22efd1e5caec45de03d613147fe6dc4))

## [3.17.0](https://github.com/hashgraph-online/hol-guard/compare/v3.16.5...v3.17.0) (2026-10-02)


### Features

* **guard:** add recovery step to native inspection unavailable result ([#3393](https://github.com/hashgraph-online/hol-guard/issues/3393)) ([4a835fd](https://github.com/hashgraph-online/hol-guard/commit/4a835fd444350f552f34c923038e15acb6eaf448))
* **guard:** verify delegated workspace review decisions ([#3120](https://github.com/hashgraph-online/hol-guard/issues/3120)) ([a288694](https://github.com/hashgraph-online/hol-guard/commit/a28869423243e17111036d2e3e978fc0cafb2b3e))
* **native:** own approval-context digests in the resident worker ([#3346](https://github.com/hashgraph-online/hol-guard/issues/3346)) ([73d1de1](https://github.com/hashgraph-online/hol-guard/commit/73d1de17580b4477ed67dbb54aa2e91159e7bd2c))


### Bug Fixes

* **daemon:** close publishers after early startup failure ([5bf2c11](https://github.com/hashgraph-online/hol-guard/commit/5bf2c119a51f7908b7709eaeaca99b8fb44f966e))
* **guard:** emit approval_requests on store-quarantined deny path ([#3390](https://github.com/hashgraph-online/hol-guard/issues/3390)) ([97c2c1e](https://github.com/hashgraph-online/hol-guard/commit/97c2c1e7d812698bd6ba282424c2b2b99472f4a4))
* **guard:** preserve Codex rollback state and harden MCPB verification ([#3380](https://github.com/hashgraph-online/hol-guard/issues/3380)) ([8b18ef9](https://github.com/hashgraph-online/hol-guard/commit/8b18ef95f813111956deec5c50f60f01ca41b32f))
* **guard:** preserve daemon-failure category through local-queue fallback ([#3394](https://github.com/hashgraph-online/hol-guard/issues/3394)) ([8588fbe](https://github.com/hashgraph-online/hol-guard/commit/8588fbede0317786baed5015bab2da2fe0ef65a1))
* **guard:** preserve transaction participants on rollback conflict ([#3387](https://github.com/hashgraph-online/hol-guard/issues/3387)) ([d6c31d9](https://github.com/hashgraph-online/hol-guard/commit/d6c31d9ad6d024fdc31ad4c56e80b8ec3746d5cd))
* **guard:** report snapshot substitution as config_invalid, not rollback_conflict ([#3385](https://github.com/hashgraph-online/hol-guard/issues/3385)) ([078a981](https://github.com/hashgraph-online/hol-guard/commit/078a9815552fc8f8481fe0ef1a294624edf742e5))
* **guard:** restore quiet routine workflows without weakening risk checks ([37bb699](https://github.com/hashgraph-online/hol-guard/commit/37bb699e42a72e75676b684593a100d1e16a648c))
* **runtime:** retain cancelled workers through containment failures ([0944ff3](https://github.com/hashgraph-online/hol-guard/commit/0944ff3f6c8835d3c867f27523970e6aaf2c47a7))
* **security:** pin node-forge to 1.3.1 for mcpb tooling ([c61e9fc](https://github.com/hashgraph-online/hol-guard/commit/c61e9fc951bd66fc56038eeb2f6b2a72f1e8d5ec))

## [3.16.5](https://github.com/hashgraph-online/hol-guard/compare/v3.16.4...v3.16.5) (2026-10-02)


### Bug Fixes

* **evaluation:** retain partial setup recovery state ([#3373](https://github.com/hashgraph-online/hol-guard/issues/3373)) ([d26b794](https://github.com/hashgraph-online/hol-guard/commit/d26b79441ca13adbc243251d29231c75cfc95c74))

## [3.16.4](https://github.com/hashgraph-online/hol-guard/compare/v3.16.3...v3.16.4) (2026-10-02)


### Bug Fixes

* **ci:** prevent evidence drift and daemon response races ([#3368](https://github.com/hashgraph-online/hol-guard/issues/3368)) ([cf6481b](https://github.com/hashgraph-online/hol-guard/commit/cf6481b3450572694040d84a52af67d9aca715fa))
* **mcp:** keep managed servers discoverable after updates ([d6e4fd9](https://github.com/hashgraph-online/hol-guard/commit/d6e4fd9043d37f7166b229b7b255fe7c049beb20))
* **native:** allow standalone plain directory changes ([e430915](https://github.com/hashgraph-online/hol-guard/commit/e43091501fa6e55e570fba85ee1935cb7703a554))
* **review:** recover collided snapshot sequences ([#3348](https://github.com/hashgraph-online/hol-guard/issues/3348)) ([e5f9503](https://github.com/hashgraph-online/hol-guard/commit/e5f9503def74e65a8f6f08b1f4281b734a6da667))

## [3.16.3](https://github.com/hashgraph-online/hol-guard/compare/v3.16.2...v3.16.3) (2026-10-02)


### Bug Fixes

* **benchmarks:** preserve failure and route evidence ([#3357](https://github.com/hashgraph-online/hol-guard/issues/3357)) ([b4a1cab](https://github.com/hashgraph-online/hol-guard/commit/b4a1cabc48c879c4447bab75ff8a9f3fa3214c6a))
* **codex:** serialize competing configuration lifecycle writers ([e529cd0](https://github.com/hashgraph-online/hol-guard/commit/e529cd06324f4690bcf754a59689f24201b01e6b))
* **runtime:** detect closed supervisor pipes before serving requests ([#3349](https://github.com/hashgraph-online/hol-guard/issues/3349)) ([92bd8df](https://github.com/hashgraph-online/hol-guard/commit/92bd8df9d3903c903fa252c04ebeb931fafff2b8))

## [3.16.2](https://github.com/hashgraph-online/hol-guard/compare/v3.16.1...v3.16.2) (2026-10-01)

### Bug Fixes
* **adapters:** withhold structured output without a validated destination ([8fcd376](https://github.com/hashgraph-online/hol-guard/commit/8fcd376b68be5d3b57c669cedc773e39cac6091c))
* **ci:** align macOS verification and surface native build blockers ([#3356](https://github.com/hashgraph-online/hol-guard/issues/3356)) ([d9fd6aa](https://github.com/hashgraph-online/hol-guard/commit/d9fd6aa9518371bec5ad9e2016fc5b770bbf2dd6))
* **command:** evaluate bounded timeout commands through native controls ([8523d6b](https://github.com/hashgraph-online/hol-guard/commit/8523d6b67e6a73a836679d36834729c40f9bc26d))

## [3.16.1](https://github.com/hashgraph-online/hol-guard/compare/v3.16.0...v3.16.1) (2026-10-01)

### Bug Fixes
* **codex:** bound optional hook diagnostics ([fde51df](https://github.com/hashgraph-online/hol-guard/commit/fde51df1df40413397a033476e0fce75da84a3b6))
* **codex:** preserve ownership conflicts for aliased Python imports ([f94860c](https://github.com/hashgraph-online/hol-guard/commit/f94860cb3efcd93bdec752fed0ddaee8fa7eae7e))
* **native:** bound managed client cleanup by the caller deadline ([14f4f8d](https://github.com/hashgraph-online/hol-guard/commit/14f4f8ded6de5a6477702538c525765c8cf2e576))

### Performance Improvements

* **ci:** give Sonar dedicated CPU and heap budgets ([#3350](https://github.com/hashgraph-online/hol-guard/issues/3350)) ([e22c395](https://github.com/hashgraph-online/hol-guard/commit/e22c395f7f0d2ae08b784a71a1e5cbb4e4dad61c))

## [3.16.0](https://github.com/hashgraph-online/hol-guard/compare/v3.15.6...v3.16.0) (2026-10-01)

### Features

* **mcp:** show app summaries from existing Codex hosts ([7c1e9b6](https://github.com/hashgraph-online/hol-guard/commit/7c1e9b60b44d82fbfd770b8cbd19fb7cbcf90a4e))

## [3.15.6](https://github.com/hashgraph-online/hol-guard/compare/v3.15.5...v3.15.6) (2026-10-01)

### Bug Fixes

* **approvals:** consume native reviews bound to policy domains ([7b3cf82](https://github.com/hashgraph-online/hol-guard/commit/7b3cf82c8ab08728d8d2c07ae60caa62175f4756))
* **claude:** deny tool actions when native review is unavailable ([9a97d62](https://github.com/hashgraph-online/hol-guard/commit/9a97d620a66654b4a24896efdc88dfcf74c7736e))
* **codex:** reject conflicting unowned Guard hooks ([cb47a1a](https://github.com/hashgraph-online/hol-guard/commit/cb47a1adcde5552a11517133a8308c807d20d473))
* **command:** recognize benign head and tail pipeline input ([e5aada7](https://github.com/hashgraph-online/hol-guard/commit/e5aada7c1132c43b521b9e21783711cc204b919f))
* **containment:** reject executable identity races ([#3331](https://github.com/hashgraph-online/hol-guard/issues/3331)) ([4faebae](https://github.com/hashgraph-online/hol-guard/commit/4faebae7f59707c74445dbd4e7ea0f21af715a70))
* **guard:** move archive inspection lease and containment into the Rust worker ([#3330](https://github.com/hashgraph-online/hol-guard/issues/3330)) ([d79f0c4](https://github.com/hashgraph-online/hol-guard/commit/d79f0c47d7d01ebbcf6487890bd77d9419a3ae6a))
* **hooks:** emit native failure responses as JSON ([6bdbc54](https://github.com/hashgraph-online/hol-guard/commit/6bdbc542d912ce338b838e8af927334f187819ad))
* **native:** honor the caller budget during resident startup ([399f7cb](https://github.com/hashgraph-online/hol-guard/commit/399f7cbcc1322ef43f4240c17c9c18f0ef6a69ce))

## [3.15.5](https://github.com/hashgraph-online/hol-guard/compare/v3.15.4...v3.15.5) (2026-10-01)

### Bug Fixes

* **mcp:** discover up to 100 configured servers ([#3317](https://github.com/hashgraph-online/hol-guard/issues/3317)) ([02b3aad](https://github.com/hashgraph-online/hol-guard/commit/02b3aad99e1b880010019b47cf111dc61486bd0f))

## [3.15.4](https://github.com/hashgraph-online/hol-guard/compare/v3.15.3...v3.15.4) (2026-10-01)

### Bug Fixes

* **mcp:** explain discovery capability rejections ([b2bc18f](https://github.com/hashgraph-online/hol-guard/commit/b2bc18fb3abcc64e60d6f5829307d9204c3fc56c))

## [3.15.3](https://github.com/hashgraph-online/hol-guard/compare/v3.15.2...v3.15.3) (2026-10-01)

### Bug Fixes

* **ci:** dispatch Desktop Core feeds after verified publication ([8c3dc97](https://github.com/hashgraph-online/hol-guard/commit/8c3dc9750789c407ca8c78508507296cda8e7d01))
* **ci:** isolate test setup and trim worker dependencies ([766db3b](https://github.com/hashgraph-online/hol-guard/commit/766db3bdf02eb2722d42a8e169f7993befa7a5a2))
* **ci:** retain bounded receipt persistence diagnostics ([0e6fbef](https://github.com/hashgraph-online/hol-guard/commit/0e6fbefcff1b919ff7f11d5632f4609cf9eaf019))

## [3.15.2](https://github.com/hashgraph-online/hol-guard/compare/v3.15.1...v3.15.2) (2026-10-01)

### Performance Improvements

* **mcp:** reduce decision connection overhead and page connectors ([ad915da](https://github.com/hashgraph-online/hol-guard/commit/ad915da0488d4665ef8b83999d2705d919520d9d))

## [3.15.1](https://github.com/hashgraph-online/hol-guard/compare/v3.15.0...v3.15.1) (2026-10-01)

### Bug Fixes

* **ci:** preserve pending Core feed publishers ([99e2b36](https://github.com/hashgraph-online/hol-guard/commit/99e2b36f1324b2168454d148135942bc015c2167))
* **ci:** wake Core feeds after stable publication ([a9e0657](https://github.com/hashgraph-online/hol-guard/commit/a9e0657391476bf2590f8cd96e82fa74cd029812))
* **mcp:** diagnose inventory refresh failures ([a9ddedb](https://github.com/hashgraph-online/hol-guard/commit/a9ddedb5d8605d85381864943cce41a259e488db))

## [3.15.0](https://github.com/hashgraph-online/hol-guard/compare/v3.14.1...v3.15.0) (2026-10-01)

### Features

* **guard:** move offline archive inspection into the Rust runtime ([#3300](https://github.com/hashgraph-online/hol-guard/issues/3300)) ([61ef105](https://github.com/hashgraph-online/hol-guard/commit/61ef105eb7aae0aa8a8c9c4e46ec3a83a976efd0))
* **mcp:** add reviewed Undo for Codex setup ([#3289](https://github.com/hashgraph-online/hol-guard/issues/3289)) ([9e6ccb1](https://github.com/hashgraph-online/hol-guard/commit/9e6ccb1cd5ab93a0c9b2c7e0ce69bb6d1f6f1ef4))

## [3.14.1](https://github.com/hashgraph-online/hol-guard/compare/v3.14.0...v3.14.1) (2026-09-30)

### Bug Fixes

* **daemon:** load pipx shared dependencies during isolated startup ([6af80cb](https://github.com/hashgraph-online/hol-guard/commit/6af80cb3540a66732eeabae2d21ff72e6a29ffc9))
* **hooks:** deny protected requests without native decisions ([#3228](https://github.com/hashgraph-online/hol-guard/issues/3228)) ([eba5953](https://github.com/hashgraph-online/hol-guard/commit/eba59535d34f93637a8736d0b10045ea848c8d90))

## [3.14.0](https://github.com/hashgraph-online/hol-guard/compare/v3.13.1...v3.14.0) (2026-09-30)

### Features

* **hook:** native hook pipeline with context-token approval provenance ([#3154](https://github.com/hashgraph-online/hol-guard/issues/3154)) ([599617c](https://github.com/hashgraph-online/hol-guard/commit/599617c34e56a5840bdc79b4e3029a1b08aa8939))

### Bug Fixes

* **codex:** require trusted decisions during evaluator outages ([#3219](https://github.com/hashgraph-online/hol-guard/issues/3219)) ([96ab771](https://github.com/hashgraph-online/hol-guard/commit/96ab7714f4c1c5800c8e5ea00ec1a0e7879c2c43))
* **cursor:** deny parsed actions when trusted evaluation is unavailable ([5f6a902](https://github.com/hashgraph-online/hol-guard/commit/5f6a902696fda77231b2338429ac941c7b21e874))
* **cursor:** deny unparsed actions without mode authority ([9135fd7](https://github.com/hashgraph-online/hol-guard/commit/9135fd7bca2e75f0986be053fe4979899488db4a))
* **deps:** bump urllib3 to 2.8.0 for CVE-2026-97687 and CVE-2026-97689 ([#3294](https://github.com/hashgraph-online/hol-guard/issues/3294)) ([58e41cc](https://github.com/hashgraph-online/hol-guard/commit/58e41cc259b19c9b39800a72611d510d83bdb1b7))
* **hooks:** close daemon responses before reusing connections ([#3296](https://github.com/hashgraph-online/hol-guard/issues/3296)) ([62e2b6f](https://github.com/hashgraph-online/hol-guard/commit/62e2b6f373515bfdca719ac494b9ce6087b71d8f))
* **hooks:** require trusted decisions in bounded fallback paths ([#3233](https://github.com/hashgraph-online/hol-guard/issues/3233)) ([903ae14](https://github.com/hashgraph-online/hol-guard/commit/903ae149c15d5b63088c0fde69acfbd2b6a8739c))

## [3.13.1](https://github.com/hashgraph-online/hol-guard/compare/v3.13.0...v3.13.1) (2026-09-30)

### Bug Fixes

* **dashboard:** restore custom connector detail rendering ([1f9d2b2](https://github.com/hashgraph-online/hol-guard/commit/1f9d2b2134cf8838b2d481c7325160ddd707f884))
* **release:** build Linux Core on Ubuntu 22.04 ([90243d2](https://github.com/hashgraph-online/hol-guard/commit/90243d265a4b88f87651c3eba516c0e1e054a147))

## [3.13.0](https://github.com/hashgraph-online/hol-guard/compare/v3.12.3...v3.13.0) (2026-09-30)

### Features

* **approval:** add reviewed workspace authority issuer ([#3220](https://github.com/hashgraph-online/hol-guard/issues/3220)) ([d0bf908](https://github.com/hashgraph-online/hol-guard/commit/d0bf9081635d2b091723dcb016d10299ea24d68b))

### Bug Fixes

* **ci:** retry transient coverage API failures within a bounded deadline ([caf9fe4](https://github.com/hashgraph-online/hol-guard/commit/caf9fe46960d1a519adbc234bf6ea16225a1a472))
* **doctor:** distinguish native availability from verified protection ([a61c21f](https://github.com/hashgraph-online/hol-guard/commit/a61c21f20f5164e9c3466e6868a16df08ad63316))
* **opencode:** restore V2 hooks and managed MCP connections ([432551e](https://github.com/hashgraph-online/hol-guard/commit/432551e1edce6e175a2d7505872753628415f042))
* **opencode:** review shell commands in their effective working directory ([#3276](https://github.com/hashgraph-online/hol-guard/issues/3276)) ([c0fe132](https://github.com/hashgraph-online/hol-guard/commit/c0fe1324918e11af822e27985ebe61ecbeb3b5fa))
* **pretool:** classify Devin exec and prove bounded home-relative reads benign ([#3243](https://github.com/hashgraph-online/hol-guard/issues/3243)) ([0d9f7f7](https://github.com/hashgraph-online/hol-guard/commit/0d9f7f7988ae59903a2a7da3c8a1fd39f92693f5))

## [3.12.3](https://github.com/hashgraph-online/hol-guard/compare/v3.12.2...v3.12.3) (2026-09-30)

### Bug Fixes

* **guard:** recognize Codex command output budgets ([9e70f1f](https://github.com/hashgraph-online/hol-guard/commit/9e70f1f189c7750f5f2f4214cd87dc21dbecdbad))

## [3.12.2](https://github.com/hashgraph-online/hol-guard/compare/v3.12.1...v3.12.2) (2026-09-29)

### Bug Fixes

* **doctor:** identify Desktop-managed bundled installations ([b0d2df7](https://github.com/hashgraph-online/hol-guard/commit/b0d2df77033e5fb0cdb94094f0e489bc1b10454f))

## [3.12.1](https://github.com/hashgraph-online/hol-guard/compare/v3.12.0...v3.12.1) (2026-09-29)

### Bug Fixes

* **cli:** preserve package approval links and recovery guidance ([#2905](https://github.com/hashgraph-online/hol-guard/issues/2905)) ([109057c](https://github.com/hashgraph-online/hol-guard/commit/109057c75270c74033b6789e7c3e8ccd6bb4dc2c))
* **daemon:** reclaim onefile extraction dirs left by killed launches ([#3224](https://github.com/hashgraph-online/hol-guard/issues/3224)) ([687c94c](https://github.com/hashgraph-online/hol-guard/commit/687c94c0d3deae12a0ae8f9d12c6f4e214f171c0))
* **dashboard:** submit Cloud Review authorization with Enter ([#3237](https://github.com/hashgraph-online/hol-guard/issues/3237)) ([dcfc369](https://github.com/hashgraph-online/hol-guard/commit/dcfc36952dc8042d45f8c3cab19b7b99859261d0))
* **guard:** treat stale paid-plan firewall claims as reconnect-required ([#3234](https://github.com/hashgraph-online/hol-guard/issues/3234)) ([564ed26](https://github.com/hashgraph-online/hol-guard/commit/564ed26a906ca16b728cd01ba0609dd4acca0aa8))
* **pi:** continue approved tool calls unchanged ([22aa017](https://github.com/hashgraph-online/hol-guard/commit/22aa01760cb8511fa40c6306c94a59f6fd5b3efb))
* **review:** quarantine terminal continuation binding mismatches ([65def12](https://github.com/hashgraph-online/hol-guard/commit/65def1215616da6d0e229d26f17988bde54895b0))

### Performance Improvements

* **ci:** parallelize native qualification and remove serial CI bottlenecks ([#3216](https://github.com/hashgraph-online/hol-guard/issues/3216)) ([a2581df](https://github.com/hashgraph-online/hol-guard/commit/a2581dfdf6f13a7ba613a1ceaeda099b45c76394))

## [3.12.0](https://github.com/hashgraph-online/hol-guard/compare/v3.11.1...v3.12.0) (2026-09-29)

### Features

* **guard:** classify declared sensitive fields with bounded local scan ([#3213](https://github.com/hashgraph-online/hol-guard/issues/3213)) ([f72566a](https://github.com/hashgraph-online/hol-guard/commit/f72566ae79a18fbb416c082dfd7afe68d902490c))

### Bug Fixes

* **ci:** retry intel SLO attempts that crash without a report ([#3208](https://github.com/hashgraph-online/hol-guard/issues/3208)) ([d346100](https://github.com/hashgraph-online/hol-guard/commit/d346100cfcf128b1e8055049777320fde3cd0e50))
* **desktop-core:** accept in-tree framework symlinks in the onedir sidecar ([#3230](https://github.com/hashgraph-online/hol-guard/issues/3230)) ([a90dbc8](https://github.com/hashgraph-online/hol-guard/commit/a90dbc8179743d27b9e02df9cbfd75b23d6b45b5))
* **hooks:** repair a tampered command policy from the local dashboard ([#3205](https://github.com/hashgraph-online/hol-guard/issues/3205)) ([311c0ea](https://github.com/hashgraph-online/hol-guard/commit/311c0eaab6d3a343abb92ba89f0ea7190e1e2e85))
* **store:** gate every live store connection and keep quarantine forensics ([#3222](https://github.com/hashgraph-online/hol-guard/issues/3222)) ([944b050](https://github.com/hashgraph-online/hol-guard/commit/944b0506843738fdd7b2e80b308bc6ad926debc7))

## [3.11.1](https://github.com/hashgraph-online/hol-guard/compare/v3.11.0...v3.11.1) (2026-09-29)

### Bug Fixes

* **daemon:** re-register the runtime after store recovery and report repair reasons ([#3214](https://github.com/hashgraph-online/hol-guard/issues/3214)) ([3b5d5ff](https://github.com/hashgraph-online/hol-guard/commit/3b5d5ff1ba785d36ac762014141db726d370da95))
* **desktop-core:** read the hardened-runtime flag from the CodeDirectory line ([#3223](https://github.com/hashgraph-online/hol-guard/issues/3223)) ([a4fb2b9](https://github.com/hashgraph-online/hol-guard/commit/a4fb2b929945b8fe3bd111a32c473b24d5f9ae46))
* **mcp:** avoid expired status after zero-TTL discovery ([4526038](https://github.com/hashgraph-online/hol-guard/commit/45260383570af33056ba7608f382ae12297e69e9))

## [3.11.0](https://github.com/hashgraph-online/hol-guard/compare/v3.10.0...v3.11.0) (2026-09-29)

### Features

* **desktop-core:** publish a sealed onedir Core sidecar with a v2 manifest ([#3212](https://github.com/hashgraph-online/hol-guard/issues/3212)) ([e51ae5c](https://github.com/hashgraph-online/hol-guard/commit/e51ae5ce29f36a1fbbf00c9270afdbe6bd7f81b4))

### Bug Fixes

* **codex:** deny actions when daemon and fallback fail ([#3211](https://github.com/hashgraph-online/hol-guard/issues/3211)) ([72cf721](https://github.com/hashgraph-online/hol-guard/commit/72cf721f15078708e760efdbd0d939035b77174b))
* **oauth:** stop dead-grant refresh storms with a persisted circuit breaker ([#3203](https://github.com/hashgraph-online/hol-guard/issues/3203)) ([99b4309](https://github.com/hashgraph-online/hol-guard/commit/99b43098f33f4797d9d1916b1ff3314e746840e7))

## [3.10.0](https://github.com/hashgraph-online/hol-guard/compare/v3.9.0...v3.10.0) (2026-09-29)

### Features

* **evaluation:** add bounded synthetic scenario runner ([#3200](https://github.com/hashgraph-online/hol-guard/issues/3200)) ([40808be](https://github.com/hashgraph-online/hol-guard/commit/40808be6878e05c5965e1a0f9108a1d483dbb2c4))
* **extensions:** add ctty command protection extension ([#3072](https://github.com/hashgraph-online/hol-guard/issues/3072)) ([69ec1fe](https://github.com/hashgraph-online/hol-guard/commit/69ec1fec840d584d55cc179b3b3adc9b8f8fefea))
* **extensions:** add digline command extension ([#3098](https://github.com/hashgraph-online/hol-guard/issues/3098)) ([24dde71](https://github.com/hashgraph-online/hol-guard/commit/24dde71512610844f1d0128af0f2b92c7d43d75a))
* **extensions:** add gitsync command source ([#3186](https://github.com/hashgraph-online/hol-guard/issues/3186)) ([a972c3e](https://github.com/hashgraph-online/hol-guard/commit/a972c3e706f87bdd469f9445d649e0d62ea22280))
* **mcp:** discover connectors and review granular permissions ([bf0313c](https://github.com/hashgraph-online/hol-guard/commit/bf0313c44675d7a42948a7d97b53f92bd860bbe9))

### Bug Fixes

* **approval-center:** distinguish Watch observations from paused actions ([#3196](https://github.com/hashgraph-online/hol-guard/issues/3196)) ([f68b29f](https://github.com/hashgraph-online/hol-guard/commit/f68b29f48bd9cf4d3cd76da0ccdb2cdc2227f668))
* **cli:** keep version probes fast for temporary binary names ([#3198](https://github.com/hashgraph-online/hol-guard/issues/3198)) ([4deeb15](https://github.com/hashgraph-online/hol-guard/commit/4deeb154eb5ba0d2829c28a303207ae5b3331576))
* **codex:** proxy managed hooks through the resident daemon before frozen imports ([#3197](https://github.com/hashgraph-online/hol-guard/issues/3197)) ([2c63d18](https://github.com/hashgraph-online/hol-guard/commit/2c63d18c6766ee311ca146343364db541a3170b3))
* **doctor:** count configured Codex hook shapes in incident export ([#3192](https://github.com/hashgraph-online/hol-guard/issues/3192)) ([d2f7cb6](https://github.com/hashgraph-online/hol-guard/commit/d2f7cb669ed3273617775c92cac9433e2369358c))
* **extensions:** authenticate regen pushes with basic x-access-token ([#3206](https://github.com/hashgraph-online/hol-guard/issues/3206)) ([248bfdd](https://github.com/hashgraph-online/hol-guard/commit/248bfdd9c5f4549191c1cbab486a495caf26af55))
* **extensions:** build runtime bin explicitly in artifact refresh ([#3207](https://github.com/hashgraph-online/hol-guard/issues/3207)) ([e9b03f1](https://github.com/hashgraph-online/hol-guard/commit/e9b03f18945e8ab89713b1dbbf49a1ea6d06a329))
* **extensions:** explain publisher claim benefits in notices ([f6b967c](https://github.com/hashgraph-online/hol-guard/commit/f6b967c0af32c36069e17b04b9ce77b4c18782b9))
* **extensions:** publish regenerated artifacts via pull request ([#3204](https://github.com/hashgraph-online/hol-guard/issues/3204)) ([6a19c30](https://github.com/hashgraph-online/hol-guard/commit/6a19c302a7745952d482296035c9b68a2a6806c8))
* **security:** ignore bracketed placeholder secrets outside docs paths ([#3091](https://github.com/hashgraph-online/hol-guard/issues/3091)) ([#3109](https://github.com/hashgraph-online/hol-guard/issues/3109)) ([d952623](https://github.com/hashgraph-online/hol-guard/commit/d9526234cbb5070de1fec1a4928df22cb5abbd57))

### Documentation

* **readme:** add Ask DeepWiki badge ([#3201](https://github.com/hashgraph-online/hol-guard/issues/3201)) ([337b654](https://github.com/hashgraph-online/hol-guard/commit/337b654148da605397902944a3ae80c7d9c11a44))

## [3.9.0](https://github.com/hashgraph-online/hol-guard/compare/v3.8.0...v3.9.0) (2026-09-28)

### Features

* add COGEXT command source ([#3146](https://github.com/hashgraph-online/hol-guard/issues/3146)) ([c906867](https://github.com/hashgraph-online/hol-guard/commit/c906867172e16b3d3b226132d8c25aaa0df0fe68))
* **command:** add gEnclave CLI protection extension (command.genclave) ([#3151](https://github.com/hashgraph-online/hol-guard/issues/3151)) ([52db423](https://github.com/hashgraph-online/hol-guard/commit/52db42310051f9fd426c2b5e3c727f4ee6c08290))
* **extensions:** add PR UI Compare MCP server contribution ([#3118](https://github.com/hashgraph-online/hol-guard/issues/3118)) ([9809915](https://github.com/hashgraph-online/hol-guard/commit/98099157cf541dd250c6e222babef3d18155b7bd))

### Bug Fixes

* **dashboard:** keep approval gate credentials reachable while gate is off ([#3181](https://github.com/hashgraph-online/hol-guard/issues/3181)) ([3727fbe](https://github.com/hashgraph-online/hol-guard/commit/3727fbeb23bc2cb03c97f960bd36ed941abe37e0))
* **dashboard:** route approval proof dead-ends to gate setup ([#3183](https://github.com/hashgraph-online/hol-guard/issues/3183)) ([2af6dbd](https://github.com/hashgraph-online/hol-guard/commit/2af6dbd6e2a3e7a26581132e2a951f11ddc84296))
* **desktop:** answer bootstrap from the running daemon ([#3191](https://github.com/hashgraph-online/hol-guard/issues/3191)) ([ddcb04b](https://github.com/hashgraph-online/hol-guard/commit/ddcb04b7e4716fd3e228b60a2dc80836edf5a048))
* **zcode:** map review tier to ZCode native ask prompt ([#3184](https://github.com/hashgraph-online/hol-guard/issues/3184)) ([dad342b](https://github.com/hashgraph-online/hol-guard/commit/dad342b92fb7d8dc2c027224efbda79ab429fe37))

### Documentation

* add Vercel OSS Program badge ([#3189](https://github.com/hashgraph-online/hol-guard/issues/3189)) ([083169c](https://github.com/hashgraph-online/hol-guard/commit/083169ce30bc6c4b948bca1a69470c6bb96df67c))
* **guard:** add Agent Skills frontmatter ([#2998](https://github.com/hashgraph-online/hol-guard/issues/2998)) ([d61ff00](https://github.com/hashgraph-online/hol-guard/commit/d61ff00bd98594aa2b5dc37b45570753c3fdd7a4))

## [3.8.0](https://github.com/hashgraph-online/hol-guard/compare/v3.7.6...v3.8.0) (2026-09-28)

### Features

* **doctor:** add bounded offline Codex incident report ([#3175](https://github.com/hashgraph-online/hol-guard/issues/3175)) ([4487237](https://github.com/hashgraph-online/hol-guard/commit/4487237fb5b0ef8fb133524ef8d6434f217dd233))
* **evaluation:** package validated evidence from CLI ([273961f](https://github.com/hashgraph-online/hol-guard/commit/273961f1d997c0aaf8c58698b00a79da6f119b43))

## [3.7.6](https://github.com/hashgraph-online/hol-guard/compare/v3.7.5...v3.7.6) (2026-09-28)

### Bug Fixes

* **diagnostics:** explain native extension evaluation failures ([#3155](https://github.com/hashgraph-online/hol-guard/issues/3155)) ([3ec32b1](https://github.com/hashgraph-online/hol-guard/commit/3ec32b1762f5b67dfef6086f0e5b457f3818ac02))
* **release:** retry temporary PyPI metadata errors ([#3170](https://github.com/hashgraph-online/hol-guard/issues/3170)) ([5bfec94](https://github.com/hashgraph-online/hol-guard/commit/5bfec94bb65cb66c7cd00b04cdfaa5b545933dee))

## [3.7.5](https://github.com/hashgraph-online/hol-guard/compare/v3.7.2...v3.7.5) (2026-09-27)

### Bug Fixes

* **core:** answer version probes before frozen runtime imports ([#3144](https://github.com/hashgraph-online/hol-guard/issues/3144)) ([722c97e](https://github.com/hashgraph-online/hol-guard/commit/722c97e0853d150460434f2846da8695ab5273cf))
* **daemon:** keep a still-starting daemon alive at the start budget ([#3149](https://github.com/hashgraph-online/hol-guard/issues/3149)) ([0dae754](https://github.com/hashgraph-online/hol-guard/commit/0dae7542ba4ae640c99a6f6cf2012e1a2a6d4456))
* **dashboard:** keep Update HOL Guard action visible on every view ([#3143](https://github.com/hashgraph-online/hol-guard/issues/3143)) ([cb72ade](https://github.com/hashgraph-online/hol-guard/commit/cb72adebe0a2863e2550dcaf3d6a530b7ed29428))
* **diagnostics:** hide error details when redaction fails ([0ef32aa](https://github.com/hashgraph-online/hol-guard/commit/0ef32aa0ffd80027f88679a8c542c0f569ecea8f))
* **doctor:** distinguish runtime readiness from registration ([#3136](https://github.com/hashgraph-online/hol-guard/issues/3136)) ([e4b6449](https://github.com/hashgraph-online/hol-guard/commit/e4b6449781f1a26c676a5fb8f3248c8db2a336ea))
* **hooks:** keep Watch ready while native snapshots republish ([05b7bc2](https://github.com/hashgraph-online/hol-guard/commit/05b7bc2fadb1b3deb9fbec50e74313d028ce5dd2))
* **release:** accept a repair attestation from the main dispatch commit ([#3141](https://github.com/hashgraph-online/hol-guard/issues/3141)) ([4c3e95a](https://github.com/hashgraph-online/hol-guard/commit/4c3e95aadf98130b25d074d5c27d6117eda067b7))
* **release:** finish GitHub assets when PyPI visibility lags ([#3138](https://github.com/hashgraph-online/hol-guard/issues/3138)) ([e1b8ef1](https://github.com/hashgraph-online/hol-guard/commit/e1b8ef1db1996a08b39e2eed26065d43ab8d1f82))
* **release:** retry absent registry artifacts ([#3139](https://github.com/hashgraph-online/hol-guard/issues/3139)) ([505c62e](https://github.com/hashgraph-online/hol-guard/commit/505c62e1e0fd506ff4d040d8cba2dd2ca1fb25f4))

## [3.7.2](https://github.com/hashgraph-online/hol-guard/compare/v3.7.1...v3.7.2) (2026-09-27)

### Bug Fixes

* **codex:** authenticate managed fallback after worker failure ([#3133](https://github.com/hashgraph-online/hol-guard/issues/3133)) ([bf00b65](https://github.com/hashgraph-online/hol-guard/commit/bf00b65ff8e29842692835363845911fabc22954))
* **evaluation:** bound process probes ([#3135](https://github.com/hashgraph-online/hol-guard/issues/3135)) ([5b5508b](https://github.com/hashgraph-online/hol-guard/commit/5b5508b8a1237b1e71dfd0c487432e0781404548))

## [3.7.1](https://github.com/hashgraph-online/hol-guard/compare/v3.7.0...v3.7.1) (2026-09-27)

### Bug Fixes

* **dashboard:** keep historical native reviews approvable ([#3130](https://github.com/hashgraph-online/hol-guard/issues/3130)) ([7851c8d](https://github.com/hashgraph-online/hol-guard/commit/7851c8d8525a6672ffb3ba0429324ca75fe8b944))

## [3.7.0](https://github.com/hashgraph-online/hol-guard/compare/v3.6.4...v3.7.0) (2026-09-27)

### Features

* **mcp:** detect connectors and manage per-tool permissions ([#3125](https://github.com/hashgraph-online/hol-guard/issues/3125)) ([a539279](https://github.com/hashgraph-online/hol-guard/commit/a5392792063cb3e061e0a8dfb2a122fee7d13f05))

## [3.6.4](https://github.com/hashgraph-online/hol-guard/compare/v3.6.3...v3.6.4) (2026-09-26)

### Bug Fixes

* **runtime:** reap detached hook workers before the replacement daemon starts ([a450f6b](https://github.com/hashgraph-online/hol-guard/commit/a450f6b0c19b3ec94a60a156b9924a7d2a038a73))
* stabilize native approval retries and bulk inbox submission ([#3121](https://github.com/hashgraph-online/hol-guard/issues/3121)) ([e5350eb](https://github.com/hashgraph-online/hol-guard/commit/e5350eb2427d7948b0ec54d2cfbf790c62507cbc))

## [3.6.3](https://github.com/hashgraph-online/hol-guard/compare/v3.6.2...v3.6.3) (2026-09-26)

### Bug Fixes

* **runtime:** drain stale resident leases past the directory cap ([#3124](https://github.com/hashgraph-online/hol-guard/issues/3124)) ([277707b](https://github.com/hashgraph-online/hol-guard/commit/277707b3a44d7237b1470b5d88c5460ace5def3e))

## [3.6.2](https://github.com/hashgraph-online/hol-guard/compare/v3.6.1...v3.6.2) (2026-09-26)

### Bug Fixes

* **command:** hide observe-mode warnings for proven local lookups ([#3122](https://github.com/hashgraph-online/hol-guard/issues/3122)) ([3292474](https://github.com/hashgraph-online/hol-guard/commit/3292474fa2373da9a17471360fcd890dc099f237))

## [3.6.1](https://github.com/hashgraph-online/hol-guard/compare/v3.6.0...v3.6.1) (2026-09-25)

### Bug Fixes

* **ci:** stabilize Windows native CI timing ([#3115](https://github.com/hashgraph-online/hol-guard/issues/3115)) ([ad36211](https://github.com/hashgraph-online/hol-guard/commit/ad3621183d5b33079d858450d476e135bbb87d08))
* **guard:** include evaluation command in release wheel ([#3116](https://github.com/hashgraph-online/hol-guard/issues/3116)) ([9ad7c06](https://github.com/hashgraph-online/hol-guard/commit/9ad7c0631379cf85aacd4020517e3bda320851ad))

## [3.6.0](https://github.com/hashgraph-online/hol-guard/compare/v3.5.1...v3.6.0) (2026-09-25)

### Features

* **guard:** add staged evaluation CLI ([#3110](https://github.com/hashgraph-online/hol-guard/issues/3110)) ([54ab9a9](https://github.com/hashgraph-online/hol-guard/commit/54ab9a9f309c191800273e477c6606358cadb2c2))

### Bug Fixes

* **command:** prove bounded clock, listing, and file reads benign ([#3113](https://github.com/hashgraph-online/hol-guard/issues/3113)) ([7b9b5c1](https://github.com/hashgraph-online/hol-guard/commit/7b9b5c18ab3c37f2701b2cc3fd9c9df1f0995d19))

## [3.5.1](https://github.com/hashgraph-online/hol-guard/compare/v3.5.0...v3.5.1) (2026-09-25)

### Bug Fixes

* **dashboard:** replace window.confirm with an in-app confirmation dialog ([#3108](https://github.com/hashgraph-online/hol-guard/issues/3108)) ([2e62aab](https://github.com/hashgraph-online/hol-guard/commit/2e62aab4b914cbd3df8f83708edcacdfb04dbcc3))
* **guard:** keep Windows command paths and daemon startup ([#3101](https://github.com/hashgraph-online/hol-guard/issues/3101)) ([3415ade](https://github.com/hashgraph-online/hol-guard/commit/3415adeb2dc171b81a0a7185a573f5a4ee313c86))
* **runtime:** keep native policy prep working when old resident scopes pile up ([#3106](https://github.com/hashgraph-online/hol-guard/issues/3106)) ([0986515](https://github.com/hashgraph-online/hol-guard/commit/0986515e7969d9dd5b14bb3554b58fc1523309da))

## [3.5.0](https://github.com/hashgraph-online/hol-guard/compare/v3.4.5...v3.5.0) (2026-09-24)

### Features

* **devin:** add Devin CLI harness adapter with managed native hooks ([#3099](https://github.com/hashgraph-online/hol-guard/issues/3099)) ([b992f68](https://github.com/hashgraph-online/hol-guard/commit/b992f680a263c264f5936b09bc91190351c72378))
* **guard:** add bounded command event parser ([#3097](https://github.com/hashgraph-online/hol-guard/issues/3097)) ([6a46a6e](https://github.com/hashgraph-online/hol-guard/commit/6a46a6ec3802524aa882f0d3582788f6959ac9fe))

### Bug Fixes

* **guard:** recover Linux enrollment without discarding native authority ([#3096](https://github.com/hashgraph-online/hol-guard/issues/3096)) ([856de33](https://github.com/hashgraph-online/hol-guard/commit/856de33862f1382012713a6a2a2d34a8e756ddac))
* **tests:** suppress real browser launches during pytest runs ([#3103](https://github.com/hashgraph-online/hol-guard/issues/3103)) ([694fc6c](https://github.com/hashgraph-online/hol-guard/commit/694fc6c5b3ad5d8dc2e99696202e4245092ca63b))

## [3.4.5](https://github.com/hashgraph-online/hol-guard/compare/v3.4.4...v3.4.5) (2026-09-24)

### Bug Fixes

* **dashboard:** clarify command activity run results ([#3090](https://github.com/hashgraph-online/hol-guard/issues/3090)) ([6d802ab](https://github.com/hashgraph-online/hol-guard/commit/6d802ab5f2c2edd7aa8e6dd3a5e645b8d91ba3ce))

## [3.4.4](https://github.com/hashgraph-online/hol-guard/compare/v3.4.3...v3.4.4) (2026-09-24)

### Bug Fixes

* **evidence:** preserve command context in action rows ([#3088](https://github.com/hashgraph-online/hol-guard/issues/3088)) ([2b250d9](https://github.com/hashgraph-online/hol-guard/commit/2b250d9a392880d69f46519e4ea88caab52a077d))

## [3.4.3](https://github.com/hashgraph-online/hol-guard/compare/v3.4.2...v3.4.3) (2026-09-24)

### Features

* Add an evidence-gated harness capability report ([#3081](https://github.com/hashgraph-online/hol-guard/pull/3081)) ([f5d568f](https://github.com/hashgraph-online/hol-guard/commit/f5d568f9c60d03cf26ec8ace7ed9aa8686af7ca7))
* Add bounded local evaluation contracts and witnesses ([#3083](https://github.com/hashgraph-online/hol-guard/pull/3083)) ([ddbe315](https://github.com/hashgraph-online/hol-guard/commit/ddbe315f62eb09dcca9ee2ef962061c172b76d9a))

### Bug Fixes

* Fail closed when Cline post-tool review is unavailable ([#3082](https://github.com/hashgraph-online/hol-guard/pull/3082)) ([e1472f7](https://github.com/hashgraph-online/hol-guard/commit/e1472f7d470d66bc6a2acf63ba8a55888ab4288f))
* **audit:** choose a project folder before running a workspace audit ([#3086](https://github.com/hashgraph-online/hol-guard/issues/3086)) ([c1afee9](https://github.com/hashgraph-online/hol-guard/commit/c1afee972e0cd77c70f67ad0bd6609c8b410805a))
* **contributors:** make extension PRs self-healing ([#3087](https://github.com/hashgraph-online/hol-guard/issues/3087)) ([b22841a](https://github.com/hashgraph-online/hol-guard/commit/b22841ac004b9d8a6deccdeee1a1be3600fddfb9))
* **dashboard:** show the Cloud Review authenticator field ([#3085](https://github.com/hashgraph-online/hol-guard/issues/3085)) ([7166570](https://github.com/hashgraph-online/hol-guard/commit/7166570f1465bfe970d4cc94250cb7b737f10875))
* **release:** follow the newest Release Please stable tag ([#3075](https://github.com/hashgraph-online/hol-guard/issues/3075)) ([13d2486](https://github.com/hashgraph-online/hol-guard/commit/13d24860d620b45ec3f542d5eec363ce7e121e00))
* **release:** verify Release Please wheels against their tag ([#3078](https://github.com/hashgraph-online/hol-guard/issues/3078)) ([56faea4](https://github.com/hashgraph-online/hol-guard/commit/56faea4878649668b84f83c351d112cc279954ac))

## [3.4.2](https://github.com/hashgraph-online/hol-guard/compare/v3.4.1...v3.4.2) (2026-09-23)

### Bug Fixes

* bind uivoid portable fixtures to canonical build sources ([77adeca](https://github.com/hashgraph-online/hol-guard/commit/77adeca00df50e6df670ae285cf8aa0cf3a19fea))
* **ci:** isolate Pi fallback probes and relax permission call count ([#3070](https://github.com/hashgraph-online/hol-guard/issues/3070)) ([035623b](https://github.com/hashgraph-online/hol-guard/commit/035623b74bcc26150806b5ea895a65af441b1433))
* **guard:** preserve native authority across Linux keyring sessions ([#3071](https://github.com/hashgraph-online/hol-guard/issues/3071)) ([9ac28e8](https://github.com/hashgraph-online/hol-guard/commit/9ac28e8f6a6ae9596c6a074585f10ecc1341f331))
* preserve option terminators in versioned package matching ([694d992](https://github.com/hashgraph-online/hol-guard/commit/694d9920c7b96fbbf63a5b5f861b1f83d3239eea))
* refresh decision report bindings after native matcher update ([e81eba1](https://github.com/hashgraph-online/hol-guard/commit/e81eba13ce9f9932d56213004c127d72cc12ea7d))
* **release-notes:** dedupe identities, credit nonconventional squashes, verify published predecessors ([830eef5](https://github.com/hashgraph-online/hol-guard/commit/830eef55a6f2b1d2c82dea8fb92fd1459ad934a6))

### Documentation

* **readme:** link the annotated release archive and contributor wall ([0655c56](https://github.com/hashgraph-online/hol-guard/commit/0655c5608f959f1e81d1ed7d6dfb6b18f5cec506))
* **readme:** link the release archive and contributor wall ([7e29453](https://github.com/hashgraph-online/hol-guard/commit/7e294534387b8dc87ade39f23ac0249e324ff9f7))

## [3.4.1](https://github.com/hashgraph-online/hol-guard/compare/v3.4.0...v3.4.1) (2026-09-22)

### Bug Fixes

* **supply-chain:** keep local repair responsive across workspaces ([#3063](https://github.com/hashgraph-online/hol-guard/issues/3063)) ([e9139a7](https://github.com/hashgraph-online/hol-guard/commit/e9139a7407430947b6e9e573a2f0d2d238cfbc27))

## [3.4.0](https://github.com/hashgraph-online/hol-guard/compare/v3.3.0...v3.4.0) (2026-09-22)

### Features

* **contributors:** support Gitar notice backfills ([#3053](https://github.com/hashgraph-online/hol-guard/issues/3053)) ([7a3932a](https://github.com/hashgraph-online/hol-guard/commit/7a3932ad277fb5f9bf12aff29ddb8e187e512cc5))
* **extensions:** streamline contributor handoffs ([#3048](https://github.com/hashgraph-online/hol-guard/issues/3048)) ([f3d829c](https://github.com/hashgraph-online/hol-guard/commit/f3d829ce117a161c9ab6418f9b450177b799edb8))

### Bug Fixes

* **ci:** stabilize native wheel validation ([#3046](https://github.com/hashgraph-online/hol-guard/issues/3046)) ([ff4de55](https://github.com/hashgraph-online/hol-guard/commit/ff4de55fc4071c57f31f7521a32a33ce65e93911))
* **codex:** deny tool use when the launcher cannot be authenticated ([#3061](https://github.com/hashgraph-online/hol-guard/issues/3061)) ([939517e](https://github.com/hashgraph-online/hol-guard/commit/939517e80890db5afe869bfbb79e4829b7502d83))
* **contributors:** explain Gitar fork access ([#3050](https://github.com/hashgraph-online/hol-guard/issues/3050)) ([3a791c1](https://github.com/hashgraph-online/hol-guard/commit/3a791c1a7a5f8a88d83bc16a8e80ff009c127840))
* **contributors:** notify blocked Gitar forks ([#3052](https://github.com/hashgraph-online/hol-guard/issues/3052)) ([ae36b89](https://github.com/hashgraph-online/hol-guard/commit/ae36b898e6515b347dcb42bd25cca3ff2fa5f05c))
* **dashboard:** reuse quick-apply bulk controls on extension detail and explain locked search ([#3043](https://github.com/hashgraph-online/hol-guard/issues/3043)) ([7f3ee58](https://github.com/hashgraph-online/hol-guard/commit/7f3ee58bf246342f8c3438f9f9b54430b53dd2af))
* **supply-chain:** review new hol-guard releases ([#3060](https://github.com/hashgraph-online/hol-guard/issues/3060)) ([d9ee378](https://github.com/hashgraph-online/hol-guard/commit/d9ee378da6c3643cba30b22c5e36fb35ea1b4981))

## [3.3.0](https://github.com/hashgraph-online/hol-guard/compare/v3.2.0...v3.3.0) (2026-09-21)

### Features

* **extensions:** simplify declarative contribution preparation ([b3371c6](https://github.com/hashgraph-online/hol-guard/commit/b3371c6557f6ab23ccf14861d62408fa8aaaace6))
* **extensions:** simplify declarative contribution preparation ([ca4e5c2](https://github.com/hashgraph-online/hol-guard/commit/ca4e5c2b45688e398ffea54de587ecbefc883971))

### Bug Fixes

* **extensions:** harden contributor preparation ([f078269](https://github.com/hashgraph-online/hol-guard/commit/f0782698b76fd5cb3469bab4d6d57662888b8893))
* **extensions:** preserve v2 catalog bytes on Windows ([b7fdf8e](https://github.com/hashgraph-online/hol-guard/commit/b7fdf8e2929dc3ab7965ca41f6b8f8ec99fee391))
* **extensions:** satisfy listing type check ([f96cc6b](https://github.com/hashgraph-online/hol-guard/commit/f96cc6b45421fa86d6a7e39f2861277951d6fc1f))
* **extensions:** snapshot directory exports ([a5d87e3](https://github.com/hashgraph-online/hol-guard/commit/a5d87e3cdff224d81271376d76b7b771184681db))
* **extensions:** stabilize source digests on Windows ([e147312](https://github.com/hashgraph-online/hol-guard/commit/e147312119f01c56155bb762bb6926e083397b32))
* **extensions:** validate listing schema types ([1db22ed](https://github.com/hashgraph-online/hol-guard/commit/1db22edf3215cf5e99a964b5f2b46dfd90f78bf9))
* **security:** resolve Scorecard dependency findings ([#3017](https://github.com/hashgraph-online/hol-guard/issues/3017)) ([ccd22e0](https://github.com/hashgraph-online/hol-guard/commit/ccd22e0386309e5dc5b64b9b0d378128dcf974bb))

### Dependencies

* **actions:** bump actions/attest-build-provenance from 4.1.0 to 4.2.2 ([#3036](https://github.com/hashgraph-online/hol-guard/issues/3036)) ([45a3849](https://github.com/hashgraph-online/hol-guard/commit/45a38493ad5a9532a12a78213029411d9f5d8ffd))
* **actions:** bump actions/setup-go from 6.4.0 to 7.0.0 ([#1597](https://github.com/hashgraph-online/hol-guard/issues/1597)) ([b709c12](https://github.com/hashgraph-online/hol-guard/commit/b709c120a1913e3af37f9151885c48752ed87288))
* **actions:** bump actions/upload-artifact from 4.6.2 to 7.0.1 ([#3023](https://github.com/hashgraph-online/hol-guard/issues/3023)) ([f663f92](https://github.com/hashgraph-online/hol-guard/commit/f663f92bbf775832ee36f81b3f4ce3654b5c2fa0))
* **actions:** bump docker/setup-buildx-action from 4.1.0 to 4.4.1 ([#3038](https://github.com/hashgraph-online/hol-guard/issues/3038)) ([d1bbb8b](https://github.com/hashgraph-online/hol-guard/commit/d1bbb8b8b2773ea3fb565a31604465de1206d8c2))
* **actions:** bump github/codeql-action/upload-sarif ([#3037](https://github.com/hashgraph-online/hol-guard/issues/3037)) ([d72d418](https://github.com/hashgraph-online/hol-guard/commit/d72d4185dc8a2d9633e3f17428703cb7e3c0fcb1))
* **actions:** bump ossf/scorecard-action from 2.4.3 to 2.4.4 ([#1957](https://github.com/hashgraph-online/hol-guard/issues/1957)) ([f9d29e1](https://github.com/hashgraph-online/hol-guard/commit/f9d29e1c66d04f40e380992ff73249a37c2da9f7))
* **bun:** bump @types/node from 24.13.3 to 26.6.1 in /dashboard ([#3026](https://github.com/hashgraph-online/hol-guard/issues/3026)) ([a37878b](https://github.com/hashgraph-online/hol-guard/commit/a37878ba67fe25ea670452e82386b01c679e8560))
* **bun:** bump typescript from 5.9.3 to 7.0.2 in /dashboard ([#3027](https://github.com/hashgraph-online/hol-guard/issues/3027)) ([1b146d4](https://github.com/hashgraph-online/hol-guard/commit/1b146d41c5c6641b2fe37593452a43fdf3d4489a))
* **docker:** bump astral-sh/uv ([#3025](https://github.com/hashgraph-online/hol-guard/issues/3025)) ([ca33e5d](https://github.com/hashgraph-online/hol-guard/commit/ca33e5d4bb734985a0254401abea18d8ab902d82))
* **pip:** bump the codex-lab-patch-minor group across 1 directory with 3 updates ([#3022](https://github.com/hashgraph-online/hol-guard/issues/3022)) ([8be6b27](https://github.com/hashgraph-online/hol-guard/commit/8be6b27c5d42894e4e79adf8f2317047e5b7e8b2))

### Documentation

* update Rust extension contribution workflow ([#3019](https://github.com/hashgraph-online/hol-guard/issues/3019)) ([5e6a619](https://github.com/hashgraph-online/hol-guard/commit/5e6a619ba026f512a09e87c0fbf254a6c464fbf5))

## [Unreleased]

### Fixed

- Claude marketplace scans treat `strict` as an optional boolean on each
  `plugins[]` entry (default `true`) instead of requiring a root-level field
  that Claude Code rejects.
- `HARDCODED_SECRET` no longer treats pure `${VAR}` or `{{var}}` expansions as
  embedded credentials outside docs and tests. Non-empty defaults and suffixes
  still fail.
- Native DeepSeek Harness packages can set `dsh.bundle.mode` to `"patch"` so
  patch-only bundles are not required to export Cordis `apply(ctx)`. Packages
  that declare `main` or `exports` still need that runtime.

### Changed

- Added the HOL Guard 3.0 Managed Controls user, operator, migration, recovery,
  incident, rollback, support, and release documentation set.
- Persistent menu-bar and system-tray ownership moved to the separate
  `hashgraph-online/hol-guard-desktop` application.
- HOL Guard Core remains headless and continues to own policy enforcement,
  approvals, receipts, the local daemon, browser dashboard, fallback
  notifications, updates, repair, and diagnostics.
- The canonical dashboard launcher remains available to trusted local callers.
- User-facing credential redaction moved to the platform-neutral
  `guard.secret_redaction` module.

### Removed

- Python/pystray tray runtime, platform startup adapters, tray CLI commands,
  dashboard tray controls, tray update handoff, tray assets, and tray-only
  dependencies.
