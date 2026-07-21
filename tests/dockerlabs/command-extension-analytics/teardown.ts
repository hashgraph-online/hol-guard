import {
  composeCommand,
  LAB_DIR,
  listProjectResources,
  requireSuccess,
  runCommand,
  safeProjectName,
  type CommandRunner,
} from "./lab-process";

export interface TeardownEvidence {
  command: "bun run guard:test:teardown";
  containers: 0;
  networks: 0;
  orphans: 0;
  project: string;
  status: "clean";
  volumes: 0;
}

export async function teardownLab(
  project: string,
  runner: CommandRunner = runCommand,
): Promise<TeardownEvidence> {
  const safeProject = safeProjectName(project);
  const result = await runner(composeCommand(safeProject, "down", "-v", "--remove-orphans"), {
    cwd: LAB_DIR,
    env: {
      HOL_GUARD_LAB_EXPECTED_VERSION: Bun.env.HOL_GUARD_LAB_EXPECTED_VERSION ?? "teardown-only",
      HOL_GUARD_LAB_PORT: Bun.env.HOL_GUARD_LAB_PORT ?? "4781",
      HOL_GUARD_LAB_WHEEL: Bun.env.HOL_GUARD_LAB_WHEEL ?? "teardown-only.whl",
    },
  });
  requireSuccess(result, "Dockerlabs teardown");
  const resources = await listProjectResources(safeProject, runner);
  const count = resources.containers.length + resources.volumes.length + resources.networks.length;
  if (count !== 0) throw new Error(`Dockerlabs cleanup incomplete: ${JSON.stringify(resources)}`);
  return {
    command: "bun run guard:test:teardown",
    containers: 0,
    networks: 0,
    orphans: 0,
    project: safeProject,
    status: "clean",
    volumes: 0,
  };
}

if (import.meta.main) {
  const project = Bun.env.GUARD_TEST_PROJECT ?? "guard-command-extension-analytics";
  console.log(JSON.stringify(await teardownLab(project)));
}
