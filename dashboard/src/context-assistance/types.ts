import type { GuardContextAssistanceConfig } from "../guard-types";
import type { ContextExecutionObservation } from "./execution-observation";
import type { CigarReleaseBinding } from "./release-version";

export type ContextRuntime = {
  schema: "guard-cigar-runtime-status.v1";
  interpreter: {
    schema: "guard-cigar-interpreter.v1";
    implementation: string;
    version: [number, number, number];
    release_level: string;
    free_threaded: boolean;
    debug_build: boolean;
    abi: string;
    platform: string;
  };
  package_version: string;
  core_version?: string;
  adapter_id?: string;
  adapter_revision?: number;
  release?: CigarReleaseBinding;
  protocol: string;
  package_fingerprint: string;
  worker_fingerprint: string;
  features: string[];
  compile_verified: boolean;
  shared_compile_verified?: boolean;
  persistence_compile_verified?: boolean;
  execution_handoff_verified?: boolean;
  active: boolean;
};

export type ContextInstallation = {
  runtime_id: string;
  qualification: "local_candidate" | "guard_qualified";
  sdk_version?: string;
  core_version?: string;
  build_id?: string | null;
  adapter_id?: string;
  adapter_revision?: number;
  managed?: boolean;
  python_version: [number, number, number];
  platform: string;
  worker_fingerprint: string;
};

export type ContextAssistanceStatus = {
  schema: "guard-context-assistance-status.v2";
  availability: "off" | "unavailable" | "checking" | "ready";
  requested_enabled: boolean;
  effective_enabled: boolean;
  preferences: GuardContextAssistanceConfig;
  effective_preferences: GuardContextAssistanceConfig;
  restriction: string | null;
  verification_permitted: boolean;
  generation: string;
  diagnostic: string | null;
  runtime: ContextRuntime | null;
  last_check: ContextRuntime | null;
  qualification: "local_candidate" | "guard_qualified" | null;
  capabilities?: { shared_agents: boolean; private_persistence: boolean; execution_context?: boolean };
  execution_ready?: boolean;
  execution_observations?: ContextExecutionObservation[] | null;
  installation_options: ContextInstallation[] | null;
  job: {
    id: string;
    operation: "activate" | "recheck";
    phase: "verifying" | "cancelling";
  } | null;
};

export type ContextControlAction = "recheck" | "activate" | "stop";
