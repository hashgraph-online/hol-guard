import { deriveSkillRiskSignals, deriveSupplyChainRiskSignals, deriveEncodedLayerSignals } from "./approval-center-utils";
import { SectionLabel } from "./approval-center-primitives";
import {
  isPackageExecutionContextEvidence,
  type GuardApprovalRequest,
  type PackageExecutionContextEvidence,
  type RiskSignalV2,
} from "./guard-types";

type SkillRiskCardProps = {
  item: GuardApprovalRequest;
};

export function SkillRiskCard(props: SkillRiskCardProps) {
  const skillSignals = deriveSkillRiskSignals(props.item);
  if (skillSignals.length === 0) return null;
  return (
    <div
      className="rounded-xl border border-brand-blue/20 bg-brand-blue/[0.04] p-4"
      aria-label="Skill risk details"
    >
      <SectionLabel>Skill risk</SectionLabel>
      <ul className="mt-3 space-y-3">
        {skillSignals.map((signal) => (
          <SkillSignalRow key={signal.signal_id} signal={signal} />
        ))}
      </ul>
    </div>
  );
}

type SkillSignalRowProps = {
  signal: RiskSignalV2;
};

function SkillSignalRow(props: SkillSignalRowProps) {
  const { signal } = props;
  return (
    <li className="space-y-1">
      <p className="text-sm font-semibold text-brand-dark">{signal.title}</p>
      <p className="text-sm leading-relaxed text-brand-dark/70">{signal.plain_reason}</p>
      {signal.technical_detail !== null ? (
        <p className="font-mono text-[11px] text-muted-foreground break-all">{signal.technical_detail}</p>
      ) : null}
      {signal.false_positive_hint !== null ? (
        <p className="text-xs leading-5 text-brand-dark/60">
          <span className="font-semibold">Might be safe if: </span>
          {signal.false_positive_hint}
        </p>
      ) : null}
    </li>
  );
}

type SupplyChainRiskCardProps = {
  item: GuardApprovalRequest;
};

export function SupplyChainRiskCard(props: SupplyChainRiskCardProps) {
  const scSignals = deriveSupplyChainRiskSignals(props.item);
  const packageContext = props.item.scanner_evidence?.find(isPackageExecutionContextEvidence) ?? null;
  const isSupplyChainArtifact =
    props.item.artifact_type === "supply_chain" ||
    props.item.artifact_type === "package_request" ||
    (typeof props.item.artifact_type === "string" && props.item.artifact_type.endsWith("_package"));
  if (scSignals.length === 0 && !isSupplyChainArtifact) return null;
  return (
    <div
      className="rounded-xl border border-brand-purple/20 bg-brand-purple/[0.04] p-4"
      aria-label="Supply-chain risk"
    >
      <SectionLabel>Supply-chain risk</SectionLabel>
      {scSignals.length > 0 ? (
        <ul className="mt-3 space-y-3">
          {scSignals.map((signal) => (
            <SupplyChainSignalRow key={signal.signal_id} signal={signal} />
          ))}
        </ul>
      ) : (
        <p className="mt-2 text-sm leading-relaxed text-brand-dark/70">
          This action originates from a supply-chain artifact. Verify the publisher and version before approving.
        </p>
      )}
      {packageContext !== null ? <PackageExecutionContextSummary context={packageContext} /> : null}
    </div>
  );
}

const PACKAGE_CONTEXT_LABELS: Record<string, string> = {
  environment_policy: "registry and proxy environment",
  exact_workspace: "project location",
  lifecycle_hooks_overrides_and_patches: "lifecycle hooks, overrides, or patches",
  manifests_and_lockfiles: "manifests or lockfiles",
  package_manager_executable: "package manager executable",
  registry_and_proxy_configuration: "registry or proxy configuration",
  repository_identity: "Git repository identity",
  workspace_configuration: "workspace configuration",
  workspace_identity: "workspace location within the repository",
};

function packageContextLabel(value: string): string {
  return PACKAGE_CONTEXT_LABELS[value] ?? value.replaceAll("_", " ");
}

function nonPortableReason(value: string | undefined): string {
  switch (value) {
    case "dynamic_manager_configuration":
      return "the package manager loads configuration dynamically";
    case "dynamic_lifecycle_hook":
      return "the project defines a lifecycle hook that can load additional local inputs";
    case "oversized_configuration":
      return "a package configuration input is too large to bind safely";
    case "package_manager_executable_unavailable":
      return "the package manager executable could not be verified";
    case "repository_identity_unavailable":
      return "a linked Git repository identity could not be verified";
    case "symlinked_configuration":
      return "a package configuration file is symlinked";
    case "unreadable_configuration":
      return "a package configuration input could not be read";
    case "unsupported_package_manager":
    case "unsupported_configuration":
      return "the package configuration is not safely portable";
    default:
      return "Guard could not verify every package execution input";
  }
}

export function packageExecutionContextMessages(context: PackageExecutionContextEvidence): string[] {
  const messages = [
    context.portable
      ? "A project approval is reused only in linked Git worktrees when the repository, package manager executable, dependency files, settings, hooks, overrides, patches, and registry/proxy environment all match."
      : `This approval is limited to one retry because ${nonPortableReason(context.non_portable_reason)}.`,
  ];
  const changedComponents = context.changed_components ?? [];
  if (changedComponents.length > 0) {
    messages.push(
      `Guard asked again because the following changed: ${changedComponents.map(packageContextLabel).join(", ")}.`,
    );
  }
  return messages;
}

function PackageExecutionContextSummary(props: { context: PackageExecutionContextEvidence }) {
  return (
    <div className="mt-3 border-t border-brand-purple/10 pt-3" aria-label="Package approval reuse">
      <p className="text-xs font-semibold uppercase tracking-wide text-brand-purple">Approval reuse</p>
      {packageExecutionContextMessages(props.context).map((message) => (
        <p key={message} className="mt-1 text-xs leading-5 text-brand-dark/70">
          {message}
        </p>
      ))}
    </div>
  );
}

type SupplyChainSignalRowProps = {
  signal: RiskSignalV2;
};

function SupplyChainSignalRow(props: SupplyChainSignalRowProps) {
  const { signal } = props;
  return (
    <li className="space-y-1">
      <p className="text-sm font-semibold text-brand-dark">{signal.title}</p>
      <p className="text-sm leading-relaxed text-brand-dark/70">{signal.plain_reason}</p>
      {signal.advisory_id !== null ? (
        <p className="font-mono text-[11px] text-brand-purple">{signal.advisory_id}</p>
      ) : null}
      {signal.false_positive_hint !== null ? (
        <p className="text-xs leading-5 text-brand-dark/60">
          <span className="font-semibold">Might be safe if: </span>
          {signal.false_positive_hint}
        </p>
      ) : null}
    </li>
  );
}

type DecodedLayerCardProps = {
  item: GuardApprovalRequest;
};

export function DecodedLayerCard(props: DecodedLayerCardProps) {
  const encodedSignals = deriveEncodedLayerSignals(props.item);
  if (encodedSignals.length === 0) return null;
  const primary = encodedSignals[0];
  const extraCount = Math.max(0, (() => {
    const m = /Decoded (\d+) encoding layer/i.exec(primary.plain_reason ?? "");
    return m != null ? parseInt(m[1], 10) - 1 : encodedSignals.length - 1;
  })());
  return (
    <div
      className="rounded-xl border border-brand-purple/20 bg-brand-purple/[0.04] p-4"
      aria-label="Decoded-layer evidence"
    >
      <SectionLabel>Encoded payload detected</SectionLabel>
      <p className="mt-2 text-sm leading-relaxed text-brand-dark/80">{primary.plain_reason}</p>
      {primary.technical_detail !== null ? (
        <p className="mt-1 font-mono text-[11px] text-muted-foreground break-all">
          {primary.technical_detail}
        </p>
      ) : null}
      {primary.evidence_ref !== null ? (
        <p className="mt-2 font-mono text-[11px] text-brand-purple/70 break-all">{primary.evidence_ref}</p>
      ) : null}
      {extraCount > 0 ? (
        <p className="mt-1 text-xs text-muted-foreground">
          {`and ${extraCount} more encoded ${extraCount === 1 ? "layer" : "layers"}`}
        </p>
      ) : null}
    </div>
  );
}
