import type { McpClassification } from "../local-cli-api";

const words = (code: string) => code.replaceAll("-", " ");
const explanations: Record<string, string> = {
  "reviewed-provider-mapping:v1": "Reviewed provider contract",
  "schema:content-fields": "Schema accepts content",
  "schema:credential-fields": "Schema accepts credentials",
  "schema:destination-fields": "Schema accepts a recipient or endpoint",
  "schema:execution-fields": "Schema accepts executable content",
  "provider-annotations:unverified": "Provider behavior claims, not verified by Guard",
};

export function McpClassificationEvidence({ value }: { value?: McpClassification }) {
  if (!value) return null;
  return (
    <details className="mt-2 text-xs leading-5 text-brand-dark/75">
      <summary className="min-h-11 cursor-pointer py-3 font-semibold">
        {value.effect === "unknown" ? "Effect not resolved" : `Suggested effect: ${words(value.effect)}`} · View evidence
      </summary>
      <dl className="grid gap-x-4 gap-y-2 sm:grid-cols-2">
        {[["Effect", value.effect], ["Data", value.data], ["Destination", value.destination],
          ["Reversibility", value.reversibility]].map(([label, content]) => (
          <div key={label}><dt className="font-semibold">{label}</dt><dd>{words(content)}</dd></div>
        ))}
      </dl>
      <p className="mt-3">Evidence quality: {value.confidence === "reviewed-mapping" ? "reviewed contract" : "limited"}.
        These suggestions do not verify behavior, account, or permission.</p>
      {value.evidence.length ? <ul className="mt-2 list-disc pl-5">{value.evidence.map((code) => (
        <li key={code}>{explanations[code] ?? "Unrecognized evidence"}</li>
      ))}</ul> : null}
      {value.warnings.length ? <p className="mt-2 font-semibold">{value.warnings.map(words).join(" · ")}</p> : null}
    </details>
  );
}
