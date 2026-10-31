import { ContextAssistanceApiError } from "./api";
export type CigarInterpreter = {
  interpreter_id: string; python_version: [number, number, number]; platform: string;
  implementation: string; abi: string; managed: boolean; build_id: string | null;
};
const object = (v: unknown): v is Record<string, unknown> => v !== null && typeof v === "object" && !Array.isArray(v);
const id = (v: unknown): v is string => typeof v === "string" && /^[a-z0-9_:-]{1,128}$/i.test(v);
function invalid(): never { throw new ContextAssistanceApiError("versions_interpreters_invalid", "Guard returned incompatible Python registration data. Refresh updates."); }
/** Registration metadata only; opening the panel never probes an interpreter. */
export function parseCigarInterpreters(value: unknown): CigarInterpreter[] {
  if (!object(value) || !Array.isArray(value.interpreters) || value.interpreters.length > 16) invalid();
  const values = value.interpreters.map((v): CigarInterpreter => {
    if (!object(v) || !id(v.interpreter_id) || !Array.isArray(v.python_version) || v.python_version.length !== 3
      || !v.python_version.every((n) => Number.isSafeInteger(n) && n >= 0 && n <= 65535)
      || !id(v.platform) || !id(v.implementation) || !id(v.abi) || typeof v.managed !== "boolean"
      || !(v.build_id === null || id(v.build_id)) || v.managed !== (v.build_id !== null)) invalid();
    return { interpreter_id: v.interpreter_id, python_version: [...v.python_version] as [number, number, number],
      platform: v.platform, implementation: v.implementation, abi: v.abi, managed: v.managed, build_id: v.build_id };
  });
  if (new Set(values.map((v) => v.interpreter_id)).size !== values.length) invalid();
  return values;
}
