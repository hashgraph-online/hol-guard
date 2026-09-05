import type { ExtensionCatalogItem, McpToolDefaultState } from "../extension-controls-api";

function toolStateLabel(state: McpToolDefaultState): string {
  if (state === "allow") return "Allow";
  if (state === "block") return "Block";
  return "Recommended";
}

export function McpServerDefaults({ extension }: { extension: ExtensionCatalogItem }) {
  if (extension.surface !== "mcp") return null;
  const launch = extension.mcp_launch;
  const tools = extension.mcp_tools ?? [];
  return (
    <article className="rounded-3xl border border-slate-200 bg-white p-5 shadow-sm lg:col-span-2" data-testid="mcp-server-defaults">
      <h2 className="text-lg font-semibold text-brand-dark">MCP server defaults</h2>
      <p className="mt-2 text-sm leading-6 text-brand-dark/75">
        Matching launches use this package name. Defaults apply only after you turn the server on. A custom extension on this device still wins.
      </p>
      <dl className="mt-5 grid gap-4 sm:grid-cols-2">
        <div>
          <dt className="text-xs font-semibold uppercase text-brand-dark/55">Launcher</dt>
          <dd className="mt-1 text-sm text-brand-dark">{launch?.command ?? "Package launcher"}</dd>
        </div>
        <div>
          <dt className="text-xs font-semibold uppercase text-brand-dark/55">Package</dt>
          <dd className="mt-1 break-all font-mono text-sm text-brand-dark">{launch?.package ?? "Unknown package"}</dd>
        </div>
      </dl>
      {tools.length ? (
        <div className="mt-5 overflow-x-auto">
          <table className="min-w-full text-left text-sm">
            <thead className="text-xs uppercase tracking-wide text-brand-dark/55">
              <tr>
                <th className="pb-2 pr-4 font-semibold">Tool</th>
                <th className="pb-2 font-semibold">Default</th>
              </tr>
            </thead>
            <tbody>
              {tools.map((tool) => (
                <tr key={tool.name} className="border-t border-slate-100">
                  <td className="py-2 pr-4 font-mono text-xs text-brand-dark">{tool.name}</td>
                  <td className="py-2 text-sm text-brand-dark">{toolStateLabel(tool.state)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : null}
    </article>
  );
}
