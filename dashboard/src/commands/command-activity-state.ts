export type CommandActivityLoadState<T> =
  | { kind: "idle" }
  | { kind: "loading"; previous: T | null }
  | { kind: "ready"; data: T }
  | { kind: "empty"; data: T }
  | { kind: "error"; message: string; previous: T | null };

export function previousCommandActivityData<T>(state: CommandActivityLoadState<T>): T | null {
  if (state.kind === "ready" || state.kind === "empty") return state.data;
  if (state.kind === "loading" || state.kind === "error") return state.previous;
  return null;
}

export function beginCommandActivityLoad<T>(state: CommandActivityLoadState<T>): CommandActivityLoadState<T> {
  return { kind: "loading", previous: previousCommandActivityData(state) };
}

export function completeCommandActivityLoad<T>(data: T, empty: boolean): CommandActivityLoadState<T> {
  return empty ? { kind: "empty", data } : { kind: "ready", data };
}

export function failCommandActivityLoad<T>(
  state: CommandActivityLoadState<T>,
  error: unknown,
): CommandActivityLoadState<T> {
  let message = "Command activity is temporarily unavailable.";
  if (error instanceof Error && error.message.trim()) {
    message = error.message;
  }
  return { kind: "error", message, previous: previousCommandActivityData(state) };
}

export async function loadCommandActivity<T>(
  state: CommandActivityLoadState<T>,
  loader: () => Promise<T>,
  isEmpty: (data: T) => boolean,
): Promise<CommandActivityLoadState<T>> {
  const loading = beginCommandActivityLoad(state);
  try {
    const data = await loader();
    return completeCommandActivityLoad(data, isEmpty(data));
  } catch (error) {
    return failCommandActivityLoad(loading, error);
  }
}
