// Transport liveness is separate from scenario deadlines and model/tool choices.
type Schedule = (callback: () => void, milliseconds: number) => () => void;
const scheduleTimer: Schedule = (callback, milliseconds) => {
  const timer = setTimeout(callback, milliseconds);
  return () => clearTimeout(timer);
};

export function nativeProgress(event: any): boolean {
  // The SDK exposes native SSE data as either JSON text or an already parsed object.
  try { event = typeof event?.data === 'string' ? JSON.parse(event.data) : event?.data ?? event; }
  catch { return false; }
  return typeof event?.delta === 'string' && event.delta.length > 0
    && ['response.output_text.delta', 'response.reasoning_text.delta',
      'response.reasoning_summary_text.delta', 'response.function_call_arguments.delta',
      'text_delta', 'thinking_delta', 'toolcall_delta'].includes(event.type);
}

export function watchInference(
  expire: () => void,
  { idleMs, maximumMs, schedule = scheduleTimer }:
  { idleMs: number; maximumMs: number; schedule?: Schedule },
) {
  let active = true;
  let generation = 0;
  let cancelIdle = () => {};
  let cancelMaximum = () => {};
  const stop = () => {
    if (!active) return;
    active = false;
    generation++;
    cancelIdle(); cancelMaximum();
  };
  const timeout = () => { if (active) { stop(); expire(); } };
  const progress = () => {
    if (!active) return;
    cancelIdle();
    const current = ++generation;
    cancelIdle = schedule(() => { if (current === generation) timeout(); }, idleMs);
  };
  cancelMaximum = schedule(timeout, maximumMs);
  progress();
  return { progress, stop };
}
