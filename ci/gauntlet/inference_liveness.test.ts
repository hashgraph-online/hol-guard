import { expect, test } from 'bun:test';
import { nativeProgress, watchInference } from './inference_liveness';

test('keepalives and lifecycle events cannot extend silent inference', () => {
  expect(nativeProgress({ type: 'response.in_progress' })).toBe(false);
  expect(nativeProgress({ type: 'keepalive', delta: 'ping' })).toBe(false);
  expect(nativeProgress({ type: 'thinking_delta', delta: '' })).toBe(false);
  for (const type of ['thinking_delta', 'text_delta', 'response.function_call_arguments.delta']) {
    expect(nativeProgress({ type, delta: 'unaltered model bytes' })).toBe(true);
    expect(nativeProgress({ data: { type, delta: 'unaltered model bytes' } })).toBe(true);
    expect(nativeProgress({ data: JSON.stringify({ type, delta: 'unaltered model bytes' }) })).toBe(true);
  }
  expect(nativeProgress({ data: 'not JSON' })).toBe(false);
});

test('progress resets idle wait but not the original total deadline; cleanup is idempotent', () => {
  const timers: { run: () => void; delay: number; cancelled: boolean }[] = [];
  let expirations = 0;
  const deadline = watchInference(() => { expirations++; }, {
    idleMs: 60_000, maximumMs: 240_000,
    schedule: (run, delay) => {
      const timer = { run, delay, cancelled: false };
      timers.push(timer);
      return () => { timer.cancelled = true; };
    },
  });
  expect(timers.map(timer => timer.delay)).toEqual([240_000, 60_000]);
  deadline.progress();
  expect(timers[1].cancelled).toBe(true);
  timers[1].run(); // A queued callback from the previous generation must do nothing.
  expect(expirations).toBe(0);
  timers[0].run();
  expect(expirations).toBe(1);
  expect(timers.every(timer => timer.cancelled)).toBe(true);
  timers[2].run(); deadline.stop(); deadline.progress();
  expect(expirations).toBe(1);
});

test('idle inference expires without manufacturing a completion', () => {
  const callbacks: (() => void)[] = [];
  let failed = false;
  const deadline = watchInference(() => { failed = true; }, {
    idleMs: 60_000, maximumMs: 240_000,
    schedule: run => { callbacks.push(run); return () => {}; },
  });
  callbacks[1]();
  expect(failed).toBe(true);
  deadline.stop();
});
