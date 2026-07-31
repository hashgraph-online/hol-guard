declare module "bun:test" {
  export function test(name: string, fn: () => void | Promise<void>): void;
  export function test(fn: () => void | Promise<void>): void;
}
