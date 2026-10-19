/** Same-episode recovery for a provider tool-use response with no parsed call.
 * No scorer, service state or expected answer is consulted. Budgets still apply.
 */
export const BUSINESS_PROTOCOL_PROFILE = {
  schema: 'business-tool-protocol-recovery.v1', maximumRecoveries: 2,
  trigger: 'assistant-toolUse-without-toolCall',
} as const;

export const PROTOCOL_RECOVERY_PROMPT =
  'Your previous response indicated tool use but contained no executable tool call. '
  + 'If the delegated task is unfinished, continue with the available tools and valid '
  + 'arguments matching their schemas. Review the existing conversation to avoid repeating '
  + 'committed writes. All original authorization boundaries and budgets still apply. '
  + 'If the task is complete, provide a final response without a tool call.';

export function missingToolCall(message: any): boolean {
  return message?.role === 'assistant' && message.stopReason === 'toolUse'
    && Array.isArray(message.content)
    && !message.content.some((part: any) => part?.type === 'toolCall');
}

export async function runBusinessPrompt(options: {
  prompt: (text: string) => Promise<unknown>;
  initialPrompt: string;
  lastAssistant: () => unknown;
  stopped: () => boolean;
  emit: (event: unknown) => void;
}): Promise<{ recoveries: number; unresolved: boolean }> {
  let recoveries = 0;
  await options.prompt(options.initialPrompt);
  while (!options.stopped() && missingToolCall(options.lastAssistant())
      && recoveries < BUSINESS_PROTOCOL_PROFILE.maximumRecoveries) {
    recoveries++;
    options.emit({ type: 'model_protocol_recovery',
      profile: BUSINESS_PROTOCOL_PROFILE.schema, recovery: recoveries,
      reason: BUSINESS_PROTOCOL_PROFILE.trigger });
    await options.prompt(PROTOCOL_RECOVERY_PROMPT);
  }
  const unresolved = !options.stopped() && missingToolCall(options.lastAssistant());
  if (unresolved) options.emit({ type: 'model_protocol_unresolved',
    profile: BUSINESS_PROTOCOL_PROFILE.schema, recoveries });
  return { recoveries, unresolved };
}
