import assert from 'node:assert/strict';
import { buildRulesExceptionsView } from './rules-exceptions-model';

const view = buildRulesExceptionsView([
  {
    id: 'remembered-1',
    title: 'Permit signed Git pushes',
    authority: 'Remembered on this device',
    extensionId: 'command.git',
  },
]);
assert.equal(view.title, 'Rules & exceptions');
assert.equal(view.includesExtensionEditor, false);
assert.deepEqual(view.governingExtensionLinks, [
  { label: 'Open command.git', href: '/extensions/command.git' },
]);
assert.match(view.description, /Extension permissions stay/);
