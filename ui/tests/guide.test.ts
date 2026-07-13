import test from 'node:test';
import assert from 'node:assert/strict';

import {
  GUIDE_DISMISS_SETTINGS,
  GUIDE_STEPS,
  guideAdvancesOnSave,
  guideCanFinish,
  guideCompletionStage,
  guideRetargetsReady,
  guideSettingForStep,
  guideTabForStep,
  guideTaskStage,
  guideTaskCopiedAfterSave,
  guideTaskTarget,
} from '../src/guide';

test('the first-task step names the service just saved, not an older neighbor', () => {
  const connections = [
    { name: 'aardvark-api', type: 'api' },
    { name: 'sandbox-pg', type: 'pg' },
  ];
  // The guided save recorded sandbox-pg as ready; the alphabetically first
  // service must not win.
  assert.equal(guideTaskTarget({ name: 'sandbox-pg' }, connections)?.name, 'sandbox-pg');
  // No recorded target: fall back to the first listed service.
  assert.equal(guideTaskTarget(null, connections)?.name, 'aardvark-api');
  // The recorded target was deleted since: fall back rather than invent.
  assert.equal(guideTaskTarget({ name: 'gone' }, connections)?.name, 'aardvark-api');
  // No services at all: nothing to hand the agent.
  assert.equal(guideTaskTarget({ name: 'sandbox-pg' }, []), null);
});

test('every save through the guided panel retargets the prompt; manual adds only when first', () => {
  // First service ever: retarget regardless of source.
  assert.equal(guideRetargetsReady(false, undefined), true);
  assert.equal(guideRetargetsReady(false, 'manual'), true);
  // Later guided saves retarget; later plain ＋ Add service saves do not.
  assert.equal(guideRetargetsReady(true, 'import'), true);
  assert.equal(guideRetargetsReady(true, 'manual'), false);
  assert.equal(guideRetargetsReady(true, undefined), false);
});

test('the task step directs users by what is missing', () => {
  assert.equal(guideTaskStage(0, 0), 'need-service');
  assert.equal(guideTaskStage(0, 1), 'need-service');
  assert.equal(guideTaskStage(1, 0), 'need-agent');
  assert.equal(guideTaskStage(2, 1), 'ready');
});

test('finishing requires a connected agent and a copied task', () => {
  assert.equal(guideCanFinish(0, false), false);
  assert.equal(guideCanFinish(0, true), false);
  assert.equal(guideCanFinish(1, false), false);
  assert.equal(guideCanFinish(1, true), true);
});

test('the freely navigable Done step never claims completion early', () => {
  assert.equal(guideCompletionStage(0, 0, false), 'need-service');
  assert.equal(guideCompletionStage(1, 0, false), 'need-agent');
  assert.equal(guideCompletionStage(1, 1, false), 'need-task');
  assert.equal(guideCompletionStage(1, 1, true), 'complete');
});

test('retargeting a newly saved service resets copied-task progress', () => {
  assert.equal(guideTaskCopiedAfterSave(false, undefined, true), false);
  assert.equal(guideTaskCopiedAfterSave(true, 'import', true), false);
  assert.equal(guideTaskCopiedAfterSave(true, 'manual', true), true);
});

test('breadcrumbs navigate across the two panes', () => {
  assert.equal(guideTabForStep('connect'), 'agents');
  assert.equal(guideTabForStep('add'), 'connections');
  assert.equal(guideTabForStep('task'), 'connections');
  assert.equal(guideTabForStep('done'), 'connections');
  // Every declared step maps to a pane.
  for (const [step] of GUIDE_STEPS) {
    assert.ok(['agents', 'connections'].includes(guideTabForStep(step)));
  }
});

test('navigating to a hidden panel re-enables exactly its walkthrough setting', () => {
  assert.equal(guideSettingForStep('connect'), 'show_agent_walkthrough');
  assert.equal(guideSettingForStep('add'), 'show_service_walkthrough');
  assert.equal(guideSettingForStep('task'), 'show_service_walkthrough');
  assert.equal(guideSettingForStep('done'), 'show_service_walkthrough');
});

test('dismissing the walkthrough retires the whole workflow, both panes', () => {
  assert.deepEqual(
    [...GUIDE_DISMISS_SETTINGS].sort(),
    ['show_agent_walkthrough', 'show_service_walkthrough'],
  );
});

test('only guided saves advance the walkthrough, and only while it is visible', () => {
  assert.equal(guideAdvancesOnSave(true, 'import'), true);
  assert.equal(guideAdvancesOnSave(true, 'manual'), false);
  assert.equal(guideAdvancesOnSave(true, undefined), false);
  // Hidden walkthrough: a guided-looking save must not silently move state.
  assert.equal(guideAdvancesOnSave(false, 'import'), false);
});
