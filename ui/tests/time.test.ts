import assert from 'node:assert/strict';
import test from 'node:test';

import { clockTime, relTime, timeLeft } from '../src/util';

const NOW = Date.parse('2026-07-25T12:00:00Z');
const at = (secondsFromNow: number): string =>
  new Date(NOW + secondsFromNow * 1000).toISOString();

test('relTime reads backwards and says nothing useful about the future', () => {
  assert.equal(relTime(at(-10), NOW), 'just now');
  assert.equal(relTime(at(-300), NOW), '5m');
  // The clamp is why forward-looking deadlines need their own helper.
  assert.equal(relTime(at(90), NOW), 'just now');
});

test('timeLeft counts down to a deadline', () => {
  assert.equal(timeLeft(at(45), NOW), '45s');
  assert.equal(timeLeft(at(90), NOW), '2m');
  assert.equal(timeLeft(at(15 * 60), NOW), '15m');
  assert.equal(timeLeft(at(2 * 3600), NOW), '2h');
});

test('a deadline already passed does not render as a negative countdown', () => {
  assert.equal(timeLeft(at(0), NOW), 'any moment now');
  assert.equal(timeLeft(at(-30), NOW), 'any moment now');
});

test('malformed timestamps render as nothing rather than "NaN"', () => {
  assert.equal(timeLeft('not a date', NOW), '');
  assert.equal(clockTime('not a date'), '');
});

test('clockTime keeps a near horizon to the time of day', () => {
  const rendered = clockTime(at(15 * 60));
  assert.match(rendered, /\d{1,2}:\d{2}/);
  assert.ok(!rendered.includes('2026'), `expected no date part: ${rendered}`);
});
