// jest-dom adds custom jest matchers for asserting on DOM nodes.
// allows you to do things like:
// expect(element).toHaveTextContent(/react/i)
// learn more: https://github.com/testing-library/jest-dom
import '@testing-library/jest-dom';
import { TextEncoder, TextDecoder } from 'util';

/**
 * jsdom ships without TextEncoder/TextDecoder, which the browser has had for
 * years. Anything that decodes bytes trips over it on import — here it is
 * jspdf, by way of fast-png, which three test files pull in and which took
 * those files down before a single test in them ran.
 *
 * Node's own implementations are the same thing, so they are simply handed
 * over. Assigned rather than declared, so a future jsdom that provides them
 * wins instead of being replaced.
 */
if (typeof global.TextEncoder === 'undefined') {
  global.TextEncoder = TextEncoder;
}
if (typeof global.TextDecoder === 'undefined') {
  global.TextDecoder = TextDecoder;
}
