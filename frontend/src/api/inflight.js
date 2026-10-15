/**
 * One request for one question, however many callers ask it.
 *
 * Identical calls fired within the same moment are a fact of React: an effect
 * that runs twice under StrictMode, two components wanting the same list, a
 * filter changed twice before the first answer lands. Each of those sends a
 * second request for an answer that is already on its way.
 *
 * This keeps the in-flight promise for a key and hands the same one back until
 * it settles. Nothing is cached afterwards — a later call is a new question,
 * because the thing being asked about keeps changing. That matters here: the
 * alerts list refreshes on a timer, and a cache would quietly serve it the
 * reading it already had.
 */
const inFlight = new Map();

/**
 * @param {string} key   what makes this request the same as another
 * @param {() => Promise<any>} run
 */
export function once(key, run) {
  const running = inFlight.get(key);
  if (running) return running;

  const promise = run().finally(() => {
    // cleared on settle, success or failure: a failed request must be
    // retryable, not remembered as the answer
    if (inFlight.get(key) === promise) inFlight.delete(key);
  });

  inFlight.set(key, promise);
  return promise;
}

/** A stable key for a URL and its query, whatever order the keys were built in. */
export function requestKey(url, params) {
  const entries = Object.entries(params || {})
    .filter(([, value]) => value !== undefined && value !== null && value !== "")
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([name, value]) => `${name}=${String(value)}`);
  return `${url}?${entries.join("&")}`;
}

/** Only for tests: forget anything still recorded as running. */
export function resetInFlight() {
  inFlight.clear();
}
