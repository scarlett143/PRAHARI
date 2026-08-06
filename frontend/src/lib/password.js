/**
 * Password strength estimation and generation for the sign-in screen.
 *
 * The estimate here is deliberately conservative and deliberately modest about what it
 * knows. A character-class entropy count is the standard cheap heuristic, and it is
 * wrong in one direction that matters: it scores "Password123!" as strong because it has
 * four character classes, when a cracker with a wordlist breaks it instantly. So the
 * count is an upper bound, and the penalties below pull it back toward reality rather
 * than the other way round.
 *
 * It is a guide for the user, never a gate. The server enforces the real rule (12
 * characters minimum, plus a deny-list); this only helps someone choose better than the
 * minimum.
 */

const CHARSETS = [
  { test: /[a-z]/, size: 26 },
  { test: /[A-Z]/, size: 26 },
  { test: /[0-9]/, size: 10 },
  { test: /[^a-zA-Z0-9]/, size: 33 },
];

/** Substrings common enough that a wordlist attack gets them for free. */
const WEAK_FRAGMENTS = [
  "password", "prahari", "qwerty", "asdf", "admin", "letmein", "welcome",
  "secret", "login", "iloveyou", "monkey", "dragon", "master", "abc123",
];

function hasRun(value) {
  // Three or more identical characters ("aaa"), or a straight alphanumeric run
  // ("abc", "789"). Both collapse the effective search space badly.
  if (/(.)\1{2,}/.test(value)) return true;
  for (let index = 0; index + 2 < value.length; index += 1) {
    const [a, b, c] = [value.charCodeAt(index), value.charCodeAt(index + 1), value.charCodeAt(index + 2)];
    if (b - a === 1 && c - b === 1) return true;
    if (a - b === 1 && b - c === 1) return true;
  }
  return false;
}

/**
 * @returns {{bits: number, score: 0|1|2|3, label: string, tone: string, notes: string[]}}
 */
export function estimatePasswordStrength(password) {
  if (!password) {
    return { bits: 0, score: 0, label: "", tone: "muted", notes: [] };
  }

  const alphabet = CHARSETS.reduce((total, set) => (set.test.test(password) ? total + set.size : total), 0);
  let bits = password.length * Math.log2(Math.max(alphabet, 2));
  const notes = [];

  const lower = password.toLowerCase();
  const fragment = WEAK_FRAGMENTS.find((word) => lower.includes(word));
  if (fragment) {
    // A known word is close to free for an attacker, so the characters spelling it
    // should not be counted as if they were random.
    bits -= fragment.length * Math.log2(Math.max(alphabet, 2)) * 0.85;
    notes.push(`Contains a common word ("${fragment}").`);
  }

  if (hasRun(password)) {
    bits *= 0.75;
    notes.push("Contains a repeated or sequential run.");
  }

  const distinct = new Set(password).size;
  if (distinct <= password.length / 2) {
    bits *= 0.8;
    notes.push("Uses few distinct characters.");
  }

  bits = Math.max(0, Math.round(bits));

  // Thresholds are about offline cracking of a stolen hash, which is the threat that
  // matters here -- the password unwraps key material, so it has to survive far more
  // than the online rate limit would allow.
  let score = 0;
  let label = "Weak";
  let tone = "critical";
  if (bits >= 100) {
    score = 3; label = "Excellent"; tone = "good";
  } else if (bits >= 75) {
    score = 2; label = "Strong"; tone = "good";
  } else if (bits >= 55) {
    score = 1; label = "Fair"; tone = "warning";
  }

  return { bits, score, label, tone, notes };
}

/**
 * A random password, generated in the browser from the platform CSPRNG.
 *
 * The alphabet omits characters that are easy to confuse when read aloud or copied by
 * hand (0/O, 1/l/I). At 20 characters over a 58-character alphabet this is about 117
 * bits -- far past anything a wordlist or offline attack reaches, and short enough that
 * a password manager and a human can both cope with it.
 */
export function generatePassword(length = 20) {
  const alphabet = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  const bytes = new Uint32Array(length);
  crypto.getRandomValues(bytes);
  // Rejection-free modulo bias is negligible here (2^32 vs 57), and the alternative
  // costs more complexity than the fraction of a bit it recovers.
  return Array.from(bytes, (value) => alphabet[value % alphabet.length]).join("");
}
