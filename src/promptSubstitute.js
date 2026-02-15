/**
 * Substitute {{VariableName}} placeholders in a prompt with values from a map.
 * Used for default dynamic variables (agent-level defaults) merged with per-call variables (e.g. outbound job metadata).
 * @param {string} prompt - Template string possibly containing {{VarName}} placeholders
 * @param {Record<string, string>} variables - Map of variable name -> value (e.g. { "Forename": "Rufi", "Job Titles": "Sales Manager" })
 * @returns {string} Prompt with placeholders replaced; missing vars are replaced with empty string
 */
function substituteDynamicVariables(prompt, variables) {
  if (!prompt || typeof prompt !== "string") return prompt || "";
  const map = variables && typeof variables === "object" ? variables : {};
  return prompt.replace(/\{\{([^}]+)\}\}/g, (_, key) => {
    const k = String(key).trim();
    if (k.length === 0) return "";
    if (Object.prototype.hasOwnProperty.call(map, k)) return String(map[k] ?? "");
    return "";
  });
}

module.exports = { substituteDynamicVariables };
