export function extractJsonObject(text: string): unknown {
  const cleaned = text
    .replace(/```json/gi, "")
    .replace(/```/g, "")
    .trim();

  try {
    return JSON.parse(cleaned);
  } catch {
    const start = cleaned.indexOf("{");
    const end = cleaned.lastIndexOf("}");
    if (start === -1 || end === -1 || end <= start) {
      throw new Error("AI response did not contain a JSON object.");
    }
    return JSON.parse(cleaned.slice(start, end + 1));
  }
}

export function stringifyToolResult(value: unknown): string {
  if (typeof value === "string") return value.slice(0, 12000);
  return JSON.stringify(value, null, 2).slice(0, 12000);
}
