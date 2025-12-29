export function toGraphQLObject(obj: Record<string, any>): string {
  return Object.entries(obj)
    .map(([key, value]) => {
      // Number, boolean: raw
      if (typeof value === "number" || typeof value === "boolean") {
        return `${key}: ${value}`;
      }

      // Null
      if (value === null) {
        return `${key}: null`;
      }

      // Strings are quoted and escaped
      if (typeof value === "string") {
        const escaped = JSON.stringify(value); // safe escaping
        return `${key}: ${escaped}`;
      }

      // Nested objects
      if (typeof value === "object") {
        return `${key}: { ${toGraphQLObject(value)} }`;
      }

      throw new Error(`Unsupported value type for key '${key}'`);
    })
    .join("\n");
}