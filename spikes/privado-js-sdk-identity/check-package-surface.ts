import { readFileSync } from "node:fs";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
const packageJsonPath = require.resolve("@0xpolygonid/js-sdk/package.json");
const packageJson = JSON.parse(readFileSync(packageJsonPath, "utf8")) as {
  version: string;
  type?: string;
  exports?: unknown;
};

console.log(
  JSON.stringify(
    {
      version: packageJson.version,
      type: packageJson.type,
      exports: packageJson.exports
    },
    null,
    2
  )
);
