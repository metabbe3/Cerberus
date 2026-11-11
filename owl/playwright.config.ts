import { defineConfig } from "@playwright/test";

// Smoke runs against the real stack: the engine (on a scratch data file, so
// test PUTs don't dirty the repo) and Owl's dev server proxying to it. Port
// 3100 keeps clear of :3000, which is commonly tunneled. The engine command
// self-preps: build the binary and copy prod.json to a scratch data file
// before starting.
export default defineConfig({
  testDir: "./e2e",
  use: { baseURL: "http://localhost:3100" },
  webServer: [
    {
      command:
        "go build -o bin/cerberus ./cmd/cerberus && cp data/prod.json /tmp/cerberus-e2e-data.json && rm -f /tmp/cerberus-e2e-audit.db && CERBERUS_ADMIN_TOKEN=e2e CERBERUS_DATA_FILE=/tmp/cerberus-e2e-data.json CERBERUS_AUDIT_DB=/tmp/cerberus-e2e-audit.db bin/cerberus",
      cwd: "..",
      port: 8089,
      timeout: 30_000,
      reuseExistingServer: false,
      stdout: "pipe",
      stderr: "pipe",
    },
    {
      command: "PORT=3100 npm run dev",
      url: "http://localhost:3100",
      timeout: 60_000,
      reuseExistingServer: false,
      stdout: "pipe",
      stderr: "pipe",
      env: {
        CERBERUS_ADMIN_TOKEN: "e2e",
        CERBERUS_URL: "http://localhost:8089",
      },
    },
  ],
});
