import { defineConfig } from "vite";
import { builtinModules } from "module";
import { readFileSync } from "fs";
import { resolve, dirname } from "path";
import { fileURLToPath } from "url";
import { playwright } from "@vitest/browser-playwright";
import dts from "vite-plugin-dts";

const __dirname = dirname(fileURLToPath(import.meta.url));
const r = (p) => resolve(__dirname, p);

const pkg = JSON.parse(readFileSync(resolve("package.json"), "utf-8"));
const peerDeps = Object.keys(pkg.peerDependencies || {});

// Node builds: externalize builtins + all peer deps
const external = [
    ...builtinModules,
    ...builtinModules.map((m) => `node:${m}`),
    ...peerDeps,
];

// Browser IIFE: bundle everything (no externals)

const sharedBuildOptions = {
    emptyOutDir: false,
    minify: false,
    sourcemap: true,
};

export default defineConfig(({ mode, command }) => {
    // ── Build modes ────────────────────────────────────────────────────────────
    if (command === "build") {
        // Node: ESM + CJS
        if (mode === "node") {
            return {
                plugins: [
                    dts({ outDir: "dist/types", tsconfigPath: "./tsconfig.json" }),
                ],
                build: {
                    ...sharedBuildOptions,
                    outDir: "dist",
                    lib: { entry: "./src/index.ts", name: "JWZ" },
                    rolldownOptions: {
                        external,
                        output: [
                            {
                                format: "es",
                                dir: "dist/node/esm",
                                entryFileNames: "index.js",
                            },
                            {
                                format: "cjs",
                                dir: "dist/node/cjs",
                                entryFileNames: "index.cjs",
                            },
                        ],
                    },
                },
            };
        }

        // Browser ESM (externalizes @iden3/*, snarkjs, ffjavascript)
        if (mode === "browser-esm") {
            return {
                build: {
                    ...sharedBuildOptions,
                    outDir: "dist/browser/esm",
                    lib: {
                        entry: "./src/index.ts",
                        formats: ["es"],
                        fileName: () => "index.js",
                    },
                    rolldownOptions: {
                        external,
                    },
                },
            };
        }

        // Browser IIFE (fully bundled, no externals)
        if (mode === "browser-iife") {
            return {
                build: {
                    ...sharedBuildOptions,
                    outDir: "dist/browser/umd",
                    lib: {
                        entry: "./src/index.ts",
                        formats: ["iife"],
                        name: "JWZ",
                        fileName: () => "index.js",
                    },
                    rolldownOptions: {},
                },
            };
        }
    }

    // ── Test mode (vitest) ─────────────────────────────────────────────────────
    return {
        test: {
            projects: [
                // Node – ESM: tests run with native ESM (default Vite/Vitest transform)
                {
                    test: {
                        name: "node-esm",
                        include: ["test/**/*.test.ts"],
                        exclude: ["test/iife.test.ts"],
                        environment: "node",
                        globals: true,
                        testTimeout: 120_000,
                    },
                },

                // Node – CJS: same tests, but dependency resolution prefers CJS
                // exports ("require" condition) and each file runs in its own fork
                // to simulate a fresh CommonJS module registry.
                {
                    test: {
                        name: "node-cjs",
                        include: ["test/**/*.test.ts"],
                        exclude: ["test/iife.test.ts"],
                        environment: "node",
                        globals: true,
                        testTimeout: 120_000,
                        pool: "vmForks",
                        // In Vitest 4, pool options moved to top-level (no poolOptions wrapper)
                        interopDefault: true,
                    },
                    resolve: {
                        conditions: ["require", "node", "default"],
                    },
                },

                // Browser – ESM: runs in a real Chromium via Playwright.
                // Only includes tests that don't rely on Node.js fs APIs.
                {
                    test: {
                        name: "browser-esm",
                        include: ["test/hash.test.ts", "test/verify.test.ts"],
                        browser: {
                            enabled: true,
                            headless: false,
                            provider: playwright(),
                            instances: [{ browser: "chromium" }],
                        },
                        setupFiles: [r("test/iife-setup.ts")],
                        globals: true,
                        testTimeout: 120_000,
                    },
                },

                // Browser – IIFE: loads the pre-built dist/browser/umd/index.js via <script>
                // and tests the window.JWZ global. Requires `npm run build:browser` first.
                {
                    test: {
                        name: "browser-iife",
                        include: ["test/iife.test.ts"],
                        browser: {
                            enabled: true,
                            headless: false,
                            provider: playwright(),
                            instances: [{ browser: "chromium" }],
                        },
                        setupFiles: [r("test/iife-setup.ts")],
                        globals: true,
                        testTimeout: 120_000,
                    },
                },

            ],
        },
    };
});
