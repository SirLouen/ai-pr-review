#!/usr/bin/env node

/**
 * NDJSON bridge over the vendored security-audit validators.
 *
 * The parent validates one record at a time, dozens to hundreds of times per run.
 * Spawning node per record would dominate the run's wall clock, so this process is
 * started once: it reads one JSON request per line on stdin and writes one JSON
 * response per line on stdout, in order.
 *
 * It deliberately adds no checks of its own. Every answer is a vendored function's
 * return value, so vendor/security-audit stays the single schema authority and this
 * file never has to be kept in sync with it.
 *
 * Usage: node sa-helper.cjs [vendor-dir]
 *
 * Request:  {"id": 1, "op": "validate_findings", "records": [...]}
 * Response: {"id": 1, "ok": true, "errors": [...]}  |  {"id": 1, "ok": false, "error": "..."}
 */

"use strict";

const fs = require("node:fs");
const path = require("node:path");
const readline = require("node:readline");

const vendorDir = path.resolve(
  process.argv[2] || path.join(__dirname, "..", "vendor", "security-audit"));
const findings = require(path.join(vendorDir, "validate-findings.cjs"));
const ledger = require(path.join(vendorDir, "validate-coverage-ledger.cjs"));

// The schema is read from the vendored directory, which is also where
// validate-findings.cjs reads it (from its own __dirname) when the CLI runs at the
// final gate. Loading it from anywhere else would let the per-record gate and the
// final gate enforce two different contracts.
const schemaPath = path.join(vendorDir, "report-schema.json");
const schema = JSON.parse(fs.readFileSync(schemaPath, "utf8"));
const schemaErrors = findings.collectSchemaErrors(schema);
if (schemaErrors.length > 0) {
  process.stderr.write(`sa-helper: unusable report schema: ${schemaErrors.join("; ")}\n`);
  process.exit(2);
}

function requireArray(value, name) {
  if (!Array.isArray(value)) throw new TypeError(`${name} must be an array`);
  return value;
}

const OPS = {
  ping() {
    return {
      node: process.versions.node,
      vendor_dir: vendorDir,
      schema_path: schemaPath,
      findings_limits: findings.LIMITS,
      ledger_limits: ledger.LIMITS,
    };
  },

  // A findings document, which for the per-record gate is a one-element array.
  validate_findings(req) {
    return { errors: Array.from(findings.validateDocument(req.records, schema)) };
  },

  validate_ledger(req) {
    return { errors: Array.from(ledger.validateDocument(req.units)) };
  },

  // The only legal source of a coverage_id: the skill forbids a model choosing one.
  coverage_id(req) {
    return { coverage_id: ledger.canonicalCoverageId(req.canonical_refs) };
  },

  /**
   * Screen repository paths against both vendored path predicates.
   *
   * A path that either rejects can never appear in a finding or in a coverage unit,
   * so any finding about it is structurally unrepresentable. The parent has to know
   * that before it hunts, not after a record is discarded.
   */
  screen_paths(req) {
    const paths = requireArray(req.paths, "paths");
    return {
      safe_source: paths.map((value) => findings.isSafeRelativeSourcePath(value) === true),
      safe_ledger: paths.map((value) => ledger.isSafeRelativePath(value) === true),
    };
  },
};

function respond(id, body) {
  process.stdout.write(`${JSON.stringify(Object.assign({ id }, body))}\n`);
}

function handle(line) {
  let req;
  try {
    req = JSON.parse(line);
  } catch {
    respond(null, { ok: false, error: "request is not valid JSON" });
    return;
  }
  const id = req && typeof req.id === "number" ? req.id : null;
  const op = req && typeof req.op === "string" ? OPS[req.op] : undefined;
  if (typeof op !== "function") {
    respond(id, { ok: false, error: `unknown op ${JSON.stringify(req && req.op)}` });
    return;
  }
  try {
    respond(id, Object.assign({ ok: true }, op(req)));
  } catch (error) {
    // A malformed record must fail this one request, never the bridge: the parent
    // reuses the process for every later record in the run.
    respond(id, { ok: false, error: String((error && error.message) || error) });
  }
}

const rl = readline.createInterface({ input: process.stdin, crlfDelay: Infinity });
rl.on("line", (line) => {
  if (line.trim() !== "") handle(line);
});
rl.on("close", () => process.exit(0));
