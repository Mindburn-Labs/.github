import { createHash } from "node:crypto";
import { lstat, readFile, writeFile } from "node:fs/promises";
import { basename, resolve } from "node:path";

import { bundleToJSON } from "@sigstore/bundle";
import {
  CIContextProvider,
  DSSEBundleBuilder,
  FulcioSigner,
  TSAWitness,
} from "@sigstore/sign";

const MAX_SUBJECT_BYTES = 2 * 1024 * 1024;
const INTOTO_PAYLOAD_TYPE = "application/vnd.in-toto+json";
const SLSA_PREDICATE_TYPE = "https://slsa.dev/provenance/v1";
const GITHUB_BUILD_TYPE = "https://actions.github.io/buildtypes/workflow/v1";
const REQUEST_TIMEOUT_MS = 10_000;
const REQUEST_RETRIES = 3;

function fail(message) {
  process.stderr.write(`offline-attest: ${message}\n`);
  process.exit(1);
}

function requiredEnvironment(name) {
  const value = process.env[name];
  if (!value) {
    fail(`${name} is required`);
  }
  return value;
}

const arguments_ = process.argv.slice(2);
if (arguments_.length !== 2) {
  fail("usage: node attest.mjs <subject> <bundle-output>");
}

const [subjectArgument, outputArgument] = arguments_;
const subjectPath = resolve(subjectArgument);
const outputPath = resolve(outputArgument);
if (subjectPath === outputPath) {
  fail("subject and bundle output must be different files");
}

let metadata;
try {
  metadata = await lstat(subjectPath);
} catch (error) {
  fail(`cannot inspect subject: ${error.message}`);
}
if (!metadata.isFile() || metadata.isSymbolicLink()) {
  fail("subject must be a regular non-symlink file");
}
if (metadata.size <= 0 || metadata.size > MAX_SUBJECT_BYTES) {
  fail(`subject must contain between 1 and ${MAX_SUBJECT_BYTES} bytes`);
}

const subject = await readFile(subjectPath);
const digest = createHash("sha256").update(subject).digest("hex");
const serverUrl = requiredEnvironment("GITHUB_SERVER_URL");
const repository = requiredEnvironment("GITHUB_REPOSITORY");
const workflowRef = requiredEnvironment("GITHUB_WORKFLOW_REF");
const workflowSeparator = workflowRef.lastIndexOf("@");
const workflowMarker = "/.github/workflows/";
const workflowMarkerIndex = workflowRef.indexOf(workflowMarker);
if (workflowMarkerIndex <= 0 || workflowSeparator <= workflowMarkerIndex + 1) {
  fail("GITHUB_WORKFLOW_REF does not identify a GitHub Actions workflow");
}
const workflowRepository = workflowRef.slice(0, workflowMarkerIndex);
const workflowPath = workflowRef.slice(workflowMarkerIndex + 1, workflowSeparator);
const sourceRef = requiredEnvironment("GITHUB_REF");
const sourceSha = requiredEnvironment("GITHUB_SHA");
const statement = {
  _type: "https://in-toto.io/Statement/v1",
  subject: [{ name: basename(subjectPath), digest: { sha256: digest } }],
  predicateType: SLSA_PREDICATE_TYPE,
  predicate: {
    buildDefinition: {
      buildType: GITHUB_BUILD_TYPE,
      externalParameters: {
        workflow: {
          ref: sourceRef,
          repository: `${serverUrl}/${workflowRepository}`,
          path: workflowPath,
        },
      },
      internalParameters: {
        github: {
          event_name: requiredEnvironment("GITHUB_EVENT_NAME"),
          repository_id: requiredEnvironment("GITHUB_REPOSITORY_ID"),
          repository_owner_id: requiredEnvironment("GITHUB_REPOSITORY_OWNER_ID"),
          runner_environment: requiredEnvironment("RUNNER_ENVIRONMENT"),
        },
      },
      resolvedDependencies: [
        {
          uri: `git+${serverUrl}/${repository}@${sourceRef}`,
          digest: { gitCommit: sourceSha },
        },
      ],
    },
    runDetails: {
      builder: { id: `${serverUrl}/${workflowRef}` },
      metadata: {
        invocationId: `${serverUrl}/${repository}/actions/runs/${requiredEnvironment("GITHUB_RUN_ID")}/attempts/${requiredEnvironment("GITHUB_RUN_ATTEMPT")}`,
      },
    },
  },
};

const host = new URL(serverUrl).hostname === "github.com" ? "githubapp.com" : new URL(serverUrl).hostname;
const fetchOptions = { timeout: REQUEST_TIMEOUT_MS, retry: REQUEST_RETRIES };
const signer = new FulcioSigner({
  identityProvider: new CIContextProvider("sigstore"),
  fulcioBaseURL: `https://fulcio.${host}`,
  ...fetchOptions,
});
const bundle = await new DSSEBundleBuilder({
  signer,
  witnesses: [new TSAWitness({ tsaBaseURL: `https://timestamp.${host}`, ...fetchOptions })],
}).create({
  data: Buffer.from(JSON.stringify(statement)),
  type: INTOTO_PAYLOAD_TYPE,
});

await writeFile(outputPath, `${JSON.stringify(bundleToJSON(bundle))}\n`, {
  encoding: "utf8",
  flag: "wx",
  mode: 0o600,
});
process.stdout.write(`signed ${basename(subjectPath)}@sha256:${digest}\n`);
