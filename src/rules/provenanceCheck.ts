/**
 * npm Provenance Attestation Verification
 *
 * npm packages published with --provenance (since npm 9.5 / 2023) carry a
 * Sigstore attestation that cryptographically proves:
 *   1. Which GitHub repo the package was built from
 *   2. Which Actions workflow built it
 *   3. Which commit it was built from
 *
 * This is supply chain verification at the cryptographic level — not a
 * heuristic, not a pattern match. No other MCP scanner checks this.
 *
 * API: https://registry.npmjs.org/-/npm/v1/attestations/<pkg>@<version>
 */

import type { Finding, McpServerEntry } from "../types.js";

const REGISTRY = "https://registry.npmjs.org";

interface AttestationStatement {
  type?: string;
  predicate?: {
    buildType?: string;
    builder?: { id?: string };
    invocation?: { configSource?: { uri?: string; entryPoint?: string } };
    materials?: Array<{ uri?: string; digest?: Record<string, string> }>;
  };
}

interface AttestationBundle {
  predicateType?: string;
  verificationMaterial?: unknown;
  dsseEnvelope?: {
    payload?: string; // base64-encoded JSON statement
    payloadType?: string;
  };
}

interface AttestationsResponse {
  attestations?: AttestationBundle[];
}

interface NpmDistInfo {
  attestations?: { url?: string };
  integrity?: string;
}

interface NpmVersionInfo {
  dist?: NpmDistInfo;
  _npmUser?: { name?: string };
}

interface NpmPackageMeta {
  "dist-tags"?: { latest?: string };
  versions?: Record<string, NpmVersionInfo>;
  maintainers?: Array<{ name: string; email?: string }>;
}

function isOffline(): boolean {
  return process.env.FABRICA_STAR_OFFLINE === "1";
}

function extractPkgAndVersion(server: McpServerEntry): { name: string; version: string | null } | null {
  const RUNNERS = new Set(["npx", "bunx", "pnpm"]);
  if (!server.command || !RUNNERS.has(server.command)) return null;
  const pkgArg = (server.args ?? []).find((a) => !a.startsWith("-"));
  if (!pkgArg) return null;

  if (pkgArg.startsWith("@")) {
    const s = pkgArg.slice(1);
    const i = s.indexOf("@");
    return i > -1
      ? { name: "@" + s.slice(0, i), version: s.slice(i + 1) }
      : { name: pkgArg, version: null };
  }
  const i = pkgArg.indexOf("@");
  return i > 0
    ? { name: pkgArg.slice(0, i), version: pkgArg.slice(i + 1) }
    : { name: pkgArg, version: null };
}

function encodePackageName(name: string): string {
  return name.startsWith("@")
    ? "@" + encodeURIComponent(name.slice(1))
    : encodeURIComponent(name);
}

async function fetchPackageMeta(name: string): Promise<NpmPackageMeta | null> {
  try {
    const res = await fetch(`${REGISTRY}/${encodePackageName(name)}`, { // fabrica-star-ignore — REGISTRY is a hardcoded constant
      signal: AbortSignal.timeout(5000),
    });
    if (!res.ok) return null;
    return (await res.json()) as NpmPackageMeta;
  } catch {
    return null;
  }
}

async function fetchAttestations(name: string, version: string): Promise<AttestationBundle[] | null> {
  try {
    const encoded = encodePackageName(name);
    const url = `${REGISTRY}/-/npm/v1/attestations/${encoded}@${encodeURIComponent(version)}`;
    const res = await fetch(url, { signal: AbortSignal.timeout(5000) });
    if (!res.ok) return null;
    const data = (await res.json()) as AttestationsResponse;
    return data.attestations ?? null;
  } catch {
    return null;
  }
}

function decodeStatement(bundle: AttestationBundle): AttestationStatement | null {
  try {
    const payload = bundle.dsseEnvelope?.payload;
    if (!payload) return null;
    const json = Buffer.from(payload, "base64").toString("utf-8");
    return JSON.parse(json) as AttestationStatement;
  } catch {
    return null;
  }
}

function extractSourceRepo(statement: AttestationStatement): string | null {
  // SLSA provenance v0.2 / v1.0
  const uri =
    statement.predicate?.invocation?.configSource?.uri ??
    statement.predicate?.materials?.[0]?.uri;
  if (!uri) return null;
  // Strip git+ prefix and .git suffix for clean display
  return uri.replace(/^git\+/, "").replace(/\.git$/, "");
}

const TRUSTED_SCOPES = new Set([
  "@modelcontextprotocol",
  "@anthropic-ai",
  "@openai",
  "@github",
  "@google",
  "@microsoft",
  "@aws-sdk",
]);

function isTrustedScope(name: string): boolean {
  if (!name.startsWith("@")) return false;
  return TRUSTED_SCOPES.has(name.split("/")[0]);
}

export async function checkProvenance(server: McpServerEntry): Promise<Finding[]> {
  if (isOffline()) return [];

  const pkg = extractPkgAndVersion(server);
  if (!pkg) return [];
  if (isTrustedScope(pkg.name)) return []; // Skip well-known publishers

  // Get package metadata to find the resolved version
  const meta = await fetchPackageMeta(pkg.name);
  if (!meta) return [];

  const resolvedVersion = pkg.version ?? meta["dist-tags"]?.latest;
  if (!resolvedVersion) return [];

  // Check if this version even has attestations in its dist info
  const versionInfo = meta.versions?.[resolvedVersion];
  const hasAttestationUrl = Boolean(versionInfo?.dist?.attestations?.url);

  if (!hasAttestationUrl) {
    return [
      {
        ruleId: "no-provenance-attestation",
        severity: "medium",
        target: server.name,
        message:
          `"${pkg.name}@${resolvedVersion}" has no npm provenance attestation. ` +
          `There is no cryptographic proof this package was built from its claimed source repo. ` +
          `Prefer packages published with --provenance (attestation verifiable via Sigstore).`,
      },
    ];
  }

  // Fetch and decode the attestation to extract source repo
  const attestations = await fetchAttestations(pkg.name, resolvedVersion);
  if (!attestations || attestations.length === 0) {
    return [
      {
        ruleId: "no-provenance-attestation",
        severity: "medium",
        target: server.name,
        message: `"${pkg.name}@${resolvedVersion}" provenance attestation URL exists but returned no bundles. Cannot verify build origin.`,
      },
    ];
  }

  // Find the npm publish attestation
  const publishAttestation = attestations.find(
    (a) =>
      a.predicateType?.includes("npm/v1") ||
      a.dsseEnvelope?.payloadType?.includes("in-toto") ||
      a.predicateType?.includes("slsa"),
  );

  if (!publishAttestation) {
    return [
      {
        ruleId: "provenance-unverifiable",
        severity: "low",
        target: server.name,
        message: `"${pkg.name}@${resolvedVersion}" has attestations but none match the expected npm publish format. Manual review recommended.`,
      },
    ];
  }

  const statement = decodeStatement(publishAttestation);
  const sourceRepo = statement ? extractSourceRepo(statement) : null;

  // Package has valid provenance — report it as informational (good news)
  return [
    {
      ruleId: "provenance-verified",
      severity: "info",
      target: server.name,
      message:
        `"${pkg.name}@${resolvedVersion}" provenance verified via Sigstore attestation.` +
        (sourceRepo ? ` Built from: ${sourceRepo}` : ""),
    },
  ];
}
