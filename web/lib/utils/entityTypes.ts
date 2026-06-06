export const ENTITY_TYPE_CONFIG: Record<string, {
  label: string;
  color: string;
  textColor: string;
}> = {
  "CVE": {
    label: "CVE",
    color: "var(--bg-raised)",
    textColor: "var(--entity-cve)"
  },
  "MITRE_TECHNIQUE": {
    label: "ATT&CK Technique",
    color: "var(--bg-raised)",
    textColor: "var(--warning)"
  },
  "FILE_HASH_MD5": {
    label: "MD5 Hash",
    color: "var(--bg-raised)",
    textColor: "var(--text-secondary)"
  },
  "FILE_HASH_SHA1": {
    label: "SHA1 Hash",
    color: "var(--bg-raised)",
    textColor: "var(--text-secondary)"
  },
  "FILE_HASH_SHA256": {
    label: "SHA256 Hash",
    color: "var(--bg-raised)",
    textColor: "var(--text-secondary)"
  },
  "THREAT_ACTOR": {
    label: "Threat Actor",
    color: "var(--bg-raised)",
    textColor: "var(--entity-threat-actor)"
  },
  "RANSOMWARE_GROUP": {
    label: "Ransomware Group",
    color: "var(--bg-raised)",
    textColor: "var(--entity-threat-actor)"
  },
  "MALWARE_FAMILY": {
    label: "Malware",
    color: "var(--bg-raised)",
    textColor: "var(--entity-malware)"
  },
  "ONION_URL": {
    label: "Onion URL",
    color: "var(--bg-raised)",
    textColor: "var(--entity-onion)"
  },
  "IP_ADDRESS": {
    label: "IP Address",
    color: "var(--bg-raised)",
    textColor: "var(--entity-c2)"
  },
  "DOMAIN": {
    label: "Domain",
    color: "var(--bg-raised)",
    textColor: "var(--text-secondary)"
  },
  "BITCOIN_ADDRESS": {
    label: "Bitcoin Address",
    color: "var(--bg-raised)",
    textColor: "var(--entity-wallet)"
  },
  "MONERO_ADDRESS": {
    label: "Monero Address",
    color: "var(--bg-raised)",
    textColor: "var(--entity-wallet)"
  },
  "ETH_ADDRESS": {
    label: "ETH Address",
    color: "var(--bg-raised)",
    textColor: "var(--entity-wallet)"
  },
  "EMAIL_ADDRESS": {
    label: "Email",
    color: "var(--bg-raised)",
    textColor: "var(--entity-email)"
  },
  "PGP_KEY_BLOCK": {
    label: "PGP Key",
    color: "var(--bg-raised)",
    textColor: "var(--entity-pgp)"
  },
  "ORGANIZATION_NAME": {
    label: "Organization",
    color: "var(--bg-raised)",
    textColor: "var(--text-secondary)"
  },
  "PERSON_NAME": {
    label: "Person",
    color: "var(--bg-raised)",
    textColor: "var(--text-secondary)"
  },
};

export function getEntityTypeConfig(rawType: string) {
  return ENTITY_TYPE_CONFIG[rawType] ?? {
    label: rawType.replace(/_/g, " ").toLowerCase(),
    color: "var(--bg-raised)",
    textColor: "var(--text-secondary)"
  };
}