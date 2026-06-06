export function getMitreUrl(tcode: string): string {
  if (tcode.includes(".")) {
    const [base, sub] = tcode.split(".");
    return `https://attack.mitre.org/techniques/${base}/${sub}/`;
  }
  return `https://attack.mitre.org/techniques/${tcode}/`;
}

export function getCveUrl(cveId: string): string {
  return `https://nvd.nist.gov/vuln/detail/${cveId}`;
}