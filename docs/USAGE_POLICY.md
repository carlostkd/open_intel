# Usage Policy

## 1. What This Tool Is

VoidAccess is a passive OSINT platform for collecting and analyzing publicly accessible information from dark web sources. It searches .onion domains via Tor, extracts content from accessible pages, and uses large language models to generate threat intelligence summaries. It does not exploit systems, does not de-anonymize users, does not store scraped content at scale beyond individual investigations, and does not provide real-time attack capabilities. All collection is passive observation of publicly accessible sources.

## 2. Who This Tool Is For

This tool is for anyone whose job involves understanding threats so you can defend against them. This includes threat intelligence analysts, security operations center (SOC) teams, penetration testers working within authorized scope, law enforcement and government agencies, and academic researchers studying cybercrime and dark web ecosystems.

## 3. Permitted Uses

The following uses are permitted when conducted lawfully and ethically:

- Researching threat actors, malware families, and ransomware groups for defensive purposes
- Identifying indicators of compromise (IOCs) such as hashes, domains, IP addresses, and wallet addresses to feed into detection systems
- Monitoring dark web sources for mentions of your organization, assets, employees, or data
- Academic research into cybercrime ecosystems and threat landscape analysis
- Law enforcement investigations conducted with proper authorization
- Building threat intelligence reports for internal organizational use or client use under authorized engagement

## 4. Prohibited Uses

The following uses are prohibited:

- Using investigation results to target, harass, extort, or dox any individual or organization
- Running investigations on behalf of clients or third parties without documented authorization to do so
- Using the tool to locate or access illegal content. This includes any content the built-in filter blocks, and any attempt to modify the tool to circumvent the content filter
- Feeding investigation results into offensive tooling, attack pipelines, or any activity that enables harm to systems or persons
- Reselling access to the platform or its output without making clear to end users what data is being collected and from where
- Using the tool in any jurisdiction where accessing dark web content is itself illegal without appropriate authorization

## 5. Content Filtering

The platform includes mandatory filters that automatically block queries, URLs, and content related to child sexual abuse material (CSAM), gore, snuff content, and other categories of illegal or harmful material. These filters operate at query intake, URL validation, content scraping, and post-extraction layers.

This filtering cannot be disabled. Any attempt to modify the tool to remove or bypass these filters is a violation of this policy and likely violates applicable law.

## 6. Your Responsibility

Running this tool is your responsibility. You are responsible for ensuring your use complies with laws in your jurisdiction. If you are unsure whether accessing dark web content is legal where you are, you should consult a lawyer before running investigations. You are responsible for obtaining proper authorization before investigating anything related to organizations you do not own or are not authorized to investigate. You are responsible for handling any intelligence you collect in a manner consistent with its sensitivity and any legal requirements that apply to it.

The maintainer is not responsible for how you use the output of this tool.

## 7. No Warranty

This tool is provided as-is with no guarantees about accuracy, completeness, or fitness for any particular purpose. The dark web is inherently unreliable. Sources may be deliberately misleading, defunct, or operated by threat actors. Additionally, threat actors deliberately plant false information, so intelligence from this tool should be validated before acting on it.

## 8. Reporting Misuse

If you see this tool being used in violation of this policy, or if you see forks of this project that violate these terms, report it via GitHub or the contact method documented in SECURITY.md.