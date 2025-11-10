// RDAP scanner: Domain registration and DNSSEC information

import { DomainScanner, ExecutedScannerResult, ScannerInterpretation, SeverityLevel } from '../../types/domainScan';

export const rdapScanner: DomainScanner = {
  id: 'rdap',
  label: 'Domain Registration (RDAP)',
  description: 'Retrieves domain registration and DNSSEC information via RDAP',
  timeout: 10000, // 10 seconds - bootstrap lookup + RDAP query
  dataSource: {
    name: 'RDAP',
    url: 'https://about.rdap.org/',
  },
  run: async (domain) => {
    const issues: string[] = [];
    const warnings: string[] = [];

    try {
      // Extract TLD from domain
      const parts = domain.split('.');
      if (parts.length < 2) {
        return {
          data: { error: 'Invalid domain format' },
          summary: 'Invalid domain',
          issues: ['Domain must have at least a name and TLD (e.g., example.com)']
        };
      }

      const tld = parts[parts.length - 1];

      // Step 1: Query IANA RDAP bootstrap service to find the correct RDAP server for this TLD
      const bootstrapUrl = 'https://data.iana.org/rdap/dns.json';
      const bootstrapResponse = await fetch(bootstrapUrl);

      if (!bootstrapResponse.ok) {
        throw new Error(`Failed to fetch RDAP bootstrap data: ${bootstrapResponse.status}`);
      }

      const bootstrapData = await bootstrapResponse.json();

      // Find the RDAP server(s) for this TLD
      let rdapServers: string[] = [];
      if (bootstrapData.services) {
        for (const service of bootstrapData.services) {
          const [tlds, servers] = service;
          if (tlds.includes(tld.toLowerCase())) {
            rdapServers = servers;
            break;
          }
        }
      }

      if (rdapServers.length === 0) {
        return {
          data: {
            error: `No RDAP server found for .${tld} TLD`,
            tld
          },
          summary: 'RDAP not available for this TLD',
          issues: [
            `No RDAP service available for .${tld} domains.`,
            'This TLD may not support RDAP or uses legacy WHOIS only.'
          ]
        };
      }

      // Step 2: Query the RDAP server for domain information
      // Try each server until one succeeds
      let rdapData = null;
      let lastError = null;

      for (const server of rdapServers) {
        try {
          const rdapUrl = `${server}domain/${domain}`;
          const response = await fetch(rdapUrl);

          if (response.ok) {
            rdapData = await response.json();
            break;
          } else if (response.status === 404) {
            lastError = 'Domain not found';
            continue;
          } else {
            lastError = `Server returned ${response.status}`;
            continue;
          }
        } catch (err) {
          lastError = err instanceof Error ? err.message : 'Unknown error';
          continue;
        }
      }

      if (!rdapData) {
        return {
          data: {
            error: lastError || 'Domain not found in RDAP',
            rdapServers
          },
          summary: 'RDAP lookup failed',
          issues: [
            `Could not retrieve RDAP data: ${lastError || 'Domain not found'}`,
            'Domain may not be registered or RDAP server may be unavailable.'
          ]
        };
      }

      // Step 3: Analyze RDAP response
      const data = rdapData;

      // Check domain status
      const statuses = data.status || [];
      const ldhName = data.ldhName || domain;

      // Check for problematic statuses
      const problemStatuses = ['clientHold', 'serverHold', 'redemptionPeriod', 'pendingDelete'];
      const hasProblems = statuses.some((s: string) =>
        problemStatuses.some((ps) => s.toLowerCase().includes(ps.toLowerCase()))
      );

      if (hasProblems) {
        const problemStatusList = statuses.filter((s: string) =>
          problemStatuses.some((ps) => s.toLowerCase().includes(ps.toLowerCase()))
        );
        issues.push(`Domain has problematic status: ${problemStatusList.join(', ')}`);
      }

      // Check expiration
      const events = data.events || [];
      const expirationEvent = events.find((e: { eventAction: string }) =>
        e.eventAction === 'expiration'
      );

      if (expirationEvent) {
        const expirationDate = new Date(expirationEvent.eventDate);
        const now = new Date();
        const daysUntilExpiration = Math.floor(
          (expirationDate.getTime() - now.getTime()) / (1000 * 60 * 60 * 24)
        );

        if (daysUntilExpiration < 0) {
          issues.push(`Domain expired ${Math.abs(daysUntilExpiration)} days ago`);
        } else if (daysUntilExpiration <= 30) {
          issues.push(`Domain expires in ${daysUntilExpiration} days - renew soon!`);
        } else if (daysUntilExpiration <= 60) {
          warnings.push(`Domain expires in ${daysUntilExpiration} days - plan renewal`);
        }
      }

      // Check DNSSEC
      const secureDNS = data.secureDNS;
      if (secureDNS) {
        if (secureDNS.delegationSigned === false) {
          warnings.push('DNSSEC is not enabled - domain is vulnerable to DNS spoofing attacks');
        }
      }

      // Check nameservers
      const nameservers = data.nameservers || [];
      if (nameservers.length === 0) {
        issues.push('No nameservers found - domain cannot resolve');
      } else if (nameservers.length < 2) {
        warnings.push('Only one nameserver configured - add redundant nameservers for reliability');
      }

      // Build summary
      let summary = `Domain: ${ldhName}`;
      if (statuses.length > 0) {
        const activeStatus = statuses.includes('active') ? 'active' : statuses[0];
        summary += `, status: ${activeStatus}`;
      }
      if (expirationEvent) {
        const expirationDate = new Date(expirationEvent.eventDate);
        const daysUntilExpiration = Math.floor(
          (expirationDate.getTime() - new Date().getTime()) / (1000 * 60 * 60 * 24)
        );
        summary += `, expires in ${daysUntilExpiration} days`;
      }

      const allIssues = [...issues, ...warnings];

      return {
        summary,
        issues: allIssues.length > 0 ? allIssues : undefined,
        data: {
          ldhName,
          status: statuses,
          nameservers: nameservers.map((ns: { ldhName: string }) => ns.ldhName),
          dnssecEnabled: secureDNS?.delegationSigned || false,
          expirationDate: expirationEvent?.eventDate,
          registrationDate: events.find((e: { eventAction: string }) =>
            e.eventAction === 'registration'
          )?.eventDate,
          registrar: data.entities?.find((e: { roles: string[] }) =>
            e.roles?.includes('registrar')
          )?.vcardArray?.[1]?.find((v: string[]) => v[0] === 'fn')?.[3],
        },
      };
    } catch (err: unknown) {
      const errorMessage = err instanceof Error ? err.message : 'Unknown error';
      return {
        data: { error: errorMessage },
        summary: 'RDAP lookup failed',
        issues: [`Failed to retrieve RDAP information: ${errorMessage}`]
      };
    }
  }
};

// Interpretation function for RDAP scanner results
export const interpretRdapResult = (
  scanner: ExecutedScannerResult,
  issueCount: number
): ScannerInterpretation => {
  const data = scanner.data as {
    status?: string[];
    dnssecEnabled?: boolean;
    error?: string;
    expirationDate?: string;
    registrationDate?: string;
    nameservers?: string[];
  };

  if (data?.error) {
    return {
      severity: 'info',
      message: 'RDAP lookup incomplete',
      recommendation: data.error.includes('not found')
        ? 'Domain not found in RDAP. This may be normal for some TLDs or private registrations.'
        : 'RDAP lookup failed. This doesn\'t affect domain functionality.'
    };
  }

  // Check for critical issues
  const hasCriticalIssues = scanner.issues?.some((issue) =>
    issue.toLowerCase().includes('expired') ||
    issue.toLowerCase().includes('no nameservers')
  );

  const hasExpirationWarning = scanner.issues?.some((issue) =>
    issue.toLowerCase().includes('expires in') && issue.toLowerCase().includes('days')
  );

  let severity: SeverityLevel;
  let message: string;
  let recommendation: string;

  if (hasCriticalIssues) {
    severity = 'critical';
    message = 'Domain registration has critical issues';
    recommendation = 'Address domain registration issues immediately to prevent service disruption. ' +
      'Check expiration date and nameserver configuration.';
  } else if (hasExpirationWarning) {
    severity = 'warning';
    message = 'Domain registration needs attention';
    recommendation = 'Plan to renew your domain before expiration. Set up auto-renewal if available.';
  } else if (issueCount > 0) {
    severity = 'warning';
    message = 'Domain registration has recommendations';
    recommendation = 'Review the recommendations below to improve domain security and reliability.';
  } else {
    severity = 'success';
    message = 'Domain registration is healthy';
    recommendation = data?.dnssecEnabled
      ? 'Domain registration and DNSSEC configuration look good.'
      : 'Consider enabling DNSSEC for additional security against DNS spoofing.';
  }

  return {
    severity,
    message,
    recommendation
  };
};
