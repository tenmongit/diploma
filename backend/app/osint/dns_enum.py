"""DNS enumeration module using dnspython."""

import logging
from typing import Any

import dns.resolver
import dns.asyncresolver

from app.osint.base import BaseCollector

logger = logging.getLogger(__name__)


class DnsEnumerator(BaseCollector):
    """Enumerate DNS records for the target domain and subdomains."""

    name = "dns"

    RECORD_TYPES = ["A", "AAAA", "MX", "TXT", "NS", "CNAME", "SOA"]

    async def collect(self, target: str, **kwargs) -> list[dict[str, Any]]:
        """
        Enumerate DNS records for a domain.

        Args:
            target: Domain name to enumerate.
            kwargs: Optional 'subdomains' list to also enumerate.
        """
        subdomains = kwargs.get("subdomains", [])
        domains_to_check = [target] + list(subdomains)

        results = []
        resolver = dns.asyncresolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 10

        for domain in domains_to_check:
            records = {}
            ips = []

            for rtype in self.RECORD_TYPES:
                try:
                    answers = await resolver.resolve(domain, rtype)
                    record_list = []
                    for rdata in answers:
                        value = rdata.to_text()
                        record_list.append(value)
                        if rtype in ("A", "AAAA"):
                            ips.append(value)
                    if record_list:
                        records[rtype] = record_list
                except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                    pass
                except dns.resolver.NoNameservers:
                    logger.warning(f"No nameservers for {domain}/{rtype}")
                except Exception as e:
                    logger.debug(f"DNS query failed for {domain}/{rtype}: {e}")

            if records:
                for ip in ips if ips else [""]:
                    results.append(self._normalize_result(
                        ip=ip,
                        hostnames=[domain],
                        raw={"dns_records": records, "domain": domain},
                    ))
                if not ips:
                    results.append(self._normalize_result(
                        ip="",
                        hostnames=[domain],
                        raw={"dns_records": records, "domain": domain},
                    ))

        logger.info(f"DNS enumeration found {len(results)} results for {target}")
        return results
