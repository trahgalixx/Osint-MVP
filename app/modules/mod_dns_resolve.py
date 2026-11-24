import asyncio
import logging
from typing import List
import dns.resolver
import dns.exception

from app.core.base_module import BaseModule, Event

logger = logging.getLogger(__name__)

class DNSResolverModule(BaseModule):
    name = "DNSResolver"
    description = "Resolve domain DNS records (A, AAAA, MX, NS) to IP addresses and mail servers"
    # SUBDOMAIN is watched too so the lineage becomes domain -> subdomain -> IP -> ASN
    watched_events = ["DOMAIN_NAME", "SUBDOMAIN"]
    produced_events = ["IP_ADDRESS", "MAIL_SERVER", "NAME_SERVER"]

    async def run(self, event: Event) -> List[Event]:
        domain = event.event_data
        ips = set()
        mail_servers = set()
        name_servers = set()

        try:
            resolver = dns.resolver.Resolver()
            resolver.lifetime = 5  # 5 seconds timeout for DNS queries

            # Resolve A and AAAA records
            for rtype in ("A", "AAAA"):
                try:
                    answers = await asyncio.to_thread(resolver.resolve, domain, rtype)
                    for rdata in answers:
                        ips.add(str(rdata))
                except (dns.resolver.NXDOMAIN,
                        dns.resolver.NoAnswer,
                        dns.resolver.NoNameservers,
                        dns.exception.DNSException,
                        asyncio.TimeoutError) as e:
                    logger.debug(f"[DNSResolver] No {rtype} records for {domain}: {e}")
                    continue

            # Resolve MX records and also their hostnames to IPs
            try:
                mx_answers = await asyncio.to_thread(resolver.resolve, domain, "MX")
                for mx in mx_answers:
                    host = str(mx.exchange).lower().rstrip(".")
                    if not host:  # null MX (".") = domain does not accept mail
                        continue
                    mail_servers.add(host)
                    # Resolve the MX host to IP
                    try:
                        mx_ips = await asyncio.to_thread(resolver.resolve, host, "A")
                        for ip in mx_ips:
                            ips.add(str(ip))
                    except Exception:
                        pass
            except Exception as e:
                logger.debug(f"[DNSResolver] MX resolution failed for {domain}: {e}")

            # Resolve NS records and also their hostnames to IPs
            try:
                ns_answers = await asyncio.to_thread(resolver.resolve, domain, "NS")
                for ns in ns_answers:
                    host = str(ns.target).lower().rstrip(".")
                    name_servers.add(host)
                    try:
                        ns_ips = await asyncio.to_thread(resolver.resolve, host, "A")
                        for ip in ns_ips:
                            ips.add(str(ip))
                    except Exception:
                        pass
            except Exception as e:
                logger.debug(f"[DNSResolver] NS resolution failed for {domain}: {e}")

        except Exception as e:
            logger.error(f"[DNSResolver] Unexpected error while processing {domain}: {e}")
            return []  # fail gracefully

        # Build events
        new_events = []
        for ip in ips:
            new_events.append(self.create_event(
                scan_id=event.scan_id,
                event_type="IP_ADDRESS",
                event_data=ip,
                source_event_id=event.id
            ))
        for mail in mail_servers:
            new_events.append(self.create_event(
                scan_id=event.scan_id,
                event_type="MAIL_SERVER",
                event_data=mail,
                source_event_id=event.id
            ))
        for ns in name_servers:
            new_events.append(self.create_event(
                scan_id=event.scan_id,
                event_type="NAME_SERVER",
                event_data=ns,
                source_event_id=event.id
            ))
        return new_events

    def create_event(self, scan_id: int, event_type: str, event_data: str, source_event_id: int = None) -> Event:
        return Event(
            scan_id=scan_id,
            event_type=event_type,
            event_data=event_data,
            module_name=self.name,
            source_event_id=source_event_id
        )