import ipaddress, re, sys, urllib.request
from pathlib import Path
import dns.message, dns.query, dns.rdatatype, dns.rcode

SEED="https://raw.githubusercontent.com/arnyigor/DnsHostsGenerator/d6f32178da084ba99f30654fc9dafadaff42ea77/shared/src/commonMain/composeResources/files/seed_data.sql"
FALLBACK="https://raw.githubusercontent.com/Noktomezo/RussiaFancyLists/main/lists/hosts/only-crutch.hosts"
# Enabled strict-TLS presets from BuiltInDnsPresets.kt; disabled/trust-all presets omitted.
RESOLVERS=[("91.108.243.78","dns.bezmezhau.com"),("api.bezshansov.ru","api.bezshansov.ru"),("dns.astracat.ru","dns.astracat.ru"),("eu.geohide.ru","eu.geohide.ru"),("dns.dns-ai.ru","dns.dns-ai.ru"),("dns.geodema.love","dns.geodema.love"),("dns.keyoneday.ru","dns.keyoneday.ru")]
def get(url):
 r=urllib.request.urlopen(urllib.request.Request(url,headers={"User-Agent":"DnsConf"}),timeout=25)
 if r.status!=200: raise RuntimeError(f"HTTP {r.status}: {url}")
 return r.read().decode()
def query(domain,server,sni=None):
 q=dns.message.make_query(domain,dns.rdatatype.A)
 r=dns.query.tls(q,server,port=853,timeout=4,server_hostname=sni,verify=True) if sni else dns.query.udp(q,server,timeout=4)
 if r.rcode()!=dns.rcode.NOERROR:return set()
 return {str(x.address) for rr in r.answer if rr.rdtype==dns.rdatatype.A for x in rr if ipaddress.ip_address(x.address).is_global}
def main():
 sql=get(SEED)
 domains=list(dict.fromkeys(x.lower().rstrip(".") for x in re.findall(r"INSERT OR IGNORE INTO domains \([^)]*\) VALUES \(\s*\d+\s*,\s*'([^']+)'\s*,\s*\d+\s*,\s*[01]\s*\)",sql,re.I)))
 domains=[d for d in domains if re.fullmatch(r"[a-z0-9-]+(?:\.[a-z0-9-]+)+",d)]
 if len(domains)<100: raise RuntimeError(f"Seed parsed only {len(domains)} domains")
 fallback=get(FALLBACK); pairs=set(); failures=0
 for d in domains:
  try: base=query(d,"8.8.8.8")
  except Exception: base=set()
  for server,sni in RESOLVERS:
   try: pairs.update((ip,d) for ip in query(d,server,sni)-base)
   except Exception: failures+=1
 if len(pairs)<10: raise RuntimeError(f"Only {len(pairs)} DoT candidates; refusing unsafe update")
 lines=[f"{ip} {d}" for ip,d in sorted(pairs)]+["# Existing SMART direct fallback"]
 lines += [x.strip() for x in fallback.splitlines() if x.strip()]
 p=Path("generated/dnshostsgenerator.hosts");p.parent.mkdir(exist_ok=True)
 p.write_text("\n".join(lines)+"\n",encoding="utf-8")
 print(f"DnsHostsGenerator: {len(domains)} domains, {len(pairs)} candidate pairs, {failures} DoT query failures")
if __name__=="__main__":
 try: main()
 except Exception as e:
  print(f"::error::DnsHostsGenerator failed: {e}",file=sys.stderr);sys.exit(1)
