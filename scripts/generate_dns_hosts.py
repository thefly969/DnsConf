import concurrent.futures, ipaddress, json, re, socket, sys, urllib.request
from pathlib import Path
import dns.message, dns.query, dns.rdatatype, dns.rcode

SEED="https://raw.githubusercontent.com/arnyigor/DnsHostsGenerator/d6f32178da084ba99f30654fc9dafadaff42ea77/shared/src/commonMain/composeResources/files/seed_data.sql"
FALLBACK="https://raw.githubusercontent.com/Noktomezo/RussiaFancyLists/main/lists/hosts/only-crutch.hosts"
# Enabled strict-TLS presets from BuiltInDnsPresets.kt; disabled/trust-all presets omitted.
RESOLVERS=[("91.108.243.78","dns.bezmezhau.com"),("api.bezshansov.ru","api.bezshansov.ru"),("dns.astracat.ru","dns.astracat.ru"),("eu.geohide.ru","eu.geohide.ru"),("dns.dns-ai.ru","dns.dns-ai.ru"),("dns.geodema.love","dns.geodema.love"),("dns.keyoneday.ru","dns.keyoneday.ru")]
EXCLUDED_RESOLVER_COUNTRIES={"UA"}  # Exclude DNS resolver endpoints registered/geolocated in Ukraine.
GEO_API="https://ipwho.is/"
def get(url):
 r=urllib.request.urlopen(urllib.request.Request(url,headers={"User-Agent":"DnsConf"}),timeout=25)
 if r.status!=200: raise RuntimeError(f"HTTP {r.status}: {url}")
 return r.read().decode()
def resolver_ips(server):
 try:
  return sorted({item[4][0] for item in socket.getaddrinfo(server,853,type=socket.SOCK_STREAM)})
 except OSError as e:
  raise RuntimeError(f"Cannot resolve DNS resolver endpoint {server}: {e}") from e

def resolver_country(ip):
 # Fail closed: if the geolocation service cannot classify an endpoint, do not use it.
 with urllib.request.urlopen(urllib.request.Request(GEO_API+ip,headers={"User-Agent":"DnsConf-resolver-filter"}),timeout=10) as response:
  data=json.loads(response.read().decode("utf-8"))
 if not data.get("success") or not data.get("country_code"):
  raise RuntimeError(f"Cannot determine country for resolver IP {ip}: {data.get('message','unknown response')}")
 return data["country_code"].upper()

def filter_resolvers(resolvers):
 allowed=[]
 for server,sni in resolvers:
  try:
   addresses=resolver_ips(server)
   countries={ip:resolver_country(ip) for ip in addresses}
   excluded={ip:country for ip,country in countries.items() if country in EXCLUDED_RESOLVER_COUNTRIES}
   if excluded:
    print(f"Excluding resolver {server}: Ukrainian endpoint(s) {excluded}")
    continue
   allowed.append((server,sni))
   print(f"Resolver allowed: {server}; endpoint countries={sorted(set(countries.values()))}")
  except Exception as e:
   print(f"Excluding resolver {server}: country verification failed: {e}")
 if not allowed:
  raise RuntimeError("No DNS-over-TLS resolvers remain after country filtering; refusing to generate candidates")
 return allowed

def query(domain,server,sni=None):
 q=dns.message.make_query(domain,dns.rdatatype.A)
 r=dns.query.tls(q,server,port=853,timeout=4,server_hostname=sni,verify=True) if sni else dns.query.udp(q,server,timeout=4)
 if r.rcode()==dns.rcode.NXDOMAIN:return set()
 if r.rcode()!=dns.rcode.NOERROR: raise RuntimeError(f"DNS {r.rcode()} for {domain} via {server}")
 return {str(x.address) for rr in r.answer if rr.rdtype==dns.rdatatype.A for x in rr if ipaddress.ip_address(x.address).is_global}
def main():
 sql=get(SEED)
 rows=re.findall(r"INSERT OR IGNORE INTO domains \([^)]*\) VALUES \(\s*\d+\s*,\s*'([^']+)'\s*,\s*(\d+)\s*,\s*[01]\s*\)",sql,re.I)
 # This project currently targets ChatGPT and Gemini; ignore unrelated app groups.
 domains=list(dict.fromkeys(d.lower().rstrip(".") for d,g in rows if g in {"1","2"}))
 domains=[d for d in domains if re.fullmatch(r"[a-z0-9-]+(?:\.[a-z0-9-]+)+",d)]
 # Avoid broad parent rewrites which affect unlisted subdomains too.
 domains=[d for d in domains if d not in {"openai.com","oaistatic.com","oaiusercontent.com","withgoogle.com"}]
 if len(domains)<30: raise RuntimeError(f"Seed parsed only {len(domains)} ChatGPT/Gemini domains")
 fallback=get(FALLBACK); pairs=set(); failures=0
 # Require agreement from two independent public DNS baselines. A candidate is
 # retained only when neither resolver returns that address for the domain.
 BASELINES=[("8.8.8.8",None),("1.1.1.1",None)]
 def one(task):
  domain,server,sni=task
  try: return domain,query(domain,server,sni),None
  except Exception as e: return domain,set(),str(e)
 active_resolvers=filter_resolvers(RESOLVERS)
 tasks=[(d,s,h) for d in domains for s,h in active_resolvers]
 with concurrent.futures.ThreadPoolExecutor(max_workers=24) as pool:
  results=list(pool.map(one,tasks))
 baseline={}
 for d in domains:
  try:
   baseline[d]=set().union(*(query(d,server,sni) for server,sni in BASELINES))
  except Exception as e:
   baseline[d]=None
   failures+=1
   print(f"Baseline DNS failed for {d}; skipping domain: {e}")
 for d,answers,error in results:
  if error: failures+=1
  if baseline[d] is None: continue
  pairs.update((ip,d) for ip in answers-baseline[d])
 if len(pairs)<10: raise RuntimeError(f"Only {len(pairs)} verified DoT candidates; refusing unsafe update")
 lines=[f"{ip} {d}" for ip,d in sorted(pairs)]+["# Existing SMART direct fallback"]
 lines += [x.strip() for x in fallback.splitlines() if x.strip()]
 p=Path("generated/dnshostsgenerator.hosts");p.parent.mkdir(exist_ok=True)
 p.write_text("\n".join(lines)+"\n",encoding="utf-8")
 print(f"DnsHostsGenerator: {len(domains)} ChatGPT/Gemini domains, {len(pairs)} candidate pairs, {failures} DoT query failures")
if __name__=="__main__":
 try: main()
 except Exception as e:
  print(f"::error::DnsHostsGenerator failed: {e}",file=sys.stderr);sys.exit(1)
