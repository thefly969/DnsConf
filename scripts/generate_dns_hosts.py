import concurrent.futures, ipaddress, re, sys, urllib.request
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
 rows=re.findall(r"INSERT OR IGNORE INTO domains \([^)]*\) VALUES \(\s*\d+\s*,\s*'([^']+)'\s*,\s*(\d+)\s*,\s*[01]\s*\)",sql,re.I)
 # This project currently targets ChatGPT and Gemini; ignore unrelated app groups.
 domains=list(dict.fromkeys(d.lower().rstrip(".") for d,g in rows if g in {"1","2"}))
 domains=[d for d in domains if re.fullmatch(r"[a-z0-9-]+(?:\.[a-z0-9-]+)+",d)]
 # Avoid broad parent rewrites which affect unlisted subdomains too.
 domains=[d for d in domains if d not in {"openai.com","oaistatic.com","oaiusercontent.com","withgoogle.com"}]
 if len(domains)<30: raise RuntimeError(f"Seed parsed only {len(domains)} ChatGPT/Gemini domains")
 fallback=get(FALLBACK); pairs=set(); failures=0
 def one(task):
  domain,server,sni=task
  try: return domain,query(domain,server,sni),None
  except Exception as e: return domain,set(),str(e)
 tasks=[(d,s,h) for d in domains for s,h in RESOLVERS]
 with concurrent.futures.ThreadPoolExecutor(max_workers=24) as pool:
  results=list(pool.map(one,tasks))
 baseline={}
 for d in domains:
  try: baseline[d]=query(d,"8.8.8.8")
  except Exception: baseline[d]=None
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
