🌐 Languages: [󠁧󠁢󠁥󠁮󠁧󠁿**English**](README.md) | [**Русский**](README.ru.md)

[![Last Build](../../actions/workflows/nextdns_sync.yml/badge.svg?branch=main)](../../actions/workflows/nextdns_sync.yml)<br>

# DNS Block&Redirect Configurer

**Allows to set Redirect and Block rules to your Cloudflare and NextDNS accounts.**

**Ready-to-run via GitHub Actions.** [Video guide](https://www.youtube.com/watch?v=vbAXM_xAL5I)

## Comparison of Free Plans: NextDNS vs Cloudflare

|                         | NextDNS                                                         | Cloudflare                                                                                                           |
|-------------------------|-----------------------------------------------------------------|----------------------------------------------------------------------------------------------------------------------|
| **DNS Query Limit**     | 300,000 per month                                               | 100,000 per day                                                                                                      |
| **IPv4 Restrictions**   | DNS queries are limited to a single IP address (can be changed) | DNS queries are strictly limited to a single IP address (automatically assigned by Cloudflare and cannot be changed) |
| **DoH / DoT / IPv6**    | Unlimited                                                       | Unlimited                                                                                                            |
| **Setup API Limits**    | 60 requests per minute                                          | Unlimited                                                                                                            |
| **General Limitations** | None                                                            | Infrastructure is blocked by Roskomnadzor (availability issues in Russia)                                            |
| **Advantages**          | Built-in ad and tracker blocking options                        | More reliable and fast infrastructure                                                                                |

In summary: if you are located in Russia, **NextDNS** is your only viable option due to Roskomnadzor restrictions.

If you are in another country, **Cloudflare** offers more generous limits on the free plan. Tracker and ad blocking can also
be enabled by providing a domain blocklist in `BLOCK`, for example: https://small.oisd.nl/domainswild2

## Easy Setup

Use the configurator https://dns-conf-ui.vercel.app in **Quick** mode. It will automatically configure your DNS profile
and perform all required GitHub setup steps.

You only need to sign in with GitHub and provide **CLIENT_ID** and **AUTH_SECRET**. More details on where to find these
values here: [Setup credentials](#setup-credentials)

## Standard Setup

[Set up credentials](#set-up-credentials)

[Set up profile](#set-up-profile)

[Set up data sources](#set-up-data-sources)

[Set up exclude redirects (optional)](#set-up-exclude-redirects-optional)

[Set up a DNS donor](#set-up-a-dns-donor)

[Multiple profiles setup](#multiple-profiles-setup)

[GitHub Actions setup](#github-actions-setup)

---
## Set up credentials

### NextDNS credentials setup

1) Generate an **API KEY** from https://my.nextdns.io/account and set it as an **environment variable** `AUTH_SECRET`

2) Click on **NextDNS** logo. On the opened page, copy ID from Endpoints section.
   Set it as **environment variable** `CLIENT_ID`


### Cloudflare credentials setup

1) After signing up into a **Cloudflare**, navigate to _Zero Trust_ tab and create an account.

- Free Plan has decent limits, so just choose it.
- Skip providing payment method step by choosing _Cancel and exit_ (top right corner)
- Go back to _Zero Trust_ tab

2) Create a **Cloudflare API token**, from https://dash.cloudflare.com/profile/api-tokens

with 2 permissions:

    Account.Zero Trust : Edit

    Account.Account Firewall Access Rules : Edit

Set API token to **environment variable** `AUTH_SECRET`

3) Get your **Account ID** from : https://dash.cloudflare.com/?to=/:account/workers

Set **Account ID** to **environment variable** `CLIENT_ID`

---

## Set up profile

Set **environment variable** `DNS` with DNS provider name (**Cloudflare** or **NextDNS**)

---

## Set up data sources

The automated NextDNS workflow uses this current aggregated source:

`https://raw.githubusercontent.com/Noktomezo/RussiaFancyLists/main/lists/hosts/smart.hosts`

It is refreshed approximately every 3 hours. Unlike a simple concatenation of hosts files, its geoblock section keeps IP/domain pairs whose TLS/SNI handshake was checked by the list maintainer through the corresponding proxy. A separate **Crutch** section contains direct-IP mappings for some local ISP blocks. Source and methodology: https://github.com/Noktomezo/RussiaFancyLists

The SMART URL is pinned in `.github/workflows/nextdns_sync.yml`. The GitHub Environment variable `REDIRECT` no longer overrides this workflow; the previous two sources have been replaced with the tested aggregate. Do not append large additional sources without recalculating the NextDNS rule limit.

### 1) Set up Redirects

For a normal application run, set sources in the **environment variable** `REDIRECT`. The automated NextDNS workflow in this repository uses the pinned SMART source described above.

The parser supports standard hosts lines with multiple domains after one IP. When a domain appears more than once, the first mapping in source order is kept.

Thus, parsing lines:

    0.0.0.0 domain.to.block
    1.2.3.4 domain.to.redirect
    127.0.0.1 another.to.block

will keep only `1.2.3.4 domain.to.redirect` for the further redirect processing.

+ Redirect priority follows sources order. If domain appears more than one time, the first only IP will be applied.

### 2) Set up Blocklist

Set sources to **environment variable** `BLOCK`

Script will parse sources, keeping only redirects to `0.0.0.0`, `127.0.0.1`, `::1`, and also lines containing domain only.

Thus, parsing lines

    1.2.3.4 domain.to.redirect
    0.0.0.0 domain.to.block
    127.0.0.1 another.to.block
    ::1 ipv6.to.block
    no-ip.just.domain

will keep only 

    domain.to.block
    another.to.block
    no-ip.just.domain
    ipv6.to.block
for the further block processing.

+ You may want to provide the same source for both `BLOCK` and `REDIRECT` for **Cloudflare**.
+ For **NextDNS**, the best option might be to set `REDIRECT` only, and then manually choose any blocklists at the
  _Privacy_ tab.

---

## Set up exclude redirects (optional)

Add your own exclusions to the **environment variable** `EXCLUDE_REDIRECT`, separated by commas, e.g.
`instagram.com,twitch.com`. The named domain and its true subdomains will not be added; matching existing
rewrites will be deleted. Do not use this variable for large service families unless you intend to disable them entirely.

---

## Set up a DNS donor

If IP addresses of domains are outdated, they can be updated via "donor" DNS. You need:
1) Create **environment variable** `DONOR_DNS`
2) Provide the **DNS-provider** that will be used as a **donor**.
   Use one of the following formats:
- **IPv4** (e.g. `111.88.96.50`)
- **DoH** (e.g. `https://xbox-dns.ru/dns-query`)

For instance, if your hosts-file supplies following:

    1.2.3.4 domain-1.to.redirect
    1.2.3.4 domain-2.to.redirect
    1.2.3.4 domain-3.to.redirect

Then, a `DONOR_DNS` value will be called for each domain, fetching new IP addresses:

    5.6.7.8 domain-1.to.redirect
    2.3.4.5 domain-2.to.redirect
    9.8.7.6 domain-3.to.redirect

Thus, the new IPs will be used for the further redirect rules upload process.

**NextDNS SMART special case:** the workflow intentionally does not replace the SMART source IPs through
`DONOR_DNS`. They have already been selected by upstream TLS/SNI checks. Substituting an ordinary DNS answer
could break the proxy route. The current NextDNS workflow does not use `DONOR_DNS`.

---

## Multiple profiles setup

### Restrictions

All profiles get _similar_ settings. That means `BLOCK`, `REDIRECT` and `EXCLUDE_REDIRECT` are **shared**.

### Multiple profiles of single provider

Put your profiles separated by coma **without whitespace** into related **environment variables**.
E.g., two NextDNS profiles must be set as shown:

- `AUTH_SECRET` has: `secret_NextDns_1,secret_NextDns_2`
- `CLIENT_ID` has `client_id_NextDns_1,client_id_NextDns_2`

### Multiple profiles of different providers

In addition to setting above, list provider for each profile in **environment variable** `DNS`. For example:

- `DNS` has: `NEXTDNS,CLOUDFLARE,NEXTDNS`
- `AUTH_SECRET` has: `secret_NextDns_1,secret_Cloudflare_1,secret_NextDns_2`
- `CLIENT_ID` has `client_id_NextDns_1,client_id_Cloudflare_1,client_id_NextDns_2`

---

## Script Behavior

### Cloudflare

Previously generated data will be removed. Script recognizes old data by marks:

+ Name prefix for List: **_Blocked websites by script_** and **_Override websites by script_**
+ Name prefix for Rule: **_Rules set by script_**
+ Different **_Session id_**. **_Session id_** is stored in a description field.

After removing old data, new lists and rules will be generated and applied.

If you want to clear **Cloudflare** block/redirect settings, launch the script without providing sources in related *
*environment variables**. E.g. providing no value for **environment variable** `BLOCK` will cause removing old related
data: lists and rules used to set up blocks.

### NextDNS

For `REDIRECT`:

+ Existing domain will be updated if redirect IP has changed
+ If new domains are provided, they will be added
+ The rest redirect settings are kept untouched
+ Old source-managed domains are cleaned up during the SMART source migration; user-created rewrites outside the saved managed-domain manifest are preserved

For `BLOCK`:

+ If new domains are provided, they will be added
+ The rest block settings are kept untouched

Previously generated data is removed **ONLY** when both `BLOCK` and `REDIRECT` sources were not provided.

---

## GitHub Actions setup

#### Step-by-step video guide: [REDIRECT for NextDNS](https://www.youtube.com/watch?v=vbAXM_xAL5I)

#### Steps

1) Fork repository
2) Go _Settings_ => _Environments_
3) Create _New environment_ with name `DNS`
4) Provide `AUTH_SECRET` and `CLIENT_ID` to **Environment secrets**
5) Provide `DNS`, `BLOCK` and `EXCLUDE_REDIRECT` to **Environment variables**. The current NextDNS workflow pins its SMART source in the workflow file; no `REDIRECT` variable is required.

+ The action will be executed daily at **03:00 Europe/Zurich time**. To set another time, change cron at
  `.github/workflows/nextdns_sync.yml`
+ You can run the action manually via `Run workflow` button: switch to _Actions_ tab and choose workflow named **DNS
  Block&Redirect Configurer cron task**