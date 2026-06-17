# IP Inspector

A **fully self-contained** IP intelligence web app.  
No third-party HTTP APIs. All data is resolved by the server itself.

---

## Data sources (zero external HTTP APIs)

| Source | What it provides | How |
|---|---|---|
| `GeoLite2-City.mmdb` | City, region, country, lat/lng, timezone, postal, EU flag | Bundled local binary DB (MaxMind GeoLite2) |
| Team Cymru DNS | ASN number, network CIDR, org/ISP name | DNS TXT query to `origin.asn.cymru.com` |
| Python `socket` stdlib | Reverse DNS hostname | `socket.gethostbyaddr()` |
| `pycountry` | ISO 3166 alpha-3 code, official country name | Local pip package, no network |
| Built-in dataset (`server.py`) | Capital, TLD, calling code, currency, languages, area, population | Embedded Python dict in `server.py` |

---

## Project structure

```
ipapp/
├── server.py          # Flask backend — all resolution logic
├── requirements.txt   # Python dependencies
├── README.md
└── static/
    └── index.html     # Frontend — fetches from /api/ip on this server
```

---

## Setup & Run

### 1. Install dependencies

```bash
pip install -r requirements.txt
```

> The `maxminddb-geolite2` package bundles the GeoLite2-City.mmdb database (~55 MB).  
> No MaxMind account or license key required.

### 2. Run the server

```bash
python server.py
```

### 3. Open in browser

```
http://localhost:5000
```

---

## API endpoint

`GET /api/ip`

Returns a JSON object with all fields:

```json
{
  "ip": "203.0.113.42",
  "network": "203.0.113.0/24",
  "version": "IPv4",
  "city": "Sydney",
  "region": "New South Wales",
  "region_code": "NSW",
  "country": "AU",
  "country_name": "Australia",
  "country_code": "AU",
  "country_code_iso3": "AUS",
  "country_capital": "Canberra",
  "country_tld": ".au",
  "continent_code": "OC",
  "in_eu": false,
  "postal": "2000",
  "latitude": -33.8688,
  "longitude": 151.2093,
  "timezone": "Australia/Sydney",
  "utc_offset": "+1000",
  "country_calling_code": "+61",
  "currency": "AUD",
  "currency_name": "Australian Dollar",
  "languages": "en",
  "country_area": 7692024,
  "country_population": 25499884,
  "asn": "AS4804",
  "org": "AS4804 MICROPLEX PTY LTD, AU"
}
```

---

## Behind a reverse proxy

If running behind Nginx or another proxy, make sure `X-Forwarded-For` is set.  
The server reads it automatically:

```nginx
proxy_set_header X-Forwarded-For $remote_addr;
```

---

## Notes

- GeoLite2 is a free database from MaxMind with ~99% country-level and ~85% city-level accuracy.
- ASN lookups via Cymru DNS use standard UDP port 53 — no HTTP.
- The built-in country dataset covers all 195 UN-recognized sovereign states.
