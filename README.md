# CAmap Nordics

> Interaktiivinen kartta Pohjoismaisten kuntien TLS-sertifikaattiauktoriteettien jurisdiktiosta

**Inspiroitunut:** [mxmap.ch](https://mxmap.ch) (David Huser) → [mxmap.nl](https://mxmap.nl) (Soverin/Andre)

Siinä missä mxmap kartoittaa sähköpostipalveluntarjoajia, tämä projekti kartoittaa **TLS-sertifikaattiauktoriteetteja** ja niiden "kill switch" -riskiä. Voiko yhdysvaltalainen CA peruuttaa suomalaisen kunnan verkkosivun sertifikaatin?

## Maat

| Maa | Kuntia |
|-----|--------|
| Suomi | ~309 |
| Ruotsi | ~290 |
| Norja | ~356 |
| Tanska | ~98 |
| **Yhteensä** | **~1053** |

## Riskitasot

| Taso | Väri | Kuvaus |
|------|------|--------|
| Kriittinen | 🔴 Punainen | US CLOUD Act (DigiCert, Google, Amazon, Cloudflare) |
| Korkea | 🟠 Oranssi-punainen | US nonprofit (Let's Encrypt/ISRG) |
| Keskitaso | 🟡 Oranssi | Liittolaismaa (GlobalSign, SwissSign) |
| Matala | 🔵 Sininen | EU-jurisdiktio (HARICA, Certum, D-TRUST) |
| Minimaalinen | 🟢 Vihreä | Pohjoismainen (Buypass NO) |

## Kehitys

### Asennus

```bash
# Vaatii uv (https://docs.astral.sh/uv/)
uv sync --group dev
```

### Pipeline

```bash
# Vaihe 1: Tunnista kuntadomainit (kerran kuussa)
uv run resolve-domains --countries FI SE NO DK

# Vaihe 2: Skannaa TLS-sertifikaatit (joka yö)
uv run scan-certs

# Vaihe 3: Tilastoanalyysi
uv run analyze

# Päivitä CCADB-välimuisti
uv run update-ccadb
```

### Testit

```bash
uv run pytest --cov --cov-report=term-missing
uv run ruff check src tests
uv run ruff format src tests
```

### Karttadata (TopoJSON)

Kuntarajat tulee generoida kansallisista GeoJSON-lähteistä:

```bash
# Suomi: kuntakartta.org (CC BY 4.0)
# Ruotsi: SCB/Lantmäteriet (CC0)
# Norja: Kartverket/Geonorge (NLOD)
# Tanska: DAGI/Geodatastyrelsen (Open)

# Yhdistä ja konvertoi TopoJSON:ksi
npx topojson-server \
    fi-municipalities.geojson \
    se-municipalities.geojson \
    no-municipalities.geojson \
    dk-municipalities.geojson \
    --out nordic-municipalities.topojson \
    --quantization 1e5
```

## Hosting

Suositeltu: **UpCloud Helsinki** + **Coolify** (~7 €/kk) — suomalainen jurisdiktio, EU-tietosuoja.

TLS-sertifikaatti: **Buypass** (Norja) ACME:n kautta — projekti "syö omaa ruokaansa".

## Arkkitehtuuri

```
src/cert_sovereignty/
├── models.py        # Pydantic-tietomallit
├── signatures.py    # CA-sormenjälkitietokanta
├── tls.py           # OpenSSL TLS-skanneri
├── probes.py        # DNS CAA + CT-lokit
├── classifier.py    # Luokittelu + confidence scoring
├── resolve.py       # Kuntadomainien resoluutio
├── pipeline.py      # Orchestraatio
├── analyze.py       # Tilastot
├── cli.py           # CLI-komennot
├── constants.py     # Wikidata SPARQL, vakiot
├── dns.py           # DNS-resoluutio
└── log.py           # Loguru-konfiguraatio
```

## Lisenssi

MIT tai EUPL-1.2 — valinta myöhemmin.

## Attribuutio

- [mxmap.ch](https://github.com/dbrgn/mxmap) (David Huser) — arkkitehtuuri-inspiraatio
- [CCADB](https://ccadb.org) (Mozilla/Linux Foundation) — CA-tietokannan lähde
- [crt.sh](https://crt.sh) (DigiCert) — Certificate Transparency -lokit
- Kansalliset tilastovirastot (Tilastokeskus, SCB, SSB, Danmarks Statistik) — kuntadata
