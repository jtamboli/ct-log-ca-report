# Top 10 CAs: Static vs RFC 6962 Distribution

_This report shows how the top certificate authorities split their submissions between static (tiled) and RFC 6962 CT logs._


## Summary

Top 10 CAs by total certificates:


| Rank | Certificate Authority | Total | Static | RFC 6962 |
|------|----------------------|-------|--------|----------|
| 1 | Let's Encrypt (US) | 10,203 | 4,137 | 6,066 |
| 2 | Amazon (US) | 9,243 | 3,958 | 5,285 |
| 3 | GoDaddy.com, Inc. (US) | 9,191 | 3,799 | 5,392 |
| 4 | Google Trust Services (US) | 6,211 | 2,046 | 4,165 |
| 5 | GlobalSign nv-sa (BE) | 4,243 | 1,441 | 2,802 |
| 6 | Microsoft Corporation (US) | 2,947 | 711 | 2,236 |
| 7 | Sectigo Limited (GB) | 2,271 | 1,669 | 602 |
| 8 | DigiCert Inc (US) | 2,251 | 1,183 | 1,068 |
| 9 | IdenTrust (US) | 829 | 251 | 578 |
| 10 | ZeroSSL (AT) | 414 | 250 | 164 |

---


## Amazon (US)

**Total certificates**: 9,243


| Log Type | Certificates | Percentage | Logs |
|----------|-------------|------------|------|
| Static   | 3,958 | 42.8% | 11 |
| RFC 6962 | 5,285 | 57.2% | 24 |


## DigiCert Inc (US)

**Total certificates**: 2,251


| Log Type | Certificates | Percentage | Logs |
|----------|-------------|------------|------|
| Static   | 1,183 | 52.6% | 19 |
| RFC 6962 | 1,068 | 47.4% | 32 |


## GlobalSign nv-sa (BE)

**Total certificates**: 4,243


| Log Type | Certificates | Percentage | Logs |
|----------|-------------|------------|------|
| Static   | 1,441 | 34.0% | 10 |
| RFC 6962 | 2,802 | 66.0% | 19 |


## GoDaddy.com, Inc. (US)

**Total certificates**: 9,191


| Log Type | Certificates | Percentage | Logs |
|----------|-------------|------------|------|
| Static   | 3,799 | 41.3% | 19 |
| RFC 6962 | 5,392 | 58.7% | 28 |


## Google Trust Services (US)

**Total certificates**: 6,211


| Log Type | Certificates | Percentage | Logs |
|----------|-------------|------------|------|
| Static   | 2,046 | 32.9% | 10 |
| RFC 6962 | 4,165 | 67.1% | 18 |


## IdenTrust (US)

**Total certificates**: 829


| Log Type | Certificates | Percentage | Logs |
|----------|-------------|------------|------|
| Static   | 251 | 30.3% | 2 |
| RFC 6962 | 578 | 69.7% | 10 |


## Let's Encrypt (US)

**Total certificates**: 10,203


| Log Type | Certificates | Percentage | Logs |
|----------|-------------|------------|------|
| Static   | 4,137 | 40.5% | 9 |
| RFC 6962 | 6,066 | 59.5% | 15 |


## Microsoft Corporation (US)

**Total certificates**: 2,947


| Log Type | Certificates | Percentage | Logs |
|----------|-------------|------------|------|
| Static   | 711 | 24.1% | 15 |
| RFC 6962 | 2,236 | 75.9% | 20 |


## Sectigo Limited (GB)

**Total certificates**: 2,271


| Log Type | Certificates | Percentage | Logs |
|----------|-------------|------------|------|
| Static   | 1,669 | 73.5% | 16 |
| RFC 6962 | 602 | 26.5% | 26 |


## ZeroSSL (AT)

**Total certificates**: 414


| Log Type | Certificates | Percentage | Logs |
|----------|-------------|------------|------|
| Static   | 250 | 60.4% | 7 |
| RFC 6962 | 164 | 39.6% | 12 |


---

# Extra Log Submissions Analysis

_Chrome requires 2 SCTs for certs ≤180 days, 3 SCTs for >180 days. 
This analysis identifies CAs that submit to more logs than required._


_Based on certificates appearing in 2+ logs in our sample (cross-log correlation)._


| CA | Correlated Certs | Required Only | With Extras | Extra % |
|---|---|---|---|---|
| GoDaddy.com, Inc. (US) | 1,952 | 1,376 | 576 | 29.5% |
| Amazon (US) | 1,522 | 664 | 858 | 56.4% |
| Let's Encrypt (US) | 1,035 | 865 | 170 | 16.4% |
| Google Trust Services (US) | 727 | 361 | 366 | 50.3% |
| GlobalSign nv-sa (BE) | 490 | 226 | 264 | 53.9% |
| DigiCert Inc (US) | 290 | 218 | 72 | 24.8% |
| Microsoft Corporation (US) | 273 | 258 | 15 | 5.5% |
| IdenTrust (US) | 201 | 124 | 77 | 38.3% |
| Sectigo Limited (GB) | 158 | 119 | 39 | 24.7% |
| DigiCert, Inc. (US) | 23 | 22 | 1 | 4.3% |
| Apple Inc. (US) | 17 | 9 | 8 | 47.1% |
| Cisco Systems, Inc. (US) | 14 | 7 | 7 | 50.0% |
| TrustAsia Technologies, Inc. (CN) | 14 | 12 | 2 | 14.3% |
| Amazon (DE) | 12 | 10 | 2 | 16.7% |
| ZeroSSL (AT) | 10 | 9 | 1 | 10.0% |
