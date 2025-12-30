# Top 10 CAs: Static vs RFC 6962 Distribution

_This report shows how the top certificate authorities split their submissions between static (tiled) and RFC 6962 CT logs._


## Summary

Top 10 CAs by total certificates:


| Rank | Certificate Authority | Total | Static | RFC 6962 |
|------|----------------------|-------|--------|----------|
| 1 | GoDaddy.com, Inc. (US) | 9,894 | 4,501 | 5,393 |
| 2 | Amazon (US) | 9,101 | 3,981 | 5,120 |
| 3 | Let's Encrypt (US) | 8,808 | 4,063 | 4,745 |
| 4 | Google Trust Services (US) | 5,880 | 1,909 | 3,971 |
| 5 | GlobalSign nv-sa (BE) | 4,409 | 1,445 | 2,964 |
| 6 | Sectigo Limited (GB) | 3,123 | 1,895 | 1,228 |
| 7 | Microsoft Corporation (US) | 2,891 | 721 | 2,170 |
| 8 | DigiCert Inc (US) | 2,408 | 1,437 | 971 |
| 9 | IdenTrust (US) | 808 | 261 | 547 |
| 10 | ZeroSSL (AT) | 509 | 228 | 281 |

---


## Amazon (US)

**Total certificates**: 9,101


| Log Type | Certificates | Percentage | Logs |
|----------|-------------|------------|------|
| Static   | 3,981 | 43.7% | 13 |
| RFC 6962 | 5,120 | 56.3% | 21 |


## DigiCert Inc (US)

**Total certificates**: 2,408


| Log Type | Certificates | Percentage | Logs |
|----------|-------------|------------|------|
| Static   | 1,437 | 59.7% | 20 |
| RFC 6962 | 971 | 40.3% | 32 |


## GlobalSign nv-sa (BE)

**Total certificates**: 4,409


| Log Type | Certificates | Percentage | Logs |
|----------|-------------|------------|------|
| Static   | 1,445 | 32.8% | 14 |
| RFC 6962 | 2,964 | 67.2% | 23 |


## GoDaddy.com, Inc. (US)

**Total certificates**: 9,894


| Log Type | Certificates | Percentage | Logs |
|----------|-------------|------------|------|
| Static   | 4,501 | 45.5% | 18 |
| RFC 6962 | 5,393 | 54.5% | 27 |


## Google Trust Services (US)

**Total certificates**: 5,880


| Log Type | Certificates | Percentage | Logs |
|----------|-------------|------------|------|
| Static   | 1,909 | 32.5% | 10 |
| RFC 6962 | 3,971 | 67.5% | 18 |


## IdenTrust (US)

**Total certificates**: 808


| Log Type | Certificates | Percentage | Logs |
|----------|-------------|------------|------|
| Static   | 261 | 32.3% | 2 |
| RFC 6962 | 547 | 67.7% | 10 |


## Let's Encrypt (US)

**Total certificates**: 8,808


| Log Type | Certificates | Percentage | Logs |
|----------|-------------|------------|------|
| Static   | 4,063 | 46.1% | 9 |
| RFC 6962 | 4,745 | 53.9% | 17 |


## Microsoft Corporation (US)

**Total certificates**: 2,891


| Log Type | Certificates | Percentage | Logs |
|----------|-------------|------------|------|
| Static   | 721 | 24.9% | 13 |
| RFC 6962 | 2,170 | 75.1% | 20 |


## Sectigo Limited (GB)

**Total certificates**: 3,123


| Log Type | Certificates | Percentage | Logs |
|----------|-------------|------------|------|
| Static   | 1,895 | 60.7% | 18 |
| RFC 6962 | 1,228 | 39.3% | 26 |


## ZeroSSL (AT)

**Total certificates**: 509


| Log Type | Certificates | Percentage | Logs |
|----------|-------------|------------|------|
| Static   | 228 | 44.8% | 8 |
| RFC 6962 | 281 | 55.2% | 15 |


---

# Extra Log Submissions Analysis

_Chrome requires 2 SCTs for certs ≤180 days, 3 SCTs for >180 days. 
This analysis identifies CAs that submit to more logs than required._


_Based on certificates appearing in 2+ logs in our sample (cross-log correlation)._


| CA | Correlated Certs | Required Only | With Extras | Extra % |
|---|---|---|---|---|
| GoDaddy.com, Inc. (US) | 2,392 | 1,869 | 523 | 21.9% |
| Amazon (US) | 1,641 | 1,010 | 631 | 38.5% |
| Google Trust Services (US) | 664 | 362 | 302 | 45.5% |
| Let's Encrypt (US) | 605 | 549 | 56 | 9.3% |
| GlobalSign nv-sa (BE) | 461 | 240 | 221 | 47.9% |
| Microsoft Corporation (US) | 370 | 361 | 9 | 2.4% |
| DigiCert Inc (US) | 316 | 247 | 69 | 21.8% |
| Sectigo Limited (GB) | 240 | 216 | 24 | 10.0% |
| IdenTrust (US) | 188 | 125 | 63 | 33.5% |
| DigiCert, Inc. (US) | 22 | 21 | 1 | 4.5% |
| Apple Inc. (US) | 17 | 10 | 7 | 41.2% |
| Amazon (DE) | 16 | 13 | 3 | 18.8% |
| TrustAsia Technologies, Inc. (CN) | 16 | 12 | 4 | 25.0% |
| ZeroSSL (AT) | 15 | 13 | 2 | 13.3% |
| Actalis S.p.A. (IT) | 11 | 8 | 3 | 27.3% |
