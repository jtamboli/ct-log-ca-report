# Top 10 CAs: Static vs RFC 6962 Distribution

_This report shows how the top certificate authorities split their submissions between static (tiled) and RFC 6962 CT logs._


## 1. Amazon (US)

**Total certificates**: 10,648


| Log Type | Certificates | Percentage | Logs |
|----------|-------------|------------|------|
| Static   | 4,484 | 42.1% | 10 |
| RFC 6962 | 6,164 | 57.9% | 26 |


## 2. Let's Encrypt (US)

**Total certificates**: 10,134


| Log Type | Certificates | Percentage | Logs |
|----------|-------------|------------|------|
| Static   | 3,952 | 39.0% | 10 |
| RFC 6962 | 6,182 | 61.0% | 17 |


## 3. GoDaddy.com, Inc. (US)

**Total certificates**: 10,006


| Log Type | Certificates | Percentage | Logs |
|----------|-------------|------------|------|
| Static   | 4,203 | 42.0% | 19 |
| RFC 6962 | 5,803 | 58.0% | 38 |


## 4. Google Trust Services (US)

**Total certificates**: 9,962


| Log Type | Certificates | Percentage | Logs |
|----------|-------------|------------|------|
| Static   | 3,198 | 32.1% | 10 |
| RFC 6962 | 6,764 | 67.9% | 22 |


## 5. Microsoft Corporation (US)

**Total certificates**: 3,468


| Log Type | Certificates | Percentage | Logs |
|----------|-------------|------------|------|
| Static   | 1,244 | 35.9% | 13 |
| RFC 6962 | 2,224 | 64.1% | 25 |


## 6. DigiCert Inc (US)

**Total certificates**: 2,381


| Log Type | Certificates | Percentage | Logs |
|----------|-------------|------------|------|
| Static   | 1,216 | 51.1% | 20 |
| RFC 6962 | 1,165 | 48.9% | 39 |


## 7. Sectigo Limited (GB)

**Total certificates**: 1,881


| Log Type | Certificates | Percentage | Logs |
|----------|-------------|------------|------|
| Static   | 1,431 | 76.1% | 17 |
| RFC 6962 | 450 | 23.9% | 32 |


## 8. ZeroSSL (AT)

**Total certificates**: 1,182


| Log Type | Certificates | Percentage | Logs |
|----------|-------------|------------|------|
| Static   | 550 | 46.5% | 10 |
| RFC 6962 | 632 | 53.5% | 20 |


## 9. IdenTrust (US)

**Total certificates**: 699


| Log Type | Certificates | Percentage | Logs |
|----------|-------------|------------|------|
| Static   | 232 | 33.2% | 2 |
| RFC 6962 | 467 | 66.8% | 11 |


## 10. GlobalSign nv-sa (BE)

**Total certificates**: 493


| Log Type | Certificates | Percentage | Logs |
|----------|-------------|------------|------|
| Static   | 69 | 14.0% | 16 |
| RFC 6962 | 424 | 86.0% | 22 |


---

# Extra Log Submissions Analysis

_Chrome requires 2 SCTs for certs ≤180 days, 3 SCTs for >180 days. 
This analysis identifies CAs that submit to more logs than required._


_Based on certificates appearing in 2+ logs in our sample (cross-log correlation)._


| CA | Correlated Certs | Required Only | With Extras | Extra % |
|---|---|---|---|---|
| GoDaddy.com, Inc. (US) | 1,666 | 823 | 843 | 50.6% |
| Let's Encrypt (US) | 1,513 | 1,263 | 250 | 16.5% |
| Amazon (US) | 1,301 | 346 | 955 | 73.4% |
| Google Trust Services (US) | 1,218 | 398 | 820 | 67.3% |
| Microsoft Corporation (US) | 608 | 588 | 20 | 3.3% |
| DigiCert Inc (US) | 268 | 127 | 141 | 52.6% |
| IdenTrust (US) | 171 | 88 | 83 | 48.5% |
| ZeroSSL (AT) | 144 | 104 | 40 | 27.8% |
| Sectigo Limited (GB) | 119 | 73 | 46 | 38.7% |
| GlobalSign nv-sa (BE) | 68 | 35 | 33 | 48.5% |
| Amazon (DE) | 47 | 41 | 6 | 12.8% |
| DigiCert, Inc. (US) | 24 | 23 | 1 | 4.2% |
| TrustAsia Technologies, Inc. (CN) | 14 | 7 | 7 | 50.0% |
| Starfield Technologies, Inc. (US) | 10 | 8 | 2 | 20.0% |
