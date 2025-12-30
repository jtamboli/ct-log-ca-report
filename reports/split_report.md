# Top 10 CAs: Static vs RFC 6962 Distribution

_This report shows how the top certificate authorities split their submissions between static (tiled) and RFC 6962 CT logs._


## 1. Let's Encrypt (US)

**Total certificates**: 10,494


| Log Type | Certificates | Percentage | Logs |
|----------|-------------|------------|------|
| Static   | 4,596 | 43.8% | 10 |
| RFC 6962 | 5,898 | 56.2% | 18 |


## 2. GoDaddy.com, Inc. (US)

**Total certificates**: 9,286


| Log Type | Certificates | Percentage | Logs |
|----------|-------------|------------|------|
| Static   | 4,296 | 46.3% | 19 |
| RFC 6962 | 4,990 | 53.7% | 28 |


## 3. Amazon (US)

**Total certificates**: 9,042


| Log Type | Certificates | Percentage | Logs |
|----------|-------------|------------|------|
| Static   | 3,782 | 41.8% | 12 |
| RFC 6962 | 5,260 | 58.2% | 19 |


## 4. Google Trust Services (US)

**Total certificates**: 6,345


| Log Type | Certificates | Percentage | Logs |
|----------|-------------|------------|------|
| Static   | 1,835 | 28.9% | 10 |
| RFC 6962 | 4,510 | 71.1% | 18 |


## 5. GlobalSign nv-sa (BE)

**Total certificates**: 4,145


| Log Type | Certificates | Percentage | Logs |
|----------|-------------|------------|------|
| Static   | 1,439 | 34.7% | 15 |
| RFC 6962 | 2,706 | 65.3% | 19 |


## 6. DigiCert Inc (US)

**Total certificates**: 3,219


| Log Type | Certificates | Percentage | Logs |
|----------|-------------|------------|------|
| Static   | 1,728 | 53.7% | 20 |
| RFC 6962 | 1,491 | 46.3% | 32 |


## 7. Microsoft Corporation (US)

**Total certificates**: 2,922


| Log Type | Certificates | Percentage | Logs |
|----------|-------------|------------|------|
| Static   | 760 | 26.0% | 14 |
| RFC 6962 | 2,162 | 74.0% | 20 |


## 8. Sectigo Limited (GB)

**Total certificates**: 1,988


| Log Type | Certificates | Percentage | Logs |
|----------|-------------|------------|------|
| Static   | 1,568 | 78.9% | 20 |
| RFC 6962 | 420 | 21.1% | 28 |


## 9. IdenTrust (US)

**Total certificates**: 906


| Log Type | Certificates | Percentage | Logs |
|----------|-------------|------------|------|
| Static   | 289 | 31.9% | 3 |
| RFC 6962 | 617 | 68.1% | 10 |


## 10. ZeroSSL (AT)

**Total certificates**: 502


| Log Type | Certificates | Percentage | Logs |
|----------|-------------|------------|------|
| Static   | 139 | 27.7% | 9 |
| RFC 6962 | 363 | 72.3% | 14 |


---

# Extra Log Submissions Analysis

_Chrome requires 2 SCTs for certs ≤180 days, 3 SCTs for >180 days. 
This analysis identifies CAs that submit to more logs than required._


_Based on certificates appearing in 2+ logs in our sample (cross-log correlation)._


| CA | Correlated Certs | Required Only | With Extras | Extra % |
|---|---|---|---|---|
| GoDaddy.com, Inc. (US) | 1,756 | 1,023 | 733 | 41.7% |
| Amazon (US) | 1,585 | 907 | 678 | 42.8% |
| Let's Encrypt (US) | 983 | 913 | 70 | 7.1% |
| Google Trust Services (US) | 912 | 568 | 344 | 37.7% |
| DigiCert Inc (US) | 509 | 380 | 129 | 25.3% |
| GlobalSign nv-sa (BE) | 470 | 202 | 268 | 57.0% |
| Microsoft Corporation (US) | 375 | 346 | 29 | 7.7% |
| IdenTrust (US) | 210 | 97 | 113 | 53.8% |
| Sectigo Limited (GB) | 128 | 99 | 29 | 22.7% |
| Gandi SAS (FR) | 43 | 33 | 10 | 23.3% |
| DigiCert, Inc. (US) | 23 | 22 | 1 | 4.3% |
| ZeroSSL (AT) | 22 | 22 | 0 | 0.0% |
| Amazon (DE) | 19 | 18 | 1 | 5.3% |
| Apple Inc. (US) | 17 | 10 | 7 | 41.2% |
| TrustAsia Technologies, Inc. (CN) | 12 | 10 | 2 | 16.7% |
