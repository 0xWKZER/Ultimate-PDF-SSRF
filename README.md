# Ultimate-PDF-SSRF: Server-Side Request Forgery (SSRF) Advisory & PoC

## Vulnerability Details

* **Vendor:** OutSystems
* **Product:** Ultimate PDF (OutSystems 11)
* **Affected Versions:** 
  * OutSystems 11 ("Ultimate PDF"): through `15.0.1`
  * OutSystems Developer Cloud ("UltimatePDF_ExternalLogic"): through `3.1.0`
* **Vulnerability Class:** Server-Side Request Forgery (SSRF) / CWE-918
* **Impact:** Internal service enumeration, arbitrary HTTP request smuggling/coercion, AWS cloud metadata extraction (IAM credential exposure leading to account compromise) / unauthenticated state-changing operations (e.g., unintended record deletion via HTTP GET).

---

## Description / Summary

A Server-Side Request Forgery (SSRF) vulnerability exists in Ultimate PDF for OutSystems. The PDF and screenshot generation actions (`PrintPDF`, `PrintPDF_ToRest`, `PrintPDF_ToS3`, and `ScreenshotPNG`) rely on basic URI syntax and scheme validation (`UrlUtils.IsValidHttpsUri`, which permits both HTTP and HTTPS URLs). 

The application performs **no host, IP, or port checks**, nor any post-DNS-resolution validation (leaving it susceptible to DNS-rebinding bypasses). The validated input is passed directly to a server-side headless Chromium instance via `page.GoToAsync` without a destination allow-list, or blocking of:
* Loopback ranges (`127.0.0.0/8`)
* Private networks (RFC 1918)
* Link-local / cloud metadata ranges (`169.254.0.0/16`)

An unauthenticated remote attacker can coerce the server into issuing attacker-controlled HTTP/HTTPS requests from the rendering host. Because requests originate from the server's internal network position and the rendered output is returned in the generated PDF or PNG, attackers can read contents from internal, loopback, and plain-HTTP services normally unreachable from the outside.

---

## Technical Analysis & Vector Scope

1. **Inadequate Input Validation:** The underlying check only validates URI syntax and scheme (`http`/`https`), completely omitting network-level restrictions.
2. **Chromium-Based Execution (`page.GoToAsync`):** Because navigation occurs inside a full headless Chromium browser that executes client-side JavaScript, an attacker-controlled page can:
   * Execute cross-origin requests (CSRF) against internal web interfaces.
   * Interact dynamically with internal services reachable from the rendering host.
3. **Cloud Metadata Exploitation:** When deployed on a cloud instance with an accessible metadata service (such as AWS IMDSv1 at `http://169.254.169.254`), this flaw exposes temporary IAM credentials, potentially resulting in full cloud account compromise.
4. **State-Changing Operations:** Authorized testing empirically confirmed that the server can be directed at internal or administrative endpoints executing state-changing operations over HTTP GET (e.g., `https://<internal-host>/?deleteid=1`), resulting in unauthenticated destructive actions like record deletion.
