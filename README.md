# GarudaNetra 🛡️

**Client-Side QR Code & URL Phishing Threat Scanner**

GarudaNetra is a fast, privacy-first cybersecurity assistive tool designed to inspect QR codes and web links for phishing, fraud, and malicious indicators. It decodes QR payloads directly in the browser and analyzes URLs across a weighted battery of 17 security heuristics to produce an immediate risk score, actionable threat explanations, and downloadable PDF reports.

---

## 🌟 Key Features

- **📷 Dual QR Capture Modes**:
  - **File Upload / Drag-and-Drop**: Decode image files (`.png`, `.jpg`, `.jpeg`, `.webp`, `.svg`) using in-browser canvas rendering.
  - **Live Camera Scanning**: Point any mobile or desktop camera at a QR code for automatic real-time detection via `getUserMedia`.
- **🔗 Manual URL Inspection**: Paste and evaluate any suspicious link directly without requiring a QR code.
- **🧠 100% Client-Side Heuristic Engine**:
  - 17 security signals evaluated locally in real-time.
  - Generates a **0–100 Risk Score** and clear verdict:
    - 🟢 **Safe** (`0–34`)
    - 🟡 **Suspicious** (`35–64`)
    - 🔴 **Dangerous** (`65–100`)
- **📝 Plain-Language Threat Explanations**: Details what attackers might be attempting and provides specific defensive recommendations.
- **📄 Branded PDF Threat Intelligence Reports**: Generate and export reports with vector risk gauges, breakdown cards, and timestamps using `jsPDF`.
- **📊 Interactive Dashboard & Scan History**:
  - Donut chart visualization of threat distribution.
  - History log stored locally on your device with search filtering and clear options.
- **🎨 Modern Cyber UI & Theme Switcher**:
  - Seamless toggle between Cyber Dark (blue neon glow) and Paper Light themes.
  - Fluid canvas particle constellation effect (with `prefers-reduced-motion` support).
  - Fully responsive across desktop, tablet, and mobile devices.

---

## 🔍 Detection Heuristics & Scoring

GarudaNetra inspects URLs against 17 weighted heuristic indicators commonly leveraged by phishing campaigns:

| Signal | Description | Weight |
|---|---|:---:|
| **Data / Javascript URI** | Checks for non-web schemes (`data:`, `javascript:`, etc.) that execute script or hide payloads. | `+30` |
| **Punycode / Homograph** | Detects look-alike character substitution domains (`xn--`). | `+24` |
| **IP Address as Host** | Flags raw IPv4/IPv6 addresses used instead of domain names. | `+22` |
| **"@" Symbol in URL** | Detects credentials/destination hiding tricks using `@`. | `+20` |
| **Brand Misuse in Subdomain** | Identifies impersonated brands positioned in subdomains of untrusted roots. | `+20` |
| **Look-alike / Typo Domain** | Catches character mutations mimicking major brands (e.g., `paypa1`, `goog1e`). | `+18` |
| **High-Risk TLD** | Flags abused and throwaway top-level domains (`.zip`, `.mov`, `.xyz`, `.top`, etc.). | `+16` |
| **Embedded Credentials** | Identifies `username:password@` syntax embedded in URLs. | `+16` |
| **URL Shortener** | Flags links masking true destinations (`bit.ly`, `tinyurl.com`, `t.co`, etc.). | `+14` |
| **Excessive Subdomains** | Detects multi-level subdomains used to bury malicious domain names. | `+14` |
| **Disguised File / Double Ext** | Flags executable files or deceptive extensions (`.exe`, `.scr`, `.pdf.exe`). | `+14` |
| **No HTTPS Encryption** | Flags insecure, unencrypted plain `http://` connections. | `+12` |
| **Non-Standard Port** | Checks for explicit connections on unusual ports outside `80` and `443`. | `+12` |
| **Obfuscated Characters** | Flags excessive percent-encoding or hex sequences concealing paths. | `+12` |
| **Sensitive-Action Keywords** | Flags phishing bait words (`login`, `verify`, `billing`, `wallet`, etc.). | `+10` |
| **Many Hyphens in Domain** | Detects chained hyphenated domains used to mimic legitimate services. | `+8` |
| **Unusually Long URL** | Flags excessively long links (>90 characters) used to obscure redirects. | `+8` |

---

## 🔒 Privacy & Architecture: Is There Any API?

**There are NO external or backend REST/GraphQL APIs used in this project.**

- **No Remote Threat APIs**: It does not query external third-party threat services (such as VirusTotal, Google Safe Browsing, or URLScan). All analysis logic is executed locally through custom algorithms in [`js/analyzer.js`](file:///d:/internship/Project/js/analyzer.js).
- **No Backend Server**: There is no Node.js, Python, PHP, or cloud backend. No server receives, logs, or stores your scanned URLs or images.
- **Native Browser Web APIs Only**: The application utilizes standard, offline-capable browser APIs:
  - **MediaDevices API** (`navigator.mediaDevices.getUserMedia`): Accesses device camera for QR detection.
  - **Canvas API** (`HTMLCanvasElement`, `CanvasRenderingContext2D`): Extracts pixel data for QR processing and renders particle visuals.
  - **Web Storage API** (`localStorage`): Persists scan history, user preferences, and offline feedback.
  - **URL API** (`new URL(...)`): Parses URL schemes, domains, paths, and ports.
  - **FileReader API**: Reads uploaded image files locally as Data URLs.
- **Client-Side CDN Libraries**:
  - `jsQR` (v1.4.0) via jsDelivr: Pure client-side JavaScript QR code decoder.
  - `jsPDF` (v2.5.1) via cdnjs: Client-side vector PDF generation library.

---

## 📁 Project Structure

```
.
├── index.html            # Main Single Page Application structure & SVG icon definitions
├── dark2.jpeg            # Favicon / brand asset (Dark Mode)
├── light2.jpeg           # Favicon / brand asset (Light Mode)
├── logo.jpeg             # GarudaNetra eagle brand emblem
├── tushar.jpeg           # Developer profile image
├── README.md             # Project documentation
├── css/
│   └── styles.css        # Theme variables, layouts, radar animations, responsive styling
└── js/
    ├── analyzer.js       # Heuristic phishing analysis engine & scoring logic
    ├── app.js            # Controller: navigation routing, file/cam events, scan steps
    ├── dashboard.js      # Statistics calculator & SVG donut chart renderer
    ├── effects.js        # Canvas particle background animation
    ├── logo-data.js      # Inlined Base64 logo asset for jsPDF export
    ├── report.js         # Vector PDF report generator
    ├── scanner.js        # QR decoding interface for image files & webcam streams
    └── storage.js        # LocalStorage persistence wrapper
```

---

## 🚀 Getting Started

No compilation, Node.js installation, or backend setup is required.

### Option 1: Direct File Launch
Simply double-click [`index.html`](file:///d:/internship/Project/index.html) to open it in any modern web browser (Chrome, Firefox, Edge, Safari).

### Option 2: Local HTTP Server (Recommended for camera access)
Some web browsers restrict camera access (`getUserMedia`) on `file://` URLs. To enable camera functionality:
```bash
# Using Python 3
python -m http.server 8000

# Or using Node.js / npx
npx serve .
```
Then navigate to `http://localhost:8000` in your browser.

---

## 👨‍💻 Developer & Credits

- **Creator**: **Tushar Jagad**
  - Final-year Diploma student at **R.C. Technical Institute, Ahmedabad**
  - Cybersecurity enthusiast & threat detection developer
  - Email: [jagadtusharn@gmail.com](mailto:jagadtusharn@gmail.com)
  - GitHub: [@jagadtushar](https://github.com/jagadtushar)
  - LinkedIn: [in/jagadtushar](https://www.linkedin.com/in/jagadtushar/)
- **Program**: Built during an internship with **BharatCares** in collaboration with **IBM SkillsBuild** (Cybersecurity Domain, 2026).

---

## ⚠️ Disclaimer

*GarudaNetra uses heuristic rule-based pattern matching and serves as an educational and assistive tool, not an absolute guarantee. Advanced phishing attacks may evolve around static heuristics. Always practice zero-trust verification before submitting sensitive credentials to unknown destinations.*
