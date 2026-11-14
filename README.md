# 🔍 screensharing.me

<p align="center">
  <strong>Minecraft Forensic Investigation Platform</strong>
  <br />
  Investigate. Analyze. Verify.
  <br /><br />
  A consent-first Minecraft forensic scanner with real-time investigations, evidence analysis, and a dedicated Windows desktop application.
</p>

<p align="center">
  <a href="https://screensharing-me-azure.vercel.app/">
    <img src="https://img.shields.io/badge/Website-Live-16A34A?style=for-the-badge&logo=vercel&logoColor=white" alt="Website" />
  </a>
  <img src="https://img.shields.io/badge/Platform-Windows-0078D4?style=for-the-badge&logo=windows&logoColor=white" alt="Windows" />
  <img src="https://img.shields.io/badge/Framework-.NET%2010-512BD4?style=for-the-badge&logo=dotnet&logoColor=white" alt=".NET 10" />
  <img src="https://img.shields.io/badge/Frontend-Next.js%2016-000000?style=for-the-badge&logo=next.js&logoColor=white" alt="Next.js" />
  <img src="https://img.shields.io/badge/Database-PostgreSQL-4169E1?style=for-the-badge&logo=postgresql&logoColor=white" alt="PostgreSQL" />
</p>

---

## 🔍 About screensharing.me

**screensharing.me** is a Minecraft forensic investigation platform designed to help investigators examine Minecraft installations for evidence of unauthorized modifications, cheat clients, and suspicious components.

The platform combines a web-based investigator dashboard with a dedicated Windows desktop application (`screensharing.me.exe`) that performs consent-based, read-only forensic scans.

Investigations are connected through unique PINs, allowing investigators to monitor scan progress, receive findings in real time, and review detailed forensic reports.

Unlike traditional full-computer scanners, screensharing.me focuses exclusively on the Minecraft instance being investigated.

The goal is to provide a transparent, evidence-driven investigation process without unnecessarily accessing unrelated files on a player's computer.

## ✨ Features

### 🔍 Instance-Specific Minecraft Scanning

The scanner is designed to investigate **only the currently running Minecraft instance**.

Instance identification uses information from the actual Minecraft process rather than assuming the default `.minecraft` directory.

Supported identification information includes:

- Minecraft process identification.
- Java executable and command-line arguments.
- Game directory arguments (`--gameDir`).
- Working directory information.
- Active launcher and instance information.
- Multiple running Minecraft instance selection.

If the scanner cannot confidently identify the correct instance, it refuses to proceed rather than silently scanning another directory.

**Supported launcher environments include:**

- Official Minecraft Launcher.
- Prism Launcher.
- MultiMC.
- Modrinth App.
- CurseForge.
- Other compatible launcher configurations.

Launcher compatibility depends on the information exposed by the running process.

### 🛡️ Forensic Detection Engine

screensharing.me uses a modular detection engine combining multiple inspection techniques to identify potentially unauthorized Minecraft modifications.

Detection methods include:

- Known cheat-related strings and identifiers.
- Constant-pool string matching.
- Class and package name analysis.
- JAR archive inspection.
- Suspicious metadata analysis.
- Modification framework identification.
- File hash and signature comparisons.
- Suspicious configuration and script analysis.
- Multiple-indicator evidence scoring.
- Evasion-aware detection heuristics.

The detection engine currently contains **98 signatures and heuristics** organized into categorized databases.

Detection rules are maintained separately from the scanner implementation, making it easier to introduce additional signatures and detection categories.

Detection coverage is continuously expandable as new indicators become available and can be verified.

### 📂 Files & Components Inspected

The scanner examines relevant files and components belonging to the selected Minecraft instance.

| Component | Inspection |
|---|---|
| Mod archives | JAR contents, classes and signatures |
| Configurations | Suspicious settings and identifiers |
| Scripts | Instance-local script inspection |
| Executables | Relevant executable components |
| Resource packs | Archive and metadata inspection |
| Shader packs | Relevant files and metadata |
| Logs | Historical activity and indicators |
| Crash reports | Relevant modification evidence |
| Class paths | Integrity and consistency analysis |
| Game process | Process information and available memory inspection |

Files that cannot be fully inspected are recorded in the investigation report rather than silently ignored.

### 🚨 Detection Classifications

Every finding receives a classification based on its available evidence and confidence.

| Classification | Description |
|---|---|
| 🟢 Confirmed | Confirmed detection based on available evidence |
| 🟠 High Confidence | Strong indicators requiring investigation |
| 🟡 Low Confidence | Suspicious evidence requiring manual review |
| 🔵 Informational | Relevant information without a suspicious verdict |
| ⚪ Unable to Inspect | Content could not be fully inspected |

Individual findings can include:

- Detection name.
- Suspected cheat or client.
- Detection category.
- File location.
- Matching signature or indicator.
- Supporting evidence.
- Confidence level.
- Severity.
- Confirmation status.
- Manual review requirements.

The scanner prioritizes contextual evidence to help reduce false positives from legitimate Minecraft modifications.

### 🔗 PIN-Based Investigations

Investigations are connected through unique, temporary PINs.

The investigator creates an investigation through the website and shares its PIN with the player.

The player enters the PIN in the desktop application to establish the investigation session.

Features include:

- Unique investigation PIN generation.
- PIN expiration.
- Single-use investigation connection.
- Brute-force protection.
- Player consent confirmation.
- Secure desktop authentication.
- Investigation session management.
- Reconnection handling.

### 📡 Real-Time Investigation Monitoring

Investigators can monitor the scanning process directly from the website.

Live updates include:

- Connected player and instance information.
- Current scanning stage.
- Files discovered.
- Files examined.
- Files skipped.
- Current scan progress.
- Detection findings.
- Scan completion status.

Server-Sent Events (SSE) provide real-time updates without requiring investigators to repeatedly refresh the page.

### 📊 Detailed Investigation Reports

Every completed investigation produces a detailed report containing the available scan evidence.

Reports can include:

- Overall investigation verdict.
- Detection classifications.
- Individual findings and evidence.
- Suspected cheat client identification.
- File paths and SHA-256 hashes.
- Inspection limitations.
- Files that could not be inspected.
- Instance inventory.
- Scan coverage.
- Chain-of-custody information.

**Supported export formats:**

- PDF.
- JSON.
- CSV.

Reports are accessible through the website and supported desktop application functionality.

### 🌐 Investigator Dashboard

The web dashboard provides the main interface for managing investigations.

Features include:

- Account registration and authentication.
- Investigation creation.
- PIN generation and management.
- Live investigation monitoring.
- Detailed findings and reports.
- Investigation history.
- Account settings.
- Report exports.

The dashboard is designed to keep investigation information organized and accessible.

### ⚙️ Administrative Console

The administrative console provides tools for managing the platform.

Administrative functionality includes:

- User management.
- Investigation management.
- Active session and device management.
- Detection catalog editing.
- Application version management.
- Audit log access.
- Platform configuration.
- Mail outbox management.

A dedicated desktop administrative and staff console is also included.

### 🔐 Security & Privacy

Security and investigation scope are fundamental parts of screensharing.me.

Security features include:

- Argon2id password hashing.
- Windows DPAPI-protected local storage.
- PIN expiration and brute-force protection.
- Rate limiting.
- CSRF and Origin validation.
- Secure session management.
- Investigation consent requirements.
- File integrity information.
- Chain-of-custody records.

**Important privacy guarantees:**

- The scanner does not perform a full-PC scan.
- Only the identified and selected Minecraft instance is inspected.
- Scanning requires player consent.
- Suspicious files are never automatically deleted or modified.
- Unrelated directories are outside the intended scanning scope.

---

## 🖥️ Desktop Application

The Windows client is distributed as a standalone executable.

**Application:** `screensharing.me.exe`

**Technology:**
- .NET 10.
- WPF.
- MVVM architecture.
- CommunityToolkit.Mvvm.
- Microsoft.Data.Sqlite.
- Windows DPAPI.
- QuestPDF.

The desktop application handles instance identification, player consent, forensic scanning, evidence collection, and communication with the investigation backend.

### 🖼️ Desktop Screenshots

Screenshots rendered from the actual desktop application views using real scan data.

<p align="center">
  <img src="documentation/screenshots/desktop/README.png" alt="screensharing.me desktop application" width="850" />
</p>

Additional screenshots are available in:

`documentation/screenshots/desktop/`

---

## 🏗️ Technology Stack

screensharing.me consists of three primary components.

### 🌐 Website & Backend

| Technology | Purpose |
|---|---|
| Next.js 16 | Web application |
| TypeScript | Application development |
| Tailwind CSS 4 | Styling |
| Prisma 6 | Database ORM |
| PostgreSQL | Primary database |
| Argon2id | Password hashing |
| Server-Sent Events | Real-time communication |
| Vitest | Unit testing |

### 💻 Windows Desktop Client

| Technology | Purpose |
|---|---|
| .NET 10 | Application framework |
| WPF | Desktop interface |
| MVVM | Application architecture |
| CommunityToolkit.Mvvm | MVVM utilities |
| Microsoft.Data.Sqlite | Local persistence |
| Windows DPAPI | Local data protection |
| QuestPDF | PDF generation |

### 🔍 Scanner Engine

| Component | Purpose |
|---|---|
| Signature Database | Known detection indicators |
| Archive Inspection | JAR and archive analysis |
| Constant-Pool Analysis | String detection |
| Metadata Analysis | Suspicious component identification |
| Evidence Scoring | Confidence classification |
| Evasion Checks | Additional suspicious pattern detection |
| Process Inspection | Minecraft instance identification |

---

## 📁 Repository Structure

```
screensharing.me/
│
├── apps/
│   ├── website/
│   │   ├── prisma/                  # Database schema and migrations
│   │   ├── scripts/                 # Database and setup scripts
│   │   ├── src/
│   │   │   ├── app/                 # Pages, dashboard and API
│   │   │   │   └── api/             # API route handlers
│   │   │   └── lib/                 # Authentication, PINs, reports, etc.
│   │   └── tests/
│   │       └── unit/                # Vitest unit tests
│   │
│   └── desktop/
│       ├── src/
│       │   ├── Screensharing.Scanner/
│       │   │                            # Forensic scanning engine
│       │   └── Screensharing.Desktop/
│       │                                # WPF desktop application
│       │
│       └── tests/
│           ├── Screensharing.Scanner.Tests/
│           └── Screensharing.Desktop.Tests/
│
├── packages/
│   ├── detection-rules/
│   │   ├── signatures/              # Categorized detection rules
│   │   ├── build-rules.mjs          # Rule authoring and generation
│   │   └── rules.json               # Generated detection catalog
│   │
│   └── shared-types/                # Shared design tokens and contracts
│
├── tests/
│   └── e2e/                         # API end-to-end tests
│
├── scripts/
│   ├── build-desktop.ps1            # Windows EXE build
│   ├── gen-catalog.mjs              # Detection catalog generation
│   └── unbundle.py                  # Development helper
│
├── documentation/
│   ├── screenshots/
│   │   └── desktop/
│   ├── DEPLOYMENT.md
│   └── TESTING.md
│
├── ARCHITECTURE.md
├── RESEARCH.md
├── DETECTION_CATALOG.md
├── SECURITY.md
└── README.md
```

---

## 🚀 Getting Started

### 📋 Prerequisites

Before running the project locally, make sure you have:

| Requirement | Version |
|---|---|
| Node.js | 20+ (tested with 24) |
| npm | Included with Node.js |
| .NET SDK | 10.0+ |
| PostgreSQL | 14+ for production |

Development uses an embedded PostgreSQL server through `embedded-postgres`, so a separate PostgreSQL installation is not required for the standard local development workflow.

### 1. Clone the Repository

```bash
git clone https://github.com/freakygav/screensharing.me.git
cd screensharing.me
```

### 2. Install Website Dependencies

```bash
cd apps/website
npm install
```

### 3. Configure Environment Variables

Copy the example environment file:

```bash
cp .env.example .env
```

Configure the following values in `.env`:

```env
DATABASE_URL="postgresql://ssme:ssme_dev_pw@127.0.0.1:5433/screensharing"

APP_SECRET="YOUR_RANDOM_SECRET"
APP_ORIGIN="http://localhost:3000"

ADMIN_BOOTSTRAP_EMAIL="admin@example.com"
ADMIN_BOOTSTRAP_USERNAME="admin"
ADMIN_BOOTSTRAP_PASSWORD="YOUR_SECURE_PASSWORD"
```

Generate a random application secret:

```bash
node -e "console.log(require('crypto').randomBytes(32).toString('base64url'))"
```

Use unique, secure credentials for your local environment.

### 4. Start the Development Database

```bash
npm run db:start
```

This starts the embedded PostgreSQL development database on port 5433.

### 5. Apply Database Migrations

```bash
npx prisma migrate deploy
```

### 6. Seed the Database

```bash
npm run db:seed
```

The seed process:

- Loads the detection catalog.
- Registers application version 1.0.0.
- Creates the initial administrator account.

### 7. Start the Website

```bash
npm run dev
```

Open:

`http://localhost:3000`

The website and backend API run together through the Next.js application.

---

## 👑 Administrator Setup

The initial administrator is created through the database seed process.

The following environment variables are used:

| Variable | Purpose |
|---|---|
| `ADMIN_BOOTSTRAP_EMAIL` | Administrator email |
| `ADMIN_BOOTSTRAP_USERNAME` | Administrator username |
| `ADMIN_BOOTSTRAP_PASSWORD` | Initial password |
| `ADMIN_BOOTSTRAP_FORCE_RESET` | Optional forced password reset |

The administrator password is hashed using Argon2id.

Existing administrator passwords are not overwritten unless:

```env
ADMIN_BOOTSTRAP_FORCE_RESET=1
```

Sign in through:

- Website: `/admin/login`
- Desktop: **Admin** in the application title bar.

After initial setup, remove the bootstrap password from the environment and change the password through Account settings.

See [SECURITY.md](SECURITY.md) for additional security information.

---

## 💾 Building the Windows Executable

The desktop application can be built using the included PowerShell script.

From the repository root:

```powershell
powershell -ExecutionPolicy Bypass -File scripts/build-desktop.ps1
```

The build produces:

```
artifacts/
└── desktop/
    └── screensharing.me.exe
```

The executable is published as a self-contained Windows x64 application.

The build script also:

- Publishes the desktop application.
- Calculates its SHA-256 hash.
- Copies the executable into the website's public download directory.

To specify a production server URL and application version:

```powershell
powershell -ExecutionPolicy Bypass -File scripts/build-desktop.ps1 -ServerUrl "https://screensharing-me-azure.vercel.app" -Version "1.0.1"
```

The server URL is a configurable default and can be changed through application settings.

No server secrets are embedded in the executable.

---

## 🎮 How to Use

### 1. Create an Investigation

Visit the [screensharing.me website](https://screensharing-me-azure.vercel.app/) and sign in.

Navigate to **New Investigation** to generate a unique investigation PIN.

Example:

```
483-921
```

### 2. Connect the Minecraft Player

The player:

1. Starts Minecraft.
2. Opens `screensharing.me.exe`.
3. Selects **I have an investigation PIN**.
4. Enters the provided PIN.
5. Reviews the identified Minecraft instance.
6. Selects an instance if multiple are running.
7. Reviews and grants consent.

### 3. Begin the Scan

Once connected and consent has been granted, the player selects **Begin Scan**.

The desktop application begins examining the selected Minecraft instance.

### 4. Monitor the Investigation

The investigator can monitor the scan through the website in real time.

Live information includes:

- Minecraft instance information.
- Current scan stage.
- File inspection progress.
- Detection findings.
- Inspection limitations.
- Scan completion status.

### 5. Review the Results

Once the scan finishes, the investigator can access the final report.

Reports include the investigation verdict, detection classifications, supporting evidence, file hashes, inspection limitations, instance inventory, and chain-of-custody information.

Reports can be exported in PDF, JSON, and CSV formats.

---

## 🧪 Testing & Reliability

The project includes automated tests covering the website, backend, scanner engine, and desktop application.

Latest recorded test results:

| Test Suite | Results |
|---|---:|
| Website Unit Tests | ✅ 21 / 21 |
| API Integration Tests | ✅ 18 / 18 |
| Scanner Engine Tests | ✅ 57 / 57 |
| Desktop E2E Tests | ✅ 4 / 4 |
| Live Minecraft Instance Test | ✅ Passed |
| Production Build | ✅ Successful |

**Live Minecraft instance test:**

- Identified a running Modrinth Minecraft instance.
- Examined 1,295 instance files.
- Completed in approximately 13 seconds.
- Recorded 0 scan-scope violations.

### Running Tests

**Website unit tests:**

```bash
cd apps/website
npm test
```

**API end-to-end tests:**

```bash
SSME_ADMIN_PASSWORD=YOUR_PASSWORD node --test tests/e2e/api-flow.test.mjs
```

**Scanner tests:**

```bash
dotnet test apps/desktop/tests/Screensharing.Scanner.Tests
```

**Live Minecraft instance test (opt-in):**

```bash
SSME_LIVE_INSTANCE=1 dotnet test apps/desktop/tests/Screensharing.Scanner.Tests --filter Running_instance
```

**Desktop end-to-end tests:**

```bash
SSME_E2E_FULL=1 dotnet test apps/desktop/tests/Screensharing.Desktop.Tests
```

**Production website build:**

```bash
cd apps/website
npx next build
```

For additional testing information and false-positive measurements, see [documentation/TESTING.md](documentation/TESTING.md).

---

## ☁️ Deployment

The production website is hosted on Vercel.

| Component | Service |
|---|---|
| Website | Vercel |
| Framework | Next.js 16 |
| Root Directory | `apps/website` |
| Database | Neon PostgreSQL |
| Database Hosting | Vercel Marketplace |
| Desktop Executable | Vercel Blob |
| Deployment Branch | `main` |

The Vercel project is configured to automatically deploy when changes are pushed to the `main` branch.

**Important:** Preview deployments currently share the production database. Exercise caution when testing database mutations in preview environments.

For complete deployment instructions, see [documentation/DEPLOYMENT.md](documentation/DEPLOYMENT.md).

---

## 🚧 Development Status

### ✅ Implemented

- User registration and authentication.
- Username and email login.
- Email verification.
- Password reset and administrator-issued reset links.
- Argon2id password hashing.
- Rate limiting and CSRF/Origin protection.
- PIN creation, expiration, and single-use protection.
- Desktop connection and consent workflow.
- Instance identification and selection.
- Instance-specific forensic scanning.
- String and signature-based detection.
- Evidence scoring and classifications.
- Desktop-to-server evidence upload.
- Reconnection handling.
- Real-time SSE updates.
- Detailed investigation findings.
- File hashes and inspection limitations.
- Integrity manifests and chain of custody.
- PDF, JSON, and CSV reports.
- Investigator dashboard.
- Administrative console.
- User, session, and device management.
- Detection catalog editing.
- Application version management.
- Audit logs and configuration management.
- Desktop administrative and staff console.
- Settings and application information.
- Self-contained Windows executable.

### 🔬 Areas Requiring Further Development

Some detection capabilities require additional research, verification, or real-world testing.

- SHA-256 fingerprints for specific cheat releases.
- Verified identifiers for closed-source clients.
- Additional verification of Aristois, Impact, RusherHack, Future, and ThunderHack identifiers.
- Memory detection against a real cheat-loaded JVM.
- Real-machine testing for Forge and NeoForge.
- Real-machine testing for Lunar Client launches.
- Authenticode signing of the Windows executable.
- Automatic desktop application updates.
- Production SMTP delivery testing.

The absence of a known signature does not prove that a Minecraft installation is cheat-free. Detection results must always be interpreted alongside their supporting evidence and inspection coverage.

---

## 📚 Documentation

Additional technical documentation is available in the repository.

| Document | Description |
|---|---|
| [ARCHITECTURE.md](ARCHITECTURE.md) | Project architecture and component design |
| [RESEARCH.md](RESEARCH.md) | Detection research and technical findings |
| [DETECTION_CATALOG.md](DETECTION_CATALOG.md) | Detection signatures and categories |
| [SECURITY.md](SECURITY.md) | Security considerations and implementation |
| [TESTING.md](documentation/TESTING.md) | Testing procedures and results |
| [DEPLOYMENT.md](documentation/DEPLOYMENT.md) | Production deployment instructions |

---

## 🎯 Project Goals

The goal of screensharing.me is to provide a reliable, transparent, and evidence-driven Minecraft forensic investigation platform.

The project focuses on:

1. Accurate Minecraft instance identification.
2. Strictly scoped, consent-based scanning.
3. Reliable cheat and modification detection.
4. Detailed evidence collection.
5. Real-time investigation monitoring.
6. Clear and understandable forensic reports.
7. Secure communication between the desktop client and backend.
8. An extensible detection engine that can grow over time.

Every component is designed to work together as one cohesive investigation platform.

---

## 🤝 Contributing

Suggestions, bug reports, and improvements are welcome.

If you encounter an issue or have an idea for a new feature, feel free to open an issue or submit a pull request.

When reporting bugs, include:

- A description of the issue.
- Steps to reproduce it.
- Expected behavior.
- Actual behavior.
- Relevant logs or error messages.
- Screenshots when applicable.

Contributions to detection research should include reproducible evidence and enough context to validate the proposed detection.

---

## 📜 License

Please refer to the repository's license files and individual dependency licenses for licensing information.

Third-party dependencies may have their own distribution and licensing requirements.

---

<p align="center">
  <strong>🔍 screensharing.me</strong>
  <br />
  Minecraft Forensic Investigation Platform
  <br /><br />
  <a href="https://screensharing-me-azure.vercel.app/">Website</a>
  ·
  <a href="https://github.com/freakygav/screensharing.me">GitHub Repository</a>
  <br /><br />
  Built for transparent, evidence-driven Minecraft investigations.
</p>
