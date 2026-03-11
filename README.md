# Innova Analyzer 🛡️

**Innova Analyzer** is a powerful Android application designed to provide comprehensive local network traffic interception, logging, and threat analysis. Through the power of a local on-device VPN, it inspects every packet flowing in and out of your device without ever routing data to a remote server. This ensures complete privacy and total control over your device's network activity.

---

## 🚀 Key Features

*   **Local Traffic Interception:** Uses Android's `VpnService` to capture all device traffic transparently, locally on the device.
*   **Deep Packet Inspection:** Extracts critical metadata like target IPs, HTTP/SNI domains, and DNS queries automatically from IPv4, TCP, and UDP packets.
*   **Real-time Threat Detection:** Flags and blocks known aggressive trackers, analytics nodes, and malicious endpoints as well as periodically performs background anomaly detection.
*   **Comprehensive Data Storage:** Safely persists all intercepted logs in a local Room Database to be audited later.
*   **Interactive Modern UI:** Uses Jetpack Compose and Material 3 to deliver a visually stunning, glassy, dark/light mode toggleable interface. Real-time charts powered by the `Vico` graph library provide instant insights.
*   **Detailed PDF Forensic Reports:** Export complete technical breakdowns of your network to your local storage for external audits or offline analysis, formatted exactly like PCAP hex dumps.
*   **Background Anomaly Analysis:** Automates periodic checks via Android's WorkManager to actively surveil long-term active threats.

---

## 🏗️ Technical Architecture

### 1. `core.vpn` (Network Root layer)
The `TrafficCaptureService` binds to the system as a local VPN. Traffic routed through this interface is grabbed securely at the IP layer.

### 2. `core.network` (Parsing Logic)
Raw byte buffers are passed to the `PacketParser`, which manually reads IPv4 headers to isolate the payload. 
*   **TCP**: Extracts the SNI domain via `TlsSniExtractor`.
*   **UDP**: Plucks plain text domains directly from outgoing DNS packets.
A specialized brute-force threat checker operates concurrently at this layer to block trackers almost instantly.

### 3. `core.threats & core.export` (Analysis & Forensic)
`BaselineAnalysisWorker` is triggered by `WorkManager` periodically to run anomaly detection models on the database. If necessary, user requests trigger the `PdfExporter`, generating a detailed PDF mapping exactly what each application did over the wire.

### 4. `data.local` (Local Persistence)
Backed by an asynchronous `Room` database. Real-time Coroutine Flows push state out to the Compose UI instantly as new records appear.

### 5. `ui` (Jetpack Compose View layer)
Follows modern MVVM architectures.
*   **DashboardScreen**: Displays live statistical updates and a smooth time-series chart showing traffic surges.
*   **ReportScreen**: An interactive list of all network events natively lazy-loaded for massive data sets.
*   **AlertsScreen**: Focused exclusively on anomalies and blocked connections to keep users informed of threats.

---

## ⚙️ Tech Stack & Dependencies

*   **Language:** Kotlin
*   **Framework:** Android SDK (Min 24, Target 34)
*   **UI Toolkit:** Jetpack Compose Core/Material 3/Tooling
*   **Navigation:** Compose Navigation
*   **Local Storage:** Room Database (`androidx.room`)
*   **Asynchrony/State:** Kotlin Coroutines & Flow
*   **Background Jobs:** WorkManager (`androidx.work`)
*   **Charting:** Vico Compose Graph Library
*   **PDF Generation:** Built-in Android `PdfDocument` API
*   **Networking:** OkHttp

---

## 🏃 Getting Started

### Prerequisites
*   Android Studio Ladybug (or newer).
*   Java Development Kit (JDK 11+).
*   An Android Device or API 24+ Emulator.

### Setup and Build
1. Clone the repository and open it in Android Studio.
2. Allow Gradle to synchronize dependencies.
3. Once synchronized, you can run the app directly on your emulator or physical device.

### Usage
1. Open the app and grant **Notification Permissions** to receive threat alerts.
2. Tap "Start Interception" on the prompt or Dashboard to initiate the local VPN. **Grant OS VPN permission** when prompted.
3. Observe traffic appear instantaneously on the Dashboard graph as other apps sync in the background.
4. Go to **Reports** and generate a forensics PDF to get a raw dump of telemetry to the device's "Downloads" folder.

---

## 🛡️ Privacy and Safety Declaration

Innova Analyzer utilizes the powerful `BIND_VPN_SERVICE` permission. **No remote tunnel is created**. All calculations, log persistence, and packet analysis processes exist **completely locally, offline, on your physical hardware**. We believe observability shouldn't mandate sacrificing your data rights.

## 📄 License
This application is provided strictly "As-Is". Built enthusiastically for security hacking and system observability. Use responsibly!
