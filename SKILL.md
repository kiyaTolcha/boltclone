# BOLTCLONE Chrome Extension Skill

## Overview

BOLTCLONE is a Chrome extension that captures HTTP/HTTPS traffic, analyzes API calls, and generates OpenAPI specifications. It functions as an API security and documentation tool inspired by APIsec's BOLT technology, enabling developers to discover APIs in real-time and export structured API definitions.

## Project Type

Chrome Extension (Manifest V3)

## Architecture

### Core Components

1. **Background Service Worker** (`background.js`)
   - Primary logic hub for traffic capture and analysis
   - Manages storage of captured traffic and API definitions
   - Handles periodic scanning via Chrome alarms
   - Orchestrates analysis and OpenAPI generation

2. **Content Scripts** (`content.js`)
   - Injected into all web pages (`<all_urls>`)
   - Captures HTTP requests/responses at the page level
   - Communicates with background worker via messaging

3. **DevTools Integration** (`devtools.html`, `panel.html`)
   - Dedicated DevTools panel for advanced network analysis
   - Deep integration with Chrome's network monitoring
   - Enhanced traffic inspection capabilities

4. **Popup UI** (`popup.html`, `popup.js`)
   - Main user interface for extension controls
   - Configuration options (capture modes, proxy settings)
   - Results display and export functionality

5. **Analysis Modules**
   - `rules.js` - Traffic filtering and rule-based analysis logic
   - `openapi.js` - OpenAPI specification generation from captured APIs
   - `style.css` - UI styling

## Key Features

### Capture Modes
- **API Mode**: Captures only API-related traffic
- **All Mode**: Captures all network traffic for comprehensive analysis

### Configuration Options
- **Target URL**: Specify target endpoints for focused capture
- **Proxy Settings**: Optional proxy configuration for traffic routing
- **Scan Scope**: Choose between current tab or all tabs
- **Proxy Routing**: Route all traffic through specified proxy

### Analysis Capabilities
- Real-time API discovery from network traffic
- Discovery list with UI display (max 300 discovered APIs)
- Periodic automated scanning via alarms
- Traffic statistics and history tracking
- Analysis results export

### Export Functions
- Analysis results export
- OpenAPI specification generation and export

## Data Storage

- **Chrome Storage API** (`chrome.storage.local`)
- **Storage Keys**:
  - `boltcloneCaptureMode` - Current capture mode setting
  - `boltcloneTraffic` - Array of captured network events
  - `discoveredApis` - Discovered API endpoints
  - Other configuration and state data

## Permissions & Capabilities

```json
Permissions: storage, tabs, webRequest, activeTab, scripting, alarms
Host Permissions: <all_urls>
```

- Can access and monitor traffic on any website
- Can execute scripts in web pages
- Can create and manage alarms for scheduled tasks
- Can read/write to local storage

## File Structure

```
chrome-extension/
├── manifest.json          # Extension configuration and metadata
├── background.js          # Service worker (main logic)
├── content.js            # Content script for web pages
├── popup.html            # Popup UI markup
├── popup.js              # Popup UI logic and event handlers
├── devtools.html         # DevTools panel
├── panel.html            # DevTools panel content
├── rules.js              # Traffic analysis rules and filtering
├── openapi.js            # OpenAPI generation logic
└── style.css             # UI styling
```

## Development Notes

### Module Loading
- Uses `importScripts()` in background worker to load `rules.js` and `openapi.js`
- Service Worker environment restricts dynamic imports

### Key Constants
- `DISCOVERED_API_KEY = 'discoveredApis'` - Storage key for discovered APIs
- `MAX_DISCOVERED = 300` - Maximum number of APIs to store
- `STATS_KEY = 'boltcloneTraffic'` - Storage key for traffic stats

### Capture Flow
1. Content scripts detect network activity
2. Data sent to background worker
3. Rules engine filters/classifies traffic
4. Results stored in Chrome storage
5. UI updates discovery list and history
6. User can export as analysis or OpenAPI spec

### Scheduled Scanning
- Periodic scan alarm runs every 0.25 minutes (15 seconds)
- Can be started/stopped via UI controls
- Analyzes captured traffic automatically

## UI Elements

- **Tab Navigation**: Capture, Discovery, History pages
- **Severity Color Coding**: Critical (#ff5c64), High (#ff9f43), Medium (#ffd166), Low (#69d0a3)
- **Discovery List**: Displays discovered APIs with refresh capability
- **History Tracking**: Records past analysis and captures
- **Export Controls**: Separate buttons for analysis and OpenAPI exports

## Use Cases

1. **API Documentation** - Auto-generate OpenAPI specs from captured traffic
2. **Security Analysis** - Analyze API endpoints for security issues
3. **API Discovery** - Discover undocumented APIs during web browsing
4. **Traffic Analysis** - Monitor and inspect HTTP/HTTPS requests
5. **Development** - Aid in understanding third-party API integrations

## Extension Installation

1. Load extension via Chrome's Developer Mode
2. Enable "Developer mode" in chrome://extensions
3. Click "Load unpacked" and select the chrome-extension folder
4. Extension will appear in the toolbar

## Configuration

Users can configure:
- Capture mode (API vs All traffic)
- Target URL filtering
- Proxy settings
- Scan scope (current tab vs all tabs)
- Background scanning intervals

## Related Technologies

- Chrome Extensions Manifest V3
- Chrome Storage API
- Chrome Alarms API
- OpenAPI 3.0 Specification
- HTTP/HTTPS Protocol Analysis
