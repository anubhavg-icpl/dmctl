# DManagement (dmctl)

A Swift-based CLI tool for macOS Device Management using **native macOS APIs** - query MDM status, manage profiles, and interact with MDM servers like NanoMDM.

## Features

### Local Device Management (Native APIs)
- **MDM Status** - Check enrollment via `IOKit` and system plists
- **Device Information** - Query via `IOKit` (`IOPlatformExpertDevice`)
- **Security Info** - Check via `IOKit NVRAM`, `Security.framework`
- **Certificates** - List via `Security.framework` (`SecItemCopyMatching`)
- **Profiles** - Read directly from `/var/db/ConfigurationProfiles/`

### MDM Server Interaction (Apple MDM Protocol)
- **Connect** to NanoMDM/MicroMDM servers
- **Enqueue** MDM commands to devices
- **Push** APNs notifications to wake devices
- **Generate** MDM command plists

## Installation

```bash
cd DManagement
swift build -c release
cp .build/release/dmctl /usr/local/bin/
```

## Usage

### Local Device Queries (Native APIs)

```bash
# Check MDM enrollment status
dmctl status

# Get device info (via IOKit)
dmctl device info

# Security settings (via IOKit NVRAM, Security.framework)
dmctl device security

# List certificates (via Security.framework)
dmctl device certificates

# List configuration profiles
dmctl profiles list
```

### MDM Server Interaction

```bash
# Connect to MDM server
dmctl server connect --url https://mdm.example.com --api-key SECRET

# Get server version
dmctl server version --url https://mdm.example.com

# Queue DeviceInformation command
dmctl server enqueue \
  --url https://mdm.example.com \
  --api-key SECRET \
  DEVICE-UDID \
  DeviceInformation

# Send push to wake device
dmctl server push \
  --url https://mdm.example.com \
  --api-key SECRET \
  DEVICE-UDID
```

### Generate MDM Commands

```bash
# Generate ProfileList command
dmctl generate command ProfileList

# Generate with custom UUID
dmctl generate command DeviceInformation --uuid custom-uuid-here

# Save to file
dmctl generate command SecurityInfo --output cmd.plist
```

### Generate Configuration Profiles

```bash
# WiFi profile template
dmctl generate profile wifi --identifier com.company.wifi

# VPN profile template  
dmctl generate profile vpn --output vpn.mobileconfig

# Restrictions profile
dmctl generate profile restrictions --organization "My Company"
```

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         dmctl CLI                               │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌──────────────────────────────┐  ┌──────────────────────────┐│
│  │   Local Device Queries       │  │   MDM Server Client      ││
│  │   (Native macOS APIs)        │  │   (HTTP + Binary Plist)  ││
│  └──────────────────────────────┘  └──────────────────────────┘│
│              │                                │                 │
│              ▼                                ▼                 │
│  ┌──────────────────────────────┐  ┌──────────────────────────┐│
│  │  • IOKit (device info)       │  │  • /v1/enqueue/ (queue)  ││
│  │  • Security.framework        │  │  • /v1/push/ (APNs)      ││
│  │  • Plist reading             │  │  • /mdm (check-in)       ││
│  │  • NVRAM access              │  │  • Binary plist protocol ││
│  └──────────────────────────────┘  └──────────────────────────┘│
│              │                                │                 │
│              ▼                                ▼                 │
│         macOS System                    NanoMDM Server          │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

## Native APIs Used

| Feature | API |
|---------|-----|
| Device UDID | `IOKit` - `kIOPlatformUUIDKey` |
| Serial Number | `IOKit` - `kIOPlatformSerialNumberKey` |
| Model | `IOKit` - `IOPlatformExpertDevice` |
| OS Version | `ProcessInfo.operatingSystemVersion` |
| Certificates | `Security.framework` - `SecItemCopyMatching` |
| SIP Status | `IOKit NVRAM` - `csr-active-config` |
| Secure Boot | `IOKit NVRAM` - `AppleSecureBootPolicy` |
| Find My Mac | `IOKit NVRAM` - `fmm-mobileme-token-FMM` |
| Firewall | Plist - `/Library/Preferences/com.apple.alf.plist` |
| MDM Enrollment | Plist - `/var/db/ConfigurationProfiles/` |

## MDM Protocol

The CLI speaks Apple's MDM protocol using binary plists:

```
Device → Server:
  Content-Type: application/x-apple-aspen-mdm-checkin
  Body: Binary plist (Authenticate, TokenUpdate, CheckOut)

Server → Device:
  Body: Binary plist (Command with RequestType)

API:
  PUT /v1/enqueue/{id} - Queue command
  GET /v1/push/{id}    - Send APNs push
```

## Supported Commands

`DeviceInformation`, `ProfileList`, `SecurityInfo`, `CertificateList`,
`InstalledApplicationList`, `DeviceLock`, `EraseDevice`, `RestartDevice`,
`ShutDownDevice`, `ScheduleOSUpdate`, `InstallProfile`, `RemoveProfile`,
`EnableRemoteDesktop`, `DisableRemoteDesktop`, and more.

## Requirements

- macOS 13.0+ (Ventura)
- Swift 5.9+
- Some features require root/admin access

## License

MIT
# dmctl
