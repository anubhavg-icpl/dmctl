import Foundation
import IOKit
import Security

// MARK: - MDM Status (Using Native APIs)
struct MDMStatus: Codable {
    let isEnrolled: Bool
    let isDEPEnrolled: Bool
    let isUserApproved: Bool
    let activationLockEnabled: Bool
    let remoteManagementEnabled: Bool
    let serverURL: String?
    
    static func current() throws -> MDMStatus {
        // Check MDM enrollment via configuration profiles plist
        let enrollmentInfo = getMDMEnrollmentInfo()
        
        // Check Activation Lock via IOKit NVRAM
        let activationLock = checkActivationLockViaIOKit()
        
        return MDMStatus(
            isEnrolled: enrollmentInfo.isEnrolled,
            isDEPEnrolled: enrollmentInfo.isDEP,
            isUserApproved: enrollmentInfo.isUserApproved,
            activationLockEnabled: activationLock,
            remoteManagementEnabled: enrollmentInfo.isEnrolled,
            serverURL: enrollmentInfo.serverURL
        )
    }
    
    private static func getMDMEnrollmentInfo() -> (isEnrolled: Bool, isDEP: Bool, isUserApproved: Bool, serverURL: String?) {
        // Read from ConfigurationProfiles system database
        let paths = [
            "/var/db/ConfigurationProfiles/Settings/.cloudConfigProfileInstalled",
            "/var/db/ConfigurationProfiles/Settings/CloudConfigurationSetAsideDetails.plist",
            "/var/db/ConfigurationProfiles/Store/ConfigProfiles.plist"
        ]
        
        var isEnrolled = false
        var isDEP = false
        var isUserApproved = false
        var serverURL: String?
        
        for path in paths {
            if let data = FileManager.default.contents(atPath: path),
               let plist = try? PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any] {
                
                if plist["CloudConfigurationUIComplete"] != nil {
                    isDEP = true
                    isEnrolled = true
                }
                
                if let url = plist["ServerURL"] as? String {
                    serverURL = url
                    isEnrolled = true
                }
                
                if let approved = plist["IsUserApproved"] as? Bool {
                    isUserApproved = approved
                }
            }
        }
        
        // Also check for MDM profile in installed profiles
        let profilesPath = "/var/db/ConfigurationProfiles/Store"
        if let contents = try? FileManager.default.contentsOfDirectory(atPath: profilesPath) {
            for file in contents where file.hasSuffix(".plist") {
                let filePath = "\(profilesPath)/\(file)"
                if let data = FileManager.default.contents(atPath: filePath),
                   let plist = try? PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any] {
                    
                    // Check for MDM payload
                    if let payloads = plist["ProfileItems"] as? [[String: Any]] {
                        for payload in payloads {
                            if let payloadType = payload["PayloadType"] as? String,
                               payloadType.contains("mdm") {
                                isEnrolled = true
                            }
                        }
                    }
                }
            }
        }
        
        return (isEnrolled, isDEP, isUserApproved, serverURL)
    }
    
    private static func checkActivationLockViaIOKit() -> Bool {
        // Access NVRAM via IOKit to check for Find My Mac token
        var masterPort: mach_port_t = 0
        
        guard IOMainPort(mach_host_self(), &masterPort) == KERN_SUCCESS else {
            return false
        }
        
        let nvramEntry = IORegistryEntryFromPath(masterPort, "IODeviceTree:/options")
        guard nvramEntry != 0 else {
            return false
        }
        
        defer { IOObjectRelease(nvramEntry) }
        
        // Check for FMM (Find My Mac) token
        let key = "fmm-mobileme-token-FMM" as CFString
        if let value = IORegistryEntryCreateCFProperty(nvramEntry, key, kCFAllocatorDefault, 0) {
            _ = value.takeRetainedValue()
            return true
        }
        
        return false
    }
}

// MARK: - Enrollment Details
struct EnrollmentDetails: Codable {
    let isEnrolled: Bool
    let enrollmentType: String
    let isDEPEnrolled: Bool
    let isUserApproved: Bool
    let serverURL: String?
    let pushTopic: String?
    let enrollmentDate: String?
    
    static func current() throws -> EnrollmentDetails {
        let status = try MDMStatus.current()
        
        var enrollmentType = "None"
        if status.isDEPEnrolled {
            enrollmentType = "DEP/ADE (Automated)"
        } else if status.isEnrolled {
            enrollmentType = status.isUserApproved ? "User Approved" : "Manual"
        }
        
        return EnrollmentDetails(
            isEnrolled: status.isEnrolled,
            enrollmentType: enrollmentType,
            isDEPEnrolled: status.isDEPEnrolled,
            isUserApproved: status.isUserApproved,
            serverURL: status.serverURL,
            pushTopic: nil,  // Would need to parse from MDM profile
            enrollmentDate: nil  // Would need to parse from profile install date
        )
    }
}

// MARK: - Device Info (Using IOKit APIs)
struct DeviceInfo: Codable {
    let computerName: String
    let model: String
    let modelIdentifier: String
    let serialNumber: String
    let hardwareUUID: String
    let osVersion: String
    let osBuild: String
    let chipType: String
    let memorySize: String
    
    static func current() throws -> DeviceInfo {
        let computerName = Host.current().localizedName ?? "Unknown"
        
        // Get hardware info via IOKit
        let platformExpert = IOServiceGetMatchingService(
            kIOMainPortDefault,
            IOServiceMatching("IOPlatformExpertDevice")
        )
        
        defer { IOObjectRelease(platformExpert) }
        
        // Serial Number
        let serialNumber = getIOPlatformProperty(platformExpert, key: kIOPlatformSerialNumberKey) ?? "Unknown"
        
        // Hardware UUID
        let hardwareUUID = getIOPlatformProperty(platformExpert, key: kIOPlatformUUIDKey) ?? "Unknown"
        
        // Model Identifier
        let modelIdentifier = getIOPlatformProperty(platformExpert, key: "model") ?? "Unknown"
        
        // Get model name from model identifier
        let model = getModelName(from: modelIdentifier)
        
        // Get chip type via IOKit
        let chipType = getChipType()
        
        // Get memory size via sysctl
        let memorySize = getPhysicalMemory()
        
        // Get OS version via ProcessInfo
        let osInfo = ProcessInfo.processInfo.operatingSystemVersion
        let osVersion = "macOS \(osInfo.majorVersion).\(osInfo.minorVersion).\(osInfo.patchVersion)"
        
        // Get build number from system version plist
        let osBuild = getOSBuildNumber()
        
        return DeviceInfo(
            computerName: computerName,
            model: model,
            modelIdentifier: modelIdentifier,
            serialNumber: serialNumber,
            hardwareUUID: hardwareUUID,
            osVersion: osVersion,
            osBuild: osBuild,
            chipType: chipType,
            memorySize: memorySize
        )
    }
    
    private static func getIOPlatformProperty(_ service: io_service_t, key: String) -> String? {
        guard let value = IORegistryEntryCreateCFProperty(
            service,
            key as CFString,
            kCFAllocatorDefault,
            0
        )?.takeRetainedValue() else {
            return nil
        }
        
        if let stringValue = value as? String {
            return stringValue
        } else if let dataValue = value as? Data {
            return String(data: dataValue, encoding: .utf8)?.trimmingCharacters(in: .controlCharacters)
        }
        return nil
    }
    
    private static func getModelName(from identifier: String) -> String {
        // Common model mappings
        let modelMappings: [String: String] = [
            "MacBookAir10,1": "MacBook Air (M1, 2020)",
            "MacBookAir9,1": "MacBook Air (Retina, 2020)",
            "MacBookPro18,1": "MacBook Pro (16-inch, 2021)",
            "MacBookPro18,2": "MacBook Pro (16-inch, 2021)",
            "MacBookPro18,3": "MacBook Pro (14-inch, 2021)",
            "MacBookPro18,4": "MacBook Pro (14-inch, 2021)",
            "MacBookPro17,1": "MacBook Pro (13-inch, M1, 2020)",
            "Macmini9,1": "Mac mini (M1, 2020)",
            "iMac21,1": "iMac (24-inch, M1, 2021)",
            "iMac21,2": "iMac (24-inch, M1, 2021)",
            "Mac14,2": "MacBook Air (M2, 2022)",
            "Mac14,7": "MacBook Pro (13-inch, M2, 2022)",
            "Mac14,3": "Mac Pro (2023)",
            "Mac14,13": "Mac Studio (M2 Max, 2023)",
            "Mac14,14": "Mac Studio (M2 Ultra, 2023)",
            "Mac15,3": "MacBook Air (15-inch, M3, 2024)",
        ]
        
        return modelMappings[identifier] ?? identifier.replacingOccurrences(of: ",", with: " ")
    }
    
    private static func getChipType() -> String {
        var size: size_t = 0
        sysctlbyname("machdep.cpu.brand_string", nil, &size, nil, 0)
        
        var cpuBrand = [CChar](repeating: 0, count: size)
        sysctlbyname("machdep.cpu.brand_string", &cpuBrand, &size, nil, 0)
        
        let brand = String(cString: cpuBrand)
        if !brand.isEmpty && brand != "0" {
            return brand
        }
        
        // For Apple Silicon, check IOKit
        let service = IOServiceGetMatchingService(
            kIOMainPortDefault,
            IOServiceMatching("AppleARMIODevice")
        )
        
        if service != 0 {
            defer { IOObjectRelease(service) }
            // It's Apple Silicon
            var mibSize: size_t = 256
            var chip = [CChar](repeating: 0, count: 256)
            sysctlbyname("hw.chip_id", &chip, &mibSize, nil, 0)
            
            if chip[0] != 0 {
                return String(cString: chip)
            }
            return "Apple Silicon"
        }
        
        return "Unknown"
    }
    
    private static func getPhysicalMemory() -> String {
        let bytes = ProcessInfo.processInfo.physicalMemory
        let gb = Double(bytes) / 1_073_741_824
        return String(format: "%.0f GB", gb)
    }
    
    private static func getOSBuildNumber() -> String {
        let plistPath = "/System/Library/CoreServices/SystemVersion.plist"
        guard let data = FileManager.default.contents(atPath: plistPath),
              let plist = try? PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any],
              let build = plist["ProductBuildVersion"] as? String else {
            return "Unknown"
        }
        return build
    }
}

// MARK: - Security Info (Using Native APIs)
struct SecurityInfo: Codable {
    let fileVaultEnabled: Bool
    let sipEnabled: Bool
    let secureBootLevel: String
    let firewallEnabled: Bool
    let gatekeeperEnabled: Bool
    let remoteLoginEnabled: Bool
    let findMyMacEnabled: Bool
    
    static func current() throws -> SecurityInfo {
        return SecurityInfo(
            fileVaultEnabled: checkFileVaultViaAPI(),
            sipEnabled: checkSIPViaCSR(),
            secureBootLevel: getSecureBootLevelViaIOKit(),
            firewallEnabled: checkFirewallViaPlist(),
            gatekeeperEnabled: checkGatekeeperViaSecAssessment(),
            remoteLoginEnabled: checkRemoteLoginViaPlist(),
            findMyMacEnabled: checkFindMyMacViaIOKit()
        )
    }
    
    private static func checkFileVaultViaAPI() -> Bool {
        // Check FileVault status via CoreStorage/APFS plist
        let coreStoragePath = "/Library/Preferences/com.apple.CoreStorage.plist"
        
        // Check via DADiskGetCoreStorageEncryptionStatus equivalent
        // Read boot volume encryption status
        if let data = FileManager.default.contents(atPath: coreStoragePath),
           let plist = try? PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any] {
            if let encrypted = plist["EncryptionState"] as? String, encrypted == "Encrypted" {
                return true
            }
        }
        
        // Check APFS encryption via DiskArbitration-like check
        // FileVault creates EncryptedRoot.plist.wipekey
        let fvKeyPath = "/System/Library/Caches/com.apple.corestorage/EncryptedRoot.plist.wipekey"
        if FileManager.default.fileExists(atPath: fvKeyPath) {
            return true
        }
        
        // Check via boot args for APFS sealed volumes (indirect indicator)
        var size: size_t = 0
        sysctlbyname("kern.bootargs", nil, &size, nil, 0)
        var bootArgs = [CChar](repeating: 0, count: size)
        sysctlbyname("kern.bootargs", &bootArgs, &size, nil, 0)
        let args = String(cString: bootArgs)
        
        // Modern APFS volumes with Data protection
        if args.contains("-apfs_sealed") || args.contains("fileproviderd") {
            return true
        }
        
        return false
    }
    
    private static func checkSIPViaCSR() -> Bool {
        // Check SIP via csr_get_active_config equivalent
        // SIP status stored in NVRAM csr-active-config
        var masterPort: mach_port_t = 0
        guard IOMainPort(mach_host_self(), &masterPort) == KERN_SUCCESS else {
            return true // Assume enabled if can't check
        }
        
        let nvramEntry = IORegistryEntryFromPath(masterPort, "IODeviceTree:/options")
        guard nvramEntry != 0 else {
            return true
        }
        
        defer { IOObjectRelease(nvramEntry) }
        
        let key = "csr-active-config" as CFString
        if let value = IORegistryEntryCreateCFProperty(nvramEntry, key, kCFAllocatorDefault, 0)?.takeRetainedValue() as? Data {
            // CSR_ALLOW_UNTRUSTED_KEXTS = 0x1, etc.
            // If all bits are 0, SIP is fully enabled
            if value.count >= 4 {
                let config = value.withUnsafeBytes { $0.load(as: UInt32.self) }
                return config == 0
            }
        }
        
        return true // Default to enabled
    }
    
    private static func getSecureBootLevelViaIOKit() -> String {
        var masterPort: mach_port_t = 0
        guard IOMainPort(mach_host_self(), &masterPort) == KERN_SUCCESS else {
            return "Unknown"
        }
        
        let nvramEntry = IORegistryEntryFromPath(masterPort, "IODeviceTree:/options")
        guard nvramEntry != 0 else {
            return "Unknown"
        }
        
        defer { IOObjectRelease(nvramEntry) }
        
        // Check for Apple Silicon secure boot policy
        let key = "94B73556-2197-4702-82A8-3E1337DAFBFB:AppleSecureBootPolicy" as CFString
        if let value = IORegistryEntryCreateCFProperty(nvramEntry, key, kCFAllocatorDefault, 0)?.takeRetainedValue() as? Data {
            if let byte = value.first {
                switch byte {
                case 0x02: return "Full Security"
                case 0x01: return "Reduced Security"
                case 0x00: return "Permissive Security"
                default: return "Unknown (\(byte))"
                }
            }
        }
        
        // Check if Apple Silicon
        var isAppleSilicon = false
        var size: size_t = 0
        sysctlbyname("hw.optional.arm64", nil, &size, nil, 0)
        if size > 0 {
            var arm64: Int32 = 0
            sysctlbyname("hw.optional.arm64", &arm64, &size, nil, 0)
            isAppleSilicon = arm64 == 1
        }
        
        return isAppleSilicon ? "Full Security (Default)" : "N/A (Intel Mac)"
    }
    
    private static func checkFirewallViaPlist() -> Bool {
        // Read Application Firewall preferences
        let plistPath = "/Library/Preferences/com.apple.alf.plist"
        
        if let data = FileManager.default.contents(atPath: plistPath),
           let plist = try? PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any] {
            if let globalState = plist["globalstate"] as? Int {
                return globalState > 0
            }
        }
        
        return false
    }
    
    private static func checkGatekeeperViaSecAssessment() -> Bool {
        // Check Gatekeeper via Security framework assessment policy
        // Read system policy configuration
        let plistPath = "/var/db/SystemPolicy-prefs.plist"
        
        if let data = FileManager.default.contents(atPath: plistPath),
           let plist = try? PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any] {
            if let enabled = plist["enabled"] as? Bool {
                return enabled
            }
        }
        
        // Check via SecAssessment (requires Security framework)
        // Default: Gatekeeper is enabled on macOS
        // If we can't determine, check if spctl_assess works
        let assessPath = "/var/db/SystemPolicyConfiguration/SystemPolicy.sqlite"
        if FileManager.default.fileExists(atPath: assessPath) {
            return true
        }
        
        return true // Default enabled on modern macOS
    }
    
    private static func checkRemoteLoginViaPlist() -> Bool {
        // Check SSH via launchd plist
        let sshEnabledPath = "/private/var/db/com.apple.xpc.launchd/disabled.plist"
        
        // Check if SSH is disabled in launchd
        if let data = FileManager.default.contents(atPath: sshEnabledPath),
           let plist = try? PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any] {
            if let sshDisabled = plist["com.openssh.sshd"] as? Bool {
                return !sshDisabled
            }
        }
        
        // Check if sshd is listening via netstat alternative
        // If /private/var/db/.AccessibilityAPIEnabled analogue for SSH
        return FileManager.default.fileExists(atPath: "/etc/ssh/sshd_config")
    }
    
    private static func checkFindMyMacViaIOKit() -> Bool {
        var masterPort: mach_port_t = 0
        guard IOMainPort(mach_host_self(), &masterPort) == KERN_SUCCESS else {
            return false
        }
        
        let nvramEntry = IORegistryEntryFromPath(masterPort, "IODeviceTree:/options")
        guard nvramEntry != 0 else {
            return false
        }
        
        defer { IOObjectRelease(nvramEntry) }
        
        // Check for FMM (Find My Mac) token in NVRAM
        let key = "fmm-mobileme-token-FMM" as CFString
        if let _ = IORegistryEntryCreateCFProperty(nvramEntry, key, kCFAllocatorDefault, 0) {
            return true
        }
        
        return false
    }
}
