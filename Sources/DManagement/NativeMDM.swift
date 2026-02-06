import Foundation
import IOKit
import Security

/// Native macOS MDM Protocol Handler
/// Uses system APIs to interact with the built-in MDM client
enum NativeMDM {
    
    // MARK: - Device Identity (for MDM enrollment)
    
    /// Get device UDID (Hardware UUID on macOS)
    static func getDeviceUDID() -> String? {
        let platformExpert = IOServiceGetMatchingService(
            kIOMainPortDefault,
            IOServiceMatching("IOPlatformExpertDevice")
        )
        
        guard platformExpert != 0 else { return nil }
        defer { IOObjectRelease(platformExpert) }
        
        guard let uuidRef = IORegistryEntryCreateCFProperty(
            platformExpert,
            kIOPlatformUUIDKey as CFString,
            kCFAllocatorDefault,
            0
        )?.takeRetainedValue() as? String else {
            return nil
        }
        
        return uuidRef
    }
    
    /// Get device serial number
    static func getSerialNumber() -> String? {
        let platformExpert = IOServiceGetMatchingService(
            kIOMainPortDefault,
            IOServiceMatching("IOPlatformExpertDevice")
        )
        
        guard platformExpert != 0 else { return nil }
        defer { IOObjectRelease(platformExpert) }
        
        guard let serialRef = IORegistryEntryCreateCFProperty(
            platformExpert,
            kIOPlatformSerialNumberKey as CFString,
            kCFAllocatorDefault,
            0
        )?.takeRetainedValue() as? String else {
            return nil
        }
        
        return serialRef
    }
    
    /// Get model identifier
    static func getModelIdentifier() -> String? {
        let platformExpert = IOServiceGetMatchingService(
            kIOMainPortDefault,
            IOServiceMatching("IOPlatformExpertDevice")
        )
        
        guard platformExpert != 0 else { return nil }
        defer { IOObjectRelease(platformExpert) }
        
        guard let modelRef = IORegistryEntryCreateCFProperty(
            platformExpert,
            "model" as CFString,
            kCFAllocatorDefault,
            0
        )?.takeRetainedValue() else {
            return nil
        }
        
        if let data = modelRef as? Data {
            return String(data: data, encoding: .utf8)?.trimmingCharacters(in: .controlCharacters)
        }
        
        return nil
    }
    
    // MARK: - MDM Enrollment Status
    
    /// Check if device is enrolled in MDM
    static func isEnrolled() -> Bool {
        let enrollmentPaths = [
            "/var/db/ConfigurationProfiles/Settings/.cloudConfigProfileInstalled",
            "/var/db/ConfigurationProfiles/Store/ConfigProfiles.plist"
        ]
        
        for path in enrollmentPaths {
            if let data = FileManager.default.contents(atPath: path),
               let plist = try? PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any] {
                
                // Check for MDM enrollment indicators
                if plist["CloudConfigurationUIComplete"] != nil ||
                   plist["ServerURL"] != nil {
                    return true
                }
                
                // Check for MDM profile in store
                if let profiles = plist["StoredProfiles"] as? [[String: Any]] {
                    for profile in profiles {
                        if let items = profile["ProfileItems"] as? [[String: Any]] {
                            for item in items {
                                if let type = item["PayloadType"] as? String,
                                   type.contains("mdm") {
                                    return true
                                }
                            }
                        }
                    }
                }
            }
        }
        
        return false
    }
    
    /// Get MDM server URL if enrolled
    static func getServerURL() -> String? {
        let paths = [
            "/var/db/ConfigurationProfiles/Settings/.cloudConfigProfileInstalled",
            "/var/db/ConfigurationProfiles/Store/ConfigProfiles.plist"
        ]
        
        for path in paths {
            if let data = FileManager.default.contents(atPath: path),
               let plist = try? PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any],
               let serverURL = plist["ServerURL"] as? String {
                return serverURL
            }
        }
        
        return nil
    }
    
    /// Get APNs topic from MDM enrollment
    static func getTopic() -> String? {
        let path = "/var/db/ConfigurationProfiles/Store/ConfigProfiles.plist"
        
        if let data = FileManager.default.contents(atPath: path),
           let plist = try? PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any] {
            
            if let profiles = plist["StoredProfiles"] as? [[String: Any]] {
                for profile in profiles {
                    if let items = profile["ProfileItems"] as? [[String: Any]] {
                        for item in items {
                            if let type = item["PayloadType"] as? String, type.contains("mdm"),
                               let topic = item["Topic"] as? String {
                                return topic
                            }
                        }
                    }
                }
            }
        }
        
        return nil
    }
    
    // MARK: - Push Token Access
    
    /// Get stored APNs push token (requires root access)
    static func getPushToken() -> Data? {
        // Push tokens are stored securely and typically require root access
        let tokenPath = "/var/db/ConfigurationProfiles/Settings/PushToken.plist"
        
        if let data = FileManager.default.contents(atPath: tokenPath),
           let plist = try? PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any],
           let token = plist["Token"] as? Data {
            return token
        }
        
        return nil
    }
    
    // MARK: - MDM Profile Parsing
    
    /// Parse an MDM enrollment profile
    static func parseMDMProfile(at path: String) -> MDMProfileInfo? {
        guard let data = FileManager.default.contents(atPath: path) else {
            return nil
        }
        
        guard let plist = try? PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any] else {
            return nil
        }
        
        return parseMDMProfileDict(plist)
    }
    
    /// Parse MDM profile from data
    static func parseMDMProfile(data: Data) -> MDMProfileInfo? {
        guard let plist = try? PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any] else {
            return nil
        }
        
        return parseMDMProfileDict(plist)
    }
    
    private static func parseMDMProfileDict(_ plist: [String: Any]) -> MDMProfileInfo? {
        var mdmInfo = MDMProfileInfo()
        
        mdmInfo.identifier = plist["PayloadIdentifier"] as? String
        mdmInfo.displayName = plist["PayloadDisplayName"] as? String
        mdmInfo.organization = plist["PayloadOrganization"] as? String
        
        // Look for MDM payload
        if let content = plist["PayloadContent"] as? [[String: Any]] {
            for payload in content {
                if let type = payload["PayloadType"] as? String, type == "com.apple.mdm" {
                    mdmInfo.serverURL = payload["ServerURL"] as? String
                    mdmInfo.checkInURL = payload["CheckInURL"] as? String
                    mdmInfo.topic = payload["Topic"] as? String
                    mdmInfo.identityCertificateUUID = payload["IdentityCertificateUUID"] as? String
                    mdmInfo.accessRights = payload["AccessRights"] as? Int
                    mdmInfo.checkOutWhenRemoved = payload["CheckOutWhenRemoved"] as? Bool ?? false
                    mdmInfo.serverCapabilities = payload["ServerCapabilities"] as? [String] ?? []
                    break
                }
            }
        }
        
        return mdmInfo
    }
    
    // MARK: - Build Check-in Messages
    
    /// Build Authenticate check-in message using device info
    static func buildAuthenticateMessage() -> [String: Any]? {
        guard let udid = getDeviceUDID() else { return nil }
        
        var message: [String: Any] = [
            "MessageType": "Authenticate",
            "UDID": udid,
            "BuildVersion": getOSBuildVersion()
        ]
        
        if let serial = getSerialNumber() {
            message["SerialNumber"] = serial
        }
        
        if let model = getModelIdentifier() {
            message["Model"] = model
        }
        
        if let topic = getTopic() {
            message["Topic"] = topic
        }
        
        return message
    }
    
    /// Build TokenUpdate message (requires push token)
    static func buildTokenUpdateMessage(pushToken: Data, pushMagic: String) -> [String: Any]? {
        guard let udid = getDeviceUDID(),
              let topic = getTopic() else {
            return nil
        }
        
        return [
            "MessageType": "TokenUpdate",
            "UDID": udid,
            "Topic": topic,
            "Token": pushToken,
            "PushMagic": pushMagic
        ]
    }
    
    /// Build CheckOut message
    static func buildCheckOutMessage() -> [String: Any]? {
        guard let udid = getDeviceUDID(),
              let topic = getTopic() else {
            return nil
        }
        
        return [
            "MessageType": "CheckOut",
            "UDID": udid,
            "Topic": topic
        ]
    }
    
    // MARK: - Helpers
    
    private static func getOSBuildVersion() -> String {
        let plistPath = "/System/Library/CoreServices/SystemVersion.plist"
        
        if let data = FileManager.default.contents(atPath: plistPath),
           let plist = try? PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any],
           let build = plist["ProductBuildVersion"] as? String {
            return build
        }
        
        return "Unknown"
    }
}

// MARK: - MDM Profile Info

struct MDMProfileInfo {
    var identifier: String?
    var displayName: String?
    var organization: String?
    var serverURL: String?
    var checkInURL: String?
    var topic: String?
    var identityCertificateUUID: String?
    var accessRights: Int?
    var checkOutWhenRemoved: Bool = false
    var serverCapabilities: [String] = []
    
    var description: String {
        var lines: [String] = []
        
        if let name = displayName {
            lines.append("Name: \(name)")
        }
        if let id = identifier {
            lines.append("Identifier: \(id)")
        }
        if let org = organization {
            lines.append("Organization: \(org)")
        }
        if let url = serverURL {
            lines.append("Server URL: \(url)")
        }
        if let checkIn = checkInURL {
            lines.append("Check-in URL: \(checkIn)")
        }
        if let topic = topic {
            lines.append("Topic: \(topic)")
        }
        if let rights = accessRights {
            lines.append("Access Rights: \(rights)")
        }
        if !serverCapabilities.isEmpty {
            lines.append("Capabilities: \(serverCapabilities.joined(separator: ", "))")
        }
        
        return lines.joined(separator: "\n")
    }
}

// MARK: - MDM Command Status

enum MDMCommandStatus: String {
    case acknowledged = "Acknowledged"
    case idle = "Idle"
    case notNow = "NotNow"
    case error = "Error"
}

// MARK: - MDM Access Rights

struct MDMAccessRights: OptionSet {
    let rawValue: Int
    
    static let profileInspection = MDMAccessRights(rawValue: 1)
    static let profileInstallRemove = MDMAccessRights(rawValue: 2)
    static let deviceLock = MDMAccessRights(rawValue: 4)
    static let deviceErase = MDMAccessRights(rawValue: 8)
    static let deviceQuery = MDMAccessRights(rawValue: 16)
    static let networkInfo = MDMAccessRights(rawValue: 32)
    static let provisioningProfiles = MDMAccessRights(rawValue: 64)
    static let appManagement = MDMAccessRights(rawValue: 128)
    static let securityInfo = MDMAccessRights(rawValue: 256)
    static let settings = MDMAccessRights(rawValue: 512)
    static let appManagementManaged = MDMAccessRights(rawValue: 1024)
    
    static let allRights: MDMAccessRights = [
        .profileInspection, .profileInstallRemove, .deviceLock, .deviceErase,
        .deviceQuery, .networkInfo, .provisioningProfiles, .appManagement,
        .securityInfo, .settings, .appManagementManaged
    ]
    
    var descriptions: [String] {
        var result: [String] = []
        
        if contains(.profileInspection) { result.append("Profile Inspection") }
        if contains(.profileInstallRemove) { result.append("Profile Install/Remove") }
        if contains(.deviceLock) { result.append("Device Lock") }
        if contains(.deviceErase) { result.append("Device Erase") }
        if contains(.deviceQuery) { result.append("Device Query") }
        if contains(.networkInfo) { result.append("Network Info") }
        if contains(.provisioningProfiles) { result.append("Provisioning Profiles") }
        if contains(.appManagement) { result.append("App Management") }
        if contains(.securityInfo) { result.append("Security Info") }
        if contains(.settings) { result.append("Settings") }
        if contains(.appManagementManaged) { result.append("Managed App Management") }
        
        return result
    }
}
