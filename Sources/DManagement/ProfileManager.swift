import Foundation

// MARK: - Profile Models
struct ConfigProfile: Codable {
    let displayName: String
    let identifier: String
    let uuid: String
    let profileType: String
    let organization: String?
    let description: String?
    let installDate: String
    let isManaged: Bool
    let isRemovable: Bool
    let payloads: [ProfilePayload]
}

struct ProfilePayload: Codable {
    let type: String
    let identifier: String
    let uuid: String
}

// MARK: - Profile Manager (Using Native APIs - reads configuration profile plists directly)
enum ProfileManager {
    
    // Profile storage paths on macOS
    private static let systemProfilesPath = "/var/db/ConfigurationProfiles/Store"
    private static let userProfilesPath = "~/Library/ConfigurationProfiles"
    
    static func listProfiles(system: Bool, user: Bool) throws -> [ConfigProfile] {
        var profiles: [ConfigProfile] = []
        
        // Read system profiles from ConfigurationProfiles store
        if system {
            profiles.append(contentsOf: readProfilesFromStore(systemProfilesPath, isManaged: true))
        }
        
        // Read user profiles
        if user {
            let expandedPath = NSString(string: userProfilesPath).expandingTildeInPath
            profiles.append(contentsOf: readProfilesFromStore(expandedPath, isManaged: false))
        }
        
        // Also check the main configuration profiles plist
        let mainStorePath = "/var/db/ConfigurationProfiles/Store/ConfigProfiles.plist"
        if let data = FileManager.default.contents(atPath: mainStorePath),
           let plist = try? PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any] {
            
            // Parse stored profiles
            if let storedProfiles = plist["StoredProfiles"] as? [[String: Any]] {
                for profileDict in storedProfiles {
                    if let profile = parseProfile(from: profileDict, isManaged: true) {
                        // Avoid duplicates
                        if !profiles.contains(where: { $0.identifier == profile.identifier }) {
                            profiles.append(profile)
                        }
                    }
                }
            }
        }
        
        return profiles
    }
    
    private static func readProfilesFromStore(_ path: String, isManaged: Bool) -> [ConfigProfile] {
        var profiles: [ConfigProfile] = []
        
        guard let contents = try? FileManager.default.contentsOfDirectory(atPath: path) else {
            return profiles
        }
        
        for file in contents where file.hasSuffix(".plist") || file.hasSuffix(".mobileconfig") {
            let filePath = "\(path)/\(file)"
            
            guard let data = FileManager.default.contents(atPath: filePath),
                  let plist = try? PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any] else {
                continue
            }
            
            if let profile = parseProfile(from: plist, isManaged: isManaged) {
                profiles.append(profile)
            }
        }
        
        return profiles
    }
    
    static func getProfile(identifier: String) throws -> ConfigProfile? {
        let allProfiles = try listProfiles(system: true, user: true)
        return allProfiles.first { $0.identifier == identifier }
    }
    
    private static func parseProfile(from dict: [String: Any], isManaged: Bool) -> ConfigProfile? {
        // Try different key formats (installed profiles vs mobileconfig format)
        guard let identifier = dict["ProfileIdentifier"] as? String 
            ?? dict["PayloadIdentifier"] as? String else {
            return nil
        }
        
        let displayName = dict["ProfileDisplayName"] as? String 
            ?? dict["PayloadDisplayName"] as? String
            ?? identifier
        
        guard let uuid = dict["ProfileUUID"] as? String 
            ?? dict["PayloadUUID"] as? String else {
            return nil
        }
        
        let installDate: String
        if let date = dict["ProfileInstallDate"] as? Date ?? dict["InstallDate"] as? Date {
            let formatter = DateFormatter()
            formatter.dateStyle = .medium
            formatter.timeStyle = .short
            installDate = formatter.string(from: date)
        } else {
            installDate = "Unknown"
        }
        
        var payloads: [ProfilePayload] = []
        // Check both ProfileItems and PayloadContent
        let items = dict["ProfileItems"] as? [[String: Any]] ?? dict["PayloadContent"] as? [[String: Any]] ?? []
        for item in items {
            if let payloadType = item["PayloadType"] as? String,
               let payloadId = item["PayloadIdentifier"] as? String,
               let payloadUUID = item["PayloadUUID"] as? String {
                payloads.append(ProfilePayload(
                    type: payloadType,
                    identifier: payloadId,
                    uuid: payloadUUID
                ))
            }
        }
        
        // Determine profile type from payloads
        var profileType = "Configuration"
        if payloads.contains(where: { $0.type.contains("mdm") }) {
            profileType = "MDM"
        } else if payloads.contains(where: { $0.type.contains("wifi") }) {
            profileType = "Wi-Fi"
        } else if payloads.contains(where: { $0.type.contains("vpn") }) {
            profileType = "VPN"
        } else if payloads.contains(where: { $0.type.contains("certificate") }) {
            profileType = "Certificate"
        } else if payloads.contains(where: { $0.type.contains("restrictions") }) {
            profileType = "Restrictions"
        }
        
        return ConfigProfile(
            displayName: displayName,
            identifier: identifier,
            uuid: uuid,
            profileType: profileType,
            organization: dict["ProfileOrganization"] as? String ?? dict["PayloadOrganization"] as? String,
            description: dict["ProfileDescription"] as? String ?? dict["PayloadDescription"] as? String,
            installDate: installDate,
            isManaged: isManaged || (dict["ProfileType"] as? String == "System"),
            isRemovable: dict["ProfileRemovalDisallowed"] as? Bool != true && dict["PayloadRemovalDisallowed"] as? Bool != true,
            payloads: payloads
        )
    }
}

// MARK: - Profile Generator
enum ProfileGenerator {
    
    static func generate(type: String, identifier: String, organization: String) throws -> String {
        let uuid = UUID().uuidString
        let payloadUUID = UUID().uuidString
        
        switch type.lowercased() {
        case "wifi":
            return generateWiFiProfile(identifier: identifier, organization: organization, uuid: uuid, payloadUUID: payloadUUID)
        case "vpn":
            return generateVPNProfile(identifier: identifier, organization: organization, uuid: uuid, payloadUUID: payloadUUID)
        case "restrictions":
            return generateRestrictionsProfile(identifier: identifier, organization: organization, uuid: uuid, payloadUUID: payloadUUID)
        case "passcode":
            return generatePasscodeProfile(identifier: identifier, organization: organization, uuid: uuid, payloadUUID: payloadUUID)
        case "certificate":
            return generateCertificateProfile(identifier: identifier, organization: organization, uuid: uuid, payloadUUID: payloadUUID)
        default:
            throw ProfileGeneratorError.unknownType(type)
        }
    }
    
    private static func generateWiFiProfile(identifier: String, organization: String, uuid: String, payloadUUID: String) -> String {
        """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0">
        <dict>
            <key>PayloadContent</key>
            <array>
                <dict>
                    <key>AutoJoin</key>
                    <true/>
                    <key>EncryptionType</key>
                    <string>WPA2</string>
                    <key>HIDDEN_NETWORK</key>
                    <false/>
                    <key>IsHotspot</key>
                    <false/>
                    <key>Password</key>
                    <string>YOUR_PASSWORD_HERE</string>
                    <key>PayloadDescription</key>
                    <string>Configures Wi-Fi settings</string>
                    <key>PayloadDisplayName</key>
                    <string>Wi-Fi</string>
                    <key>PayloadIdentifier</key>
                    <string>\(identifier).wifi</string>
                    <key>PayloadType</key>
                    <string>com.apple.wifi.managed</string>
                    <key>PayloadUUID</key>
                    <string>\(payloadUUID)</string>
                    <key>PayloadVersion</key>
                    <integer>1</integer>
                    <key>ProxyType</key>
                    <string>None</string>
                    <key>SSID_STR</key>
                    <string>YOUR_SSID_HERE</string>
                </dict>
            </array>
            <key>PayloadDisplayName</key>
            <string>Wi-Fi Configuration</string>
            <key>PayloadIdentifier</key>
            <string>\(identifier)</string>
            <key>PayloadOrganization</key>
            <string>\(organization)</string>
            <key>PayloadRemovalDisallowed</key>
            <false/>
            <key>PayloadType</key>
            <string>Configuration</string>
            <key>PayloadUUID</key>
            <string>\(uuid)</string>
            <key>PayloadVersion</key>
            <integer>1</integer>
        </dict>
        </plist>
        """
    }
    
    private static func generateVPNProfile(identifier: String, organization: String, uuid: String, payloadUUID: String) -> String {
        """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0">
        <dict>
            <key>PayloadContent</key>
            <array>
                <dict>
                    <key>PayloadDescription</key>
                    <string>Configures VPN settings</string>
                    <key>PayloadDisplayName</key>
                    <string>VPN</string>
                    <key>PayloadIdentifier</key>
                    <string>\(identifier).vpn</string>
                    <key>PayloadType</key>
                    <string>com.apple.vpn.managed</string>
                    <key>PayloadUUID</key>
                    <string>\(payloadUUID)</string>
                    <key>PayloadVersion</key>
                    <integer>1</integer>
                    <key>UserDefinedName</key>
                    <string>Corporate VPN</string>
                    <key>VPNType</key>
                    <string>IKEv2</string>
                    <key>IKEv2</key>
                    <dict>
                        <key>RemoteAddress</key>
                        <string>vpn.example.com</string>
                        <key>RemoteIdentifier</key>
                        <string>vpn.example.com</string>
                        <key>LocalIdentifier</key>
                        <string></string>
                        <key>AuthenticationMethod</key>
                        <string>Certificate</string>
                    </dict>
                </dict>
            </array>
            <key>PayloadDisplayName</key>
            <string>VPN Configuration</string>
            <key>PayloadIdentifier</key>
            <string>\(identifier)</string>
            <key>PayloadOrganization</key>
            <string>\(organization)</string>
            <key>PayloadRemovalDisallowed</key>
            <false/>
            <key>PayloadType</key>
            <string>Configuration</string>
            <key>PayloadUUID</key>
            <string>\(uuid)</string>
            <key>PayloadVersion</key>
            <integer>1</integer>
        </dict>
        </plist>
        """
    }
    
    private static func generateRestrictionsProfile(identifier: String, organization: String, uuid: String, payloadUUID: String) -> String {
        """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0">
        <dict>
            <key>PayloadContent</key>
            <array>
                <dict>
                    <key>PayloadDescription</key>
                    <string>Configures device restrictions</string>
                    <key>PayloadDisplayName</key>
                    <string>Restrictions</string>
                    <key>PayloadIdentifier</key>
                    <string>\(identifier).restrictions</string>
                    <key>PayloadType</key>
                    <string>com.apple.applicationaccess</string>
                    <key>PayloadUUID</key>
                    <string>\(payloadUUID)</string>
                    <key>PayloadVersion</key>
                    <integer>1</integer>
                    <key>allowCamera</key>
                    <true/>
                    <key>allowScreenShot</key>
                    <true/>
                    <key>allowCloudDocumentSync</key>
                    <true/>
                    <key>allowAirDrop</key>
                    <true/>
                </dict>
            </array>
            <key>PayloadDisplayName</key>
            <string>Restrictions</string>
            <key>PayloadIdentifier</key>
            <string>\(identifier)</string>
            <key>PayloadOrganization</key>
            <string>\(organization)</string>
            <key>PayloadRemovalDisallowed</key>
            <false/>
            <key>PayloadType</key>
            <string>Configuration</string>
            <key>PayloadUUID</key>
            <string>\(uuid)</string>
            <key>PayloadVersion</key>
            <integer>1</integer>
        </dict>
        </plist>
        """
    }
    
    private static func generatePasscodeProfile(identifier: String, organization: String, uuid: String, payloadUUID: String) -> String {
        """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0">
        <dict>
            <key>PayloadContent</key>
            <array>
                <dict>
                    <key>PayloadDescription</key>
                    <string>Configures passcode policy</string>
                    <key>PayloadDisplayName</key>
                    <string>Passcode Policy</string>
                    <key>PayloadIdentifier</key>
                    <string>\(identifier).passcode</string>
                    <key>PayloadType</key>
                    <string>com.apple.mobiledevice.passwordpolicy</string>
                    <key>PayloadUUID</key>
                    <string>\(payloadUUID)</string>
                    <key>PayloadVersion</key>
                    <integer>1</integer>
                    <key>allowSimple</key>
                    <false/>
                    <key>forcePIN</key>
                    <true/>
                    <key>maxFailedAttempts</key>
                    <integer>10</integer>
                    <key>maxInactivity</key>
                    <integer>5</integer>
                    <key>minLength</key>
                    <integer>8</integer>
                    <key>requireAlphanumeric</key>
                    <true/>
                </dict>
            </array>
            <key>PayloadDisplayName</key>
            <string>Passcode Policy</string>
            <key>PayloadIdentifier</key>
            <string>\(identifier)</string>
            <key>PayloadOrganization</key>
            <string>\(organization)</string>
            <key>PayloadRemovalDisallowed</key>
            <false/>
            <key>PayloadType</key>
            <string>Configuration</string>
            <key>PayloadUUID</key>
            <string>\(uuid)</string>
            <key>PayloadVersion</key>
            <integer>1</integer>
        </dict>
        </plist>
        """
    }
    
    private static func generateCertificateProfile(identifier: String, organization: String, uuid: String, payloadUUID: String) -> String {
        """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0">
        <dict>
            <key>PayloadContent</key>
            <array>
                <dict>
                    <key>PayloadCertificateFileName</key>
                    <string>certificate.cer</string>
                    <key>PayloadContent</key>
                    <data>BASE64_ENCODED_CERTIFICATE_HERE</data>
                    <key>PayloadDescription</key>
                    <string>Adds a CA root certificate</string>
                    <key>PayloadDisplayName</key>
                    <string>Root Certificate</string>
                    <key>PayloadIdentifier</key>
                    <string>\(identifier).cert</string>
                    <key>PayloadType</key>
                    <string>com.apple.security.root</string>
                    <key>PayloadUUID</key>
                    <string>\(payloadUUID)</string>
                    <key>PayloadVersion</key>
                    <integer>1</integer>
                </dict>
            </array>
            <key>PayloadDisplayName</key>
            <string>Certificate</string>
            <key>PayloadIdentifier</key>
            <string>\(identifier)</string>
            <key>PayloadOrganization</key>
            <string>\(organization)</string>
            <key>PayloadRemovalDisallowed</key>
            <false/>
            <key>PayloadType</key>
            <string>Configuration</string>
            <key>PayloadUUID</key>
            <string>\(uuid)</string>
            <key>PayloadVersion</key>
            <integer>1</integer>
        </dict>
        </plist>
        """
    }
}

enum ProfileGeneratorError: Error, CustomStringConvertible {
    case unknownType(String)
    
    var description: String {
        switch self {
        case .unknownType(let type):
            return "Unknown profile type: \(type). Supported types: wifi, vpn, restrictions, passcode, certificate"
        }
    }
}
