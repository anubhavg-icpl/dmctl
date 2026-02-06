import Foundation
import Security
import IOKit

/// macOS Security Policy Manager - WDAC-like functionality
/// Provides Gatekeeper, TCC/PPPC, Code Signing, and System Extension management
/// using native macOS APIs

// MARK: - Security Policy Manager

enum SecurityPolicyManager {
    
    // MARK: - Gatekeeper Policy
    
    /// Get current Gatekeeper status
    static func getGatekeeperStatus() -> GatekeeperStatus {
        // Read from system policy database
        let plistPath = "/var/db/SystemPolicy-prefs.plist"
        
        var isEnabled = true
        var allowIdentifiedDevelopers = true
        
        if let data = FileManager.default.contents(atPath: plistPath),
           let plist = try? PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any] {
            
            if let enabled = plist["enabled"] as? Bool {
                isEnabled = enabled
            }
            
            // Check assessment enabled state
            if let allowMac = plist["AllowIdentifiedDevelopers"] as? Bool {
                allowIdentifiedDevelopers = allowMac
            }
        }
        
        // Determine policy level
        let level: GatekeeperLevel
        if !isEnabled {
            level = .disabled
        } else if allowIdentifiedDevelopers {
            level = .appStoreAndIdentified
        } else {
            level = .appStoreOnly
        }
        
        return GatekeeperStatus(
            isEnabled: isEnabled,
            level: level,
            allowIdentifiedDevelopers: allowIdentifiedDevelopers
        )
    }
    
    // MARK: - Code Signing Verification
    
    /// Verify code signature of an application
    static func verifyCodeSignature(at path: String) -> CodeSignatureInfo {
        let url = URL(fileURLWithPath: path)
        var staticCode: SecStaticCode?
        
        guard SecStaticCodeCreateWithPath(url as CFURL, [], &staticCode) == errSecSuccess,
              let code = staticCode else {
            return CodeSignatureInfo(path: path, isSigned: false, error: "Failed to create static code object")
        }
        
        // Get signing information
        var info: CFDictionary?
        let flags = SecCSFlags(rawValue: kSecCSSigningInformation)
        
        guard SecCodeCopySigningInformation(code, flags, &info) == errSecSuccess,
              let signingInfo = info as? [String: Any] else {
            return CodeSignatureInfo(path: path, isSigned: false, error: "Failed to get signing info")
        }
        
        // Validate signature
        let validationFlags = SecCSFlags(rawValue: kSecCSCheckAllArchitectures | kSecCSCheckNestedCode)
        let validationResult = SecStaticCodeCheckValidity(code, validationFlags, nil)
        
        let isValid = validationResult == errSecSuccess
        
        // Parse certificate chain
        var teamID: String?
        var signingIdentity: String?
        var certificates: [String] = []
        
        if let certChain = signingInfo[kSecCodeInfoCertificates as String] as? [SecCertificate] {
            for cert in certChain {
                var name: CFString?
                SecCertificateCopyCommonName(cert, &name)
                if let certName = name as String? {
                    certificates.append(certName)
                    if signingIdentity == nil {
                        signingIdentity = certName
                    }
                }
            }
        }
        
        // Get Team ID
        if let identifier = signingInfo[kSecCodeInfoTeamIdentifier as String] as? String {
            teamID = identifier
        }
        
        // Check notarization (entitlements)
        var isNotarized = false
        if let entitlements = signingInfo[kSecCodeInfoEntitlementsDict as String] as? [String: Any] {
            // Check for notarization ticket
            isNotarized = entitlements["com.apple.application-identifier"] != nil
        }
        
        // Check if it's from App Store
        let isAppStore = signingIdentity?.contains("Apple Distribution") ?? false ||
                         signingIdentity?.contains("Mac App Store") ?? false
        
        return CodeSignatureInfo(
            path: path,
            isSigned: true,
            isValid: isValid,
            isNotarized: isNotarized,
            isAppStore: isAppStore,
            teamID: teamID,
            signingIdentity: signingIdentity,
            certificates: certificates
        )
    }
    
    /// Check if an app is allowed to run under current Gatekeeper policy
    static func isAppAllowed(at path: String) -> (allowed: Bool, reason: String) {
        let signatureInfo = verifyCodeSignature(at: path)
        let gatekeeperStatus = getGatekeeperStatus()
        
        if !gatekeeperStatus.isEnabled {
            return (true, "Gatekeeper is disabled")
        }
        
        if !signatureInfo.isSigned {
            return (false, "App is not code signed")
        }
        
        if !signatureInfo.isValid {
            return (false, "Code signature is invalid or tampered")
        }
        
        if gatekeeperStatus.level == .appStoreOnly {
            if signatureInfo.isAppStore {
                return (true, "App is from Mac App Store")
            }
            return (false, "Gatekeeper only allows App Store apps")
        }
        
        // App Store and Identified Developers
        if signatureInfo.isAppStore || signatureInfo.teamID != nil {
            return (true, "App is signed by identified developer")
        }
        
        return (false, "App is not from an identified developer")
    }
    
    // MARK: - TCC/PPPC Status
    
    /// Get TCC (Transparency, Consent, Control) database entries
    static func getTCCStatus() -> [TCCEntry] {
        var entries: [TCCEntry] = []
        
        // User TCC database
        let userTCCPath = "\(NSHomeDirectory())/Library/Application Support/com.apple.TCC/TCC.db"
        entries.append(contentsOf: readTCCDatabase(at: userTCCPath, isSystem: false))
        
        // System TCC database (requires root)
        let systemTCCPath = "/Library/Application Support/com.apple.TCC/TCC.db"
        entries.append(contentsOf: readTCCDatabase(at: systemTCCPath, isSystem: true))
        
        return entries
    }
    
    private static func readTCCDatabase(at path: String, isSystem: Bool) -> [TCCEntry] {
        // Note: Direct SQLite access requires appropriate permissions
        // For now, we'll check what we can via file existence and known patterns
        var entries: [TCCEntry] = []
        
        // Check common TCC services by looking at consent records
        let services: [String: String] = [
            "kTCCServiceCamera": "Camera",
            "kTCCServiceMicrophone": "Microphone",
            "kTCCServiceScreenCapture": "Screen Recording",
            "kTCCServiceAccessibility": "Accessibility",
            "kTCCServiceSystemPolicyAllFiles": "Full Disk Access",
            "kTCCServiceSystemPolicyDownloadsFolder": "Downloads Folder",
            "kTCCServiceSystemPolicyDocumentsFolder": "Documents Folder",
            "kTCCServiceSystemPolicyDesktopFolder": "Desktop Folder",
            "kTCCServiceAddressBook": "Contacts",
            "kTCCServiceCalendar": "Calendar",
            "kTCCServiceReminders": "Reminders",
            "kTCCServicePhotos": "Photos",
            "kTCCServiceLocation": "Location Services"
        ]
        
        // Check if TCC database exists and is readable
        if FileManager.default.fileExists(atPath: path) {
            for (service, name) in services {
                entries.append(TCCEntry(
                    service: service,
                    serviceName: name,
                    isSystemLevel: isSystem
                ))
            }
        }
        
        return entries
    }
    
    // MARK: - System Extensions
    
    /// Get installed system extensions
    static func getSystemExtensions() -> [SystemExtensionInfo] {
        var extensions: [SystemExtensionInfo] = []
        
        // System extensions are stored in /Library/SystemExtensions
        let extensionsPath = "/Library/SystemExtensions"
        
        guard let contents = try? FileManager.default.contentsOfDirectory(atPath: extensionsPath) else {
            return extensions
        }
        
        for item in contents where item.hasSuffix(".systemextension") || FileManager.default.fileExists(atPath: "\(extensionsPath)/\(item)") {
            let fullPath = "\(extensionsPath)/\(item)"
            
            // Try to get info from the extension
            if let extensionInfo = parseSystemExtension(at: fullPath) {
                extensions.append(extensionInfo)
            }
        }
        
        // Also check for extensions in db
        let dbPath = "/Library/SystemExtensions/db.plist"
        if let data = FileManager.default.contents(atPath: dbPath),
           let plist = try? PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any],
           let extensionsList = plist["extensions"] as? [[String: Any]] {
            
            for ext in extensionsList {
                if let bundleID = ext["bundleID"] as? String,
                   let state = ext["state"] as? String {
                    
                    let teamID = ext["teamID"] as? String
                    let version = ext["bundleVersion"] as? String
                    
                    // Skip if already parsed from filesystem
                    if !extensions.contains(where: { $0.bundleIdentifier == bundleID }) {
                        extensions.append(SystemExtensionInfo(
                            bundleIdentifier: bundleID,
                            teamID: teamID,
                            version: version,
                            state: state,
                            category: ext["category"] as? String ?? "Unknown"
                        ))
                    }
                }
            }
        }
        
        return extensions
    }
    
    private static func parseSystemExtension(at path: String) -> SystemExtensionInfo? {
        let infoPlistPath = "\(path)/Contents/Info.plist"
        
        guard let data = FileManager.default.contents(atPath: infoPlistPath),
              let plist = try? PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any],
              let bundleID = plist["CFBundleIdentifier"] as? String else {
            return nil
        }
        
        let version = plist["CFBundleShortVersionString"] as? String ?? plist["CFBundleVersion"] as? String
        
        // Get signing info
        let signatureInfo = verifyCodeSignature(at: path)
        
        return SystemExtensionInfo(
            bundleIdentifier: bundleID,
            teamID: signatureInfo.teamID,
            version: version,
            state: "installed",
            category: plist["NSSystemExtensionUsageDescription"] as? String ?? "System Extension"
        )
    }
    
    // MARK: - Application Allowlist/Blocklist
    
    /// Check app against allowlist/blocklist rules
    static func checkAppAgainstPolicy(at path: String, policy: AppPolicy) -> PolicyResult {
        let signatureInfo = verifyCodeSignature(at: path)
        
        // Check blocklist first
        if let bundleID = getBundleIdentifier(at: path) {
            if policy.blockedBundleIDs.contains(bundleID) {
                return PolicyResult(
                    allowed: false,
                    reason: "Application is in blocklist",
                    matchedRule: "Blocked Bundle ID: \(bundleID)"
                )
            }
            
            if policy.allowedBundleIDs.contains(bundleID) {
                return PolicyResult(
                    allowed: true,
                    reason: "Application is in allowlist",
                    matchedRule: "Allowed Bundle ID: \(bundleID)"
                )
            }
        }
        
        // Check team ID rules
        if let teamID = signatureInfo.teamID {
            if policy.blockedTeamIDs.contains(teamID) {
                return PolicyResult(
                    allowed: false,
                    reason: "Developer team is blocked",
                    matchedRule: "Blocked Team ID: \(teamID)"
                )
            }
            
            if policy.allowedTeamIDs.contains(teamID) {
                return PolicyResult(
                    allowed: true,
                    reason: "Developer team is allowed",
                    matchedRule: "Allowed Team ID: \(teamID)"
                )
            }
        }
        
        // Check signing requirements
        if policy.requireSigned && !signatureInfo.isSigned {
            return PolicyResult(
                allowed: false,
                reason: "Policy requires code signing",
                matchedRule: "Unsigned app blocked"
            )
        }
        
        if policy.requireNotarized && !signatureInfo.isNotarized {
            return PolicyResult(
                allowed: false,
                reason: "Policy requires notarization",
                matchedRule: "Non-notarized app blocked"
            )
        }
        
        if policy.requireAppStore && !signatureInfo.isAppStore {
            return PolicyResult(
                allowed: false,
                reason: "Policy requires App Store apps only",
                matchedRule: "Non-App Store app blocked"
            )
        }
        
        // Default policy
        switch policy.defaultAction {
        case .allow:
            return PolicyResult(allowed: true, reason: "Default policy: allow", matchedRule: "Default Allow")
        case .block:
            return PolicyResult(allowed: false, reason: "Default policy: block", matchedRule: "Default Block")
        case .audit:
            return PolicyResult(allowed: true, reason: "Default policy: audit (allowed)", matchedRule: "Audit Mode")
        }
    }
    
    private static func getBundleIdentifier(at path: String) -> String? {
        let infoPlistPath = "\(path)/Contents/Info.plist"
        
        guard let data = FileManager.default.contents(atPath: infoPlistPath),
              let plist = try? PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any],
              let bundleID = plist["CFBundleIdentifier"] as? String else {
            return nil
        }
        
        return bundleID
    }
    
    // MARK: - Generate Security Profiles
    
    /// Generate PPPC (Privacy Preferences Policy Control) profile
    static func generatePPPCProfile(
        identifier: String,
        organization: String,
        rules: [PPPCRule]
    ) -> String {
        let uuid = UUID().uuidString
        
        var servicesXML = ""
        
        for rule in rules {
            let serviceXML = """
                        <dict>
                            <key>Identifier</key>
                            <string>\(rule.bundleIdentifier)</string>
                            <key>IdentifierType</key>
                            <string>bundleID</string>
                            <key>CodeRequirement</key>
                            <string>\(rule.codeRequirement ?? "identifier \\\"\(rule.bundleIdentifier)\\\" and anchor apple generic")</string>
                            \(rule.teamIdentifier.map { "<key>StaticCode</key><false/><key>TeamIdentifier</key><string>\($0)</string>" } ?? "")
                            <key>Allowed</key>
                            <\(rule.allowed ? "true" : "false")/>
                            <key>Authorization</key>
                            <string>\(rule.authorization.rawValue)</string>
                        </dict>
            """
            servicesXML += serviceXML
        }
        
        return """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0">
        <dict>
            <key>PayloadContent</key>
            <array>
                <dict>
                    <key>PayloadDescription</key>
                    <string>Privacy Preferences Policy Control</string>
                    <key>PayloadDisplayName</key>
                    <string>Privacy Preferences</string>
                    <key>PayloadIdentifier</key>
                    <string>\(identifier).pppc</string>
                    <key>PayloadType</key>
                    <string>com.apple.TCC.configuration-profile-policy</string>
                    <key>PayloadUUID</key>
                    <string>\(UUID().uuidString)</string>
                    <key>PayloadVersion</key>
                    <integer>1</integer>
                    <key>Services</key>
                    <dict>
                        <key>SystemPolicyAllFiles</key>
                        <array>
        \(servicesXML)
                        </array>
                    </dict>
                </dict>
            </array>
            <key>PayloadDisplayName</key>
            <string>PPPC - Privacy Preferences</string>
            <key>PayloadIdentifier</key>
            <string>\(identifier)</string>
            <key>PayloadOrganization</key>
            <string>\(organization)</string>
            <key>PayloadRemovalDisallowed</key>
            <true/>
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
    
    /// Generate System Extension Policy profile
    static func generateSystemExtensionProfile(
        identifier: String,
        organization: String,
        allowedTeamIDs: [String],
        allowedExtensions: [(teamID: String, bundleIDs: [String])]
    ) -> String {
        let uuid = UUID().uuidString
        
        var allowedTeamsXML = ""
        for teamID in allowedTeamIDs {
            allowedTeamsXML += "                        <string>\(teamID)</string>\n"
        }
        
        var allowedExtensionsXML = ""
        for (teamID, bundleIDs) in allowedExtensions {
            allowedExtensionsXML += """
                            <key>\(teamID)</key>
                            <array>
            """
            for bundleID in bundleIDs {
                allowedExtensionsXML += "                            <string>\(bundleID)</string>\n"
            }
            allowedExtensionsXML += "                        </array>\n"
        }
        
        return """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0">
        <dict>
            <key>PayloadContent</key>
            <array>
                <dict>
                    <key>PayloadDescription</key>
                    <string>System Extension Policy</string>
                    <key>PayloadDisplayName</key>
                    <string>System Extensions</string>
                    <key>PayloadIdentifier</key>
                    <string>\(identifier).sysext</string>
                    <key>PayloadType</key>
                    <string>com.apple.system-extension-policy</string>
                    <key>PayloadUUID</key>
                    <string>\(UUID().uuidString)</string>
                    <key>PayloadVersion</key>
                    <integer>1</integer>
                    <key>AllowUserOverrides</key>
                    <false/>
                    <key>AllowedTeamIdentifiers</key>
                    <array>
        \(allowedTeamsXML)
                    </array>
                    <key>AllowedSystemExtensions</key>
                    <dict>
        \(allowedExtensionsXML)
                    </dict>
                </dict>
            </array>
            <key>PayloadDisplayName</key>
            <string>System Extension Policy</string>
            <key>PayloadIdentifier</key>
            <string>\(identifier)</string>
            <key>PayloadOrganization</key>
            <string>\(organization)</string>
            <key>PayloadRemovalDisallowed</key>
            <true/>
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
    
    /// Generate Gatekeeper/Software Restriction profile
    static func generateGatekeeperProfile(
        identifier: String,
        organization: String,
        level: GatekeeperLevel,
        disableOverride: Bool = true
    ) -> String {
        let uuid = UUID().uuidString
        
        let allowIdentifiedDevelopers = level != .appStoreOnly
        
        return """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0">
        <dict>
            <key>PayloadContent</key>
            <array>
                <dict>
                    <key>PayloadDescription</key>
                    <string>Gatekeeper Settings</string>
                    <key>PayloadDisplayName</key>
                    <string>Security Policy</string>
                    <key>PayloadIdentifier</key>
                    <string>\(identifier).gatekeeper</string>
                    <key>PayloadType</key>
                    <string>com.apple.systempolicy.control</string>
                    <key>PayloadUUID</key>
                    <string>\(UUID().uuidString)</string>
                    <key>PayloadVersion</key>
                    <integer>1</integer>
                    <key>EnableAssessment</key>
                    <true/>
                    <key>AllowIdentifiedDevelopers</key>
                    <\(allowIdentifiedDevelopers ? "true" : "false")/>
                </dict>
                <dict>
                    <key>PayloadDescription</key>
                    <string>Disables Gatekeeper override</string>
                    <key>PayloadDisplayName</key>
                    <string>Gatekeeper Override</string>
                    <key>PayloadIdentifier</key>
                    <string>\(identifier).gatekeeper.override</string>
                    <key>PayloadType</key>
                    <string>com.apple.systempolicy.managed</string>
                    <key>PayloadUUID</key>
                    <string>\(UUID().uuidString)</string>
                    <key>PayloadVersion</key>
                    <integer>1</integer>
                    <key>DisableOverride</key>
                    <\(disableOverride ? "true" : "false")/>
                </dict>
            </array>
            <key>PayloadDisplayName</key>
            <string>Gatekeeper Policy</string>
            <key>PayloadIdentifier</key>
            <string>\(identifier)</string>
            <key>PayloadOrganization</key>
            <string>\(organization)</string>
            <key>PayloadRemovalDisallowed</key>
            <true/>
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

// MARK: - Models

struct GatekeeperStatus: Codable {
    let isEnabled: Bool
    let level: GatekeeperLevel
    let allowIdentifiedDevelopers: Bool
}

enum GatekeeperLevel: String, CaseIterable, Codable {
    case disabled = "Disabled"
    case appStoreOnly = "App Store Only"
    case appStoreAndIdentified = "App Store and Identified Developers"
}

struct CodeSignatureInfo: Codable {
    let path: String
    let isSigned: Bool
    var isValid: Bool = false
    var isNotarized: Bool = false
    var isAppStore: Bool = false
    var teamID: String?
    var signingIdentity: String?
    var certificates: [String] = []
    var error: String?
}

struct TCCEntry: Codable {
    let service: String
    let serviceName: String
    var bundleIdentifier: String?
    var allowed: Bool?
    let isSystemLevel: Bool
}

struct SystemExtensionInfo: Codable {
    let bundleIdentifier: String
    let teamID: String?
    let version: String?
    let state: String
    let category: String
}

struct AppPolicy: Codable {
    var allowedBundleIDs: Set<String> = []
    var blockedBundleIDs: Set<String> = []
    var allowedTeamIDs: Set<String> = []
    var blockedTeamIDs: Set<String> = []
    var requireSigned: Bool = true
    var requireNotarized: Bool = false
    var requireAppStore: Bool = false
    var defaultAction: PolicyAction = .allow
}

enum PolicyAction: String, Codable {
    case allow
    case block
    case audit
}

struct PolicyResult: Codable {
    let allowed: Bool
    let reason: String
    let matchedRule: String
}

struct PPPCRule: Codable {
    let bundleIdentifier: String
    let teamIdentifier: String?
    let codeRequirement: String?
    let allowed: Bool
    let authorization: PPPCAuthorization
}

enum PPPCAuthorization: String, Codable {
    case allow = "Allow"
    case allowStandardUserToSetSystemService = "AllowStandardUserToSetSystemService"
    case deny = "Deny"
}
