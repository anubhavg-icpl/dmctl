import Foundation

// MARK: - MDM Command Generator
enum MDMCommandGenerator {
    
    // All supported MDM command types
    static let supportedCommands: [String: String] = [
        // Information Commands
        "DeviceInformation": "Query device information",
        "ProfileList": "List installed profiles",
        "ProvisioningProfileList": "List provisioning profiles",
        "CertificateList": "List installed certificates",
        "SecurityInfo": "Query security settings",
        "InstalledApplicationList": "List installed applications",
        "ManagedApplicationList": "List managed applications",
        "AvailableOSUpdates": "Query available OS updates",
        "OSUpdateStatus": "Check OS update status",
        "DeviceLocation": "Get device location (supervised only)",
        "UserList": "List users on device",
        
        // Profile Management
        "InstallProfile": "Install a configuration profile",
        "RemoveProfile": "Remove a configuration profile",
        
        // App Management
        "InstallApplication": "Install an application",
        "RemoveApplication": "Remove an application",
        "InviteToProgram": "Invite to VPP program",
        "ApplyRedemptionCode": "Apply VPP redemption code",
        "InstallMedia": "Install media (books)",
        "RemoveMedia": "Remove media",
        
        // Device Control
        "DeviceLock": "Lock the device",
        "EraseDevice": "Erase the device",
        "RestartDevice": "Restart the device",
        "ShutDownDevice": "Shut down the device",
        "ClearPasscode": "Clear passcode",
        "ClearRestrictionsPassword": "Clear restrictions password",
        
        // Lost Mode
        "EnableLostMode": "Enable lost mode (supervised)",
        "DisableLostMode": "Disable lost mode",
        "PlayLostModeSound": "Play lost mode sound",
        
        // Remote Desktop (macOS)
        "EnableRemoteDesktop": "Enable remote desktop",
        "DisableRemoteDesktop": "Disable remote desktop",
        
        // OS Updates
        "ScheduleOSUpdate": "Schedule an OS update",
        "ScheduleOSUpdateScan": "Scan for OS updates",
        
        // Settings
        "Settings": "Configure MDM settings",
        "AccountConfiguration": "Configure accounts",
        
        // Activation Lock
        "ActivationLockBypassCode": "Get activation lock bypass code",
        
        // Bootstrap Token (macOS)
        "SetBootstrapToken": "Set bootstrap token",
        "GetBootstrapToken": "Get bootstrap token"
    ]
    
    static func generate(requestType: String, uuid: String? = nil) throws -> String {
        let commandUUID = uuid ?? UUID().uuidString
        
        guard supportedCommands.keys.contains(requestType) else {
            throw CommandGeneratorError.unknownCommand(requestType)
        }
        
        return generateCommandPlist(requestType: requestType, uuid: commandUUID)
    }
    
    private static func generateCommandPlist(requestType: String, uuid: String) -> String {
        switch requestType {
        case "DeviceInformation":
            return deviceInformationCommand(uuid: uuid)
        case "ProfileList":
            return simpleCommand(requestType: requestType, uuid: uuid)
        case "SecurityInfo":
            return simpleCommand(requestType: requestType, uuid: uuid)
        case "CertificateList":
            return simpleCommand(requestType: requestType, uuid: uuid)
        case "InstalledApplicationList":
            return installedApplicationListCommand(uuid: uuid)
        case "DeviceLock":
            return deviceLockCommand(uuid: uuid)
        case "EraseDevice":
            return eraseDeviceCommand(uuid: uuid)
        case "RestartDevice":
            return simpleCommand(requestType: requestType, uuid: uuid)
        case "ShutDownDevice":
            return simpleCommand(requestType: requestType, uuid: uuid)
        case "ScheduleOSUpdate":
            return scheduleOSUpdateCommand(uuid: uuid)
        case "InstallProfile":
            return installProfileCommand(uuid: uuid)
        case "RemoveProfile":
            return removeProfileCommand(uuid: uuid)
        case "EnableRemoteDesktop":
            return simpleCommand(requestType: requestType, uuid: uuid)
        case "DisableRemoteDesktop":
            return simpleCommand(requestType: requestType, uuid: uuid)
        case "Settings":
            return settingsCommand(uuid: uuid)
        default:
            return simpleCommand(requestType: requestType, uuid: uuid)
        }
    }
    
    // MARK: - Command Templates
    
    private static func simpleCommand(requestType: String, uuid: String) -> String {
        """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0">
        <dict>
            <key>CommandUUID</key>
            <string>\(uuid)</string>
            <key>Command</key>
            <dict>
                <key>RequestType</key>
                <string>\(requestType)</string>
            </dict>
        </dict>
        </plist>
        """
    }
    
    private static func deviceInformationCommand(uuid: String) -> String {
        """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0">
        <dict>
            <key>CommandUUID</key>
            <string>\(uuid)</string>
            <key>Command</key>
            <dict>
                <key>RequestType</key>
                <string>DeviceInformation</string>
                <key>Queries</key>
                <array>
                    <string>UDID</string>
                    <string>DeviceName</string>
                    <string>OSVersion</string>
                    <string>BuildVersion</string>
                    <string>ModelName</string>
                    <string>Model</string>
                    <string>ProductName</string>
                    <string>SerialNumber</string>
                    <string>DeviceCapacity</string>
                    <string>AvailableDeviceCapacity</string>
                    <string>BatteryLevel</string>
                    <string>CellularTechnology</string>
                    <string>IMEI</string>
                    <string>MEID</string>
                    <string>IsSupervised</string>
                    <string>IsDeviceLocatorServiceEnabled</string>
                    <string>IsActivationLockEnabled</string>
                    <string>IsDoNotDisturbInEffect</string>
                    <string>EASDeviceIdentifier</string>
                    <string>IsCloudBackupEnabled</string>
                    <string>WiFiMAC</string>
                    <string>BluetoothMAC</string>
                    <string>EthernetMAC</string>
                </array>
            </dict>
        </dict>
        </plist>
        """
    }
    
    private static func installedApplicationListCommand(uuid: String) -> String {
        """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0">
        <dict>
            <key>CommandUUID</key>
            <string>\(uuid)</string>
            <key>Command</key>
            <dict>
                <key>RequestType</key>
                <string>InstalledApplicationList</string>
                <key>ManagedAppsOnly</key>
                <false/>
            </dict>
        </dict>
        </plist>
        """
    }
    
    private static func deviceLockCommand(uuid: String) -> String {
        """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0">
        <dict>
            <key>CommandUUID</key>
            <string>\(uuid)</string>
            <key>Command</key>
            <dict>
                <key>RequestType</key>
                <string>DeviceLock</string>
                <key>PIN</key>
                <string>123456</string>
                <key>Message</key>
                <string>This device has been locked by IT.</string>
                <key>PhoneNumber</key>
                <string>+1-555-555-5555</string>
            </dict>
        </dict>
        </plist>
        """
    }
    
    private static func eraseDeviceCommand(uuid: String) -> String {
        """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0">
        <dict>
            <key>CommandUUID</key>
            <string>\(uuid)</string>
            <key>Command</key>
            <dict>
                <key>RequestType</key>
                <string>EraseDevice</string>
                <key>PIN</key>
                <string>123456</string>
                <key>PreserveDataPlan</key>
                <false/>
                <key>DisallowProximitySetup</key>
                <false/>
            </dict>
        </dict>
        </plist>
        """
    }
    
    private static func scheduleOSUpdateCommand(uuid: String) -> String {
        """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0">
        <dict>
            <key>CommandUUID</key>
            <string>\(uuid)</string>
            <key>Command</key>
            <dict>
                <key>RequestType</key>
                <string>ScheduleOSUpdate</string>
                <key>Updates</key>
                <array>
                    <dict>
                        <key>InstallAction</key>
                        <string>InstallASAP</string>
                        <key>ProductKey</key>
                        <string>PRODUCT_KEY_HERE</string>
                    </dict>
                </array>
            </dict>
        </dict>
        </plist>
        """
    }
    
    private static func installProfileCommand(uuid: String) -> String {
        """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0">
        <dict>
            <key>CommandUUID</key>
            <string>\(uuid)</string>
            <key>Command</key>
            <dict>
                <key>RequestType</key>
                <string>InstallProfile</string>
                <key>Payload</key>
                <data>BASE64_ENCODED_MOBILECONFIG_HERE</data>
            </dict>
        </dict>
        </plist>
        """
    }
    
    private static func removeProfileCommand(uuid: String) -> String {
        """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0">
        <dict>
            <key>CommandUUID</key>
            <string>\(uuid)</string>
            <key>Command</key>
            <dict>
                <key>RequestType</key>
                <string>RemoveProfile</string>
                <key>Identifier</key>
                <string>com.example.profile.identifier</string>
            </dict>
        </dict>
        </plist>
        """
    }
    
    private static func settingsCommand(uuid: String) -> String {
        """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0">
        <dict>
            <key>CommandUUID</key>
            <string>\(uuid)</string>
            <key>Command</key>
            <dict>
                <key>RequestType</key>
                <string>Settings</string>
                <key>Settings</key>
                <array>
                    <dict>
                        <key>Item</key>
                        <string>MDMOptions</string>
                        <key>MDMOptions</key>
                        <dict>
                            <key>BootstrapTokenAllowed</key>
                            <true/>
                        </dict>
                    </dict>
                </array>
            </dict>
        </dict>
        </plist>
        """
    }
    
    // List all available commands
    static func listCommands() -> String {
        var output = "Available MDM Commands:\n\n"
        
        let sortedCommands = supportedCommands.sorted { $0.key < $1.key }
        for (command, description) in sortedCommands {
            output += "  \(command)\n    └─ \(description)\n\n"
        }
        
        return output
    }
}

enum CommandGeneratorError: Error, CustomStringConvertible {
    case unknownCommand(String)
    
    var description: String {
        switch self {
        case .unknownCommand(let cmd):
            return "Unknown command: \(cmd). Use 'dmctl generate command --help' for available commands."
        }
    }
}
