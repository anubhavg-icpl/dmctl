import ArgumentParser
import Foundation

@main
struct DMCtl: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "dmctl",
        abstract: "macOS Device Management CLI - Query MDM status, profiles, and interact with MDM servers",
        version: "2.0.0",
        subcommands: [
            Status.self,
            Profiles.self,
            Device.self,
            Enrollment.self,
            Generate.self,
            Server.self,
            Policy.self
        ],
        defaultSubcommand: Status.self
    )
}

// MARK: - Status Command
struct Status: ParsableCommand {
    static let configuration = CommandConfiguration(
        abstract: "Show MDM enrollment and management status"
    )
    
    @Flag(name: .shortAndLong, help: "Show detailed output")
    var verbose = false
    
    @Flag(name: .long, help: "Output as JSON")
    var json = false
    
    func run() throws {
        let status = try MDMStatus.current()
        
        if json {
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
            let data = try encoder.encode(status)
            print(String(data: data, encoding: .utf8)!)
        } else {
            print("╭─────────────────────────────────────────────╮")
            print("│         macOS MDM Status                    │")
            print("╰─────────────────────────────────────────────╯")
            print("")
            print("  MDM Enrolled:        \(status.isEnrolled ? "✓ Yes" : "✗ No")")
            print("  DEP Enrolled:        \(status.isDEPEnrolled ? "✓ Yes" : "✗ No")")
            print("  User Approved:       \(status.isUserApproved ? "✓ Yes" : "✗ No")")
            print("  Activation Lock:     \(status.activationLockEnabled ? "Enabled" : "Disabled")")
            print("  Remote Management:   \(status.remoteManagementEnabled ? "Enabled" : "Disabled")")
            
            if verbose, let serverURL = status.serverURL {
                print("")
                print("  MDM Server:          \(serverURL)")
            }
            print("")
        }
    }
}

// MARK: - Profiles Command
struct Profiles: ParsableCommand {
    static let configuration = CommandConfiguration(
        abstract: "List and manage configuration profiles",
        subcommands: [List.self, Show.self, Export.self],
        defaultSubcommand: List.self
    )
    
    struct List: ParsableCommand {
        static let configuration = CommandConfiguration(
            abstract: "List installed configuration profiles"
        )
        
        @Flag(name: .shortAndLong, help: "Show system profiles")
        var system = false
        
        @Flag(name: .shortAndLong, help: "Show user profiles")
        var user = false
        
        @Flag(name: .long, help: "Output as JSON")
        var json = false
        
        func run() throws {
            let profiles = try ProfileManager.listProfiles(system: system || !user, user: user || !system)
            
            if json {
                let encoder = JSONEncoder()
                encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
                let data = try encoder.encode(profiles)
                print(String(data: data, encoding: .utf8)!)
            } else {
                if profiles.isEmpty {
                    print("No configuration profiles installed.")
                    return
                }
                
                print("╭─────────────────────────────────────────────────────────────────╮")
                print("│  Installed Configuration Profiles                              │")
                print("╰─────────────────────────────────────────────────────────────────╯")
                print("")
                
                for (index, profile) in profiles.enumerated() {
                    let typeIcon = profile.isManaged ? "🔒" : "📄"
                    print("  \(index + 1). \(typeIcon) \(profile.displayName)")
                    print("     Identifier: \(profile.identifier)")
                    print("     Type:       \(profile.profileType)")
                    if let org = profile.organization {
                        print("     Org:        \(org)")
                    }
                    print("")
                }
            }
        }
    }
    
    struct Show: ParsableCommand {
        static let configuration = CommandConfiguration(
            abstract: "Show details of a specific profile"
        )
        
        @Argument(help: "Profile identifier")
        var identifier: String
        
        func run() throws {
            guard let profile = try ProfileManager.getProfile(identifier: identifier) else {
                throw ValidationError("Profile not found: \(identifier)")
            }
            
            print("╭─────────────────────────────────────────────────────────────────╮")
            print("│  Profile Details                                               │")
            print("╰─────────────────────────────────────────────────────────────────╯")
            print("")
            print("  Name:           \(profile.displayName)")
            print("  Identifier:     \(profile.identifier)")
            print("  UUID:           \(profile.uuid)")
            print("  Type:           \(profile.profileType)")
            print("  Managed:        \(profile.isManaged ? "Yes" : "No")")
            print("  Removable:      \(profile.isRemovable ? "Yes" : "No")")
            if let org = profile.organization {
                print("  Organization:   \(org)")
            }
            if let desc = profile.description {
                print("  Description:    \(desc)")
            }
            print("  Install Date:   \(profile.installDate)")
            print("")
            
            if !profile.payloads.isEmpty {
                print("  Payloads:")
                for payload in profile.payloads {
                    print("    • \(payload.type) (\(payload.identifier))")
                }
                print("")
            }
        }
    }
    
    struct Export: ParsableCommand {
        static let configuration = CommandConfiguration(
            abstract: "Export profile list to file"
        )
        
        @Option(name: .shortAndLong, help: "Output file path")
        var output: String = "profiles.json"
        
        func run() throws {
            let profiles = try ProfileManager.listProfiles(system: true, user: true)
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
            let data = try encoder.encode(profiles)
            try data.write(to: URL(fileURLWithPath: output))
            print("✓ Exported \(profiles.count) profiles to \(output)")
        }
    }
}

// MARK: - Device Command
struct Device: ParsableCommand {
    static let configuration = CommandConfiguration(
        abstract: "Query device information",
        subcommands: [Info.self, Security.self, Certificates.self],
        defaultSubcommand: Info.self
    )
    
    struct Info: ParsableCommand {
        static let configuration = CommandConfiguration(
            abstract: "Show device information"
        )
        
        @Flag(name: .long, help: "Output as JSON")
        var json = false
        
        func run() throws {
            let info = try DeviceInfo.current()
            
            if json {
                let encoder = JSONEncoder()
                encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
                let data = try encoder.encode(info)
                print(String(data: data, encoding: .utf8)!)
            } else {
                print("╭─────────────────────────────────────────────────────────────────╮")
                print("│  Device Information                                            │")
                print("╰─────────────────────────────────────────────────────────────────╯")
                print("")
                print("  Computer Name:    \(info.computerName)")
                print("  Model:            \(info.model)")
                print("  Model ID:         \(info.modelIdentifier)")
                print("  Serial Number:    \(info.serialNumber)")
                print("  Hardware UUID:    \(info.hardwareUUID)")
                print("  macOS Version:    \(info.osVersion) (\(info.osBuild))")
                print("  Chip:             \(info.chipType)")
                print("  Memory:           \(info.memorySize)")
                print("")
            }
        }
    }
    
    struct Security: ParsableCommand {
        static let configuration = CommandConfiguration(
            abstract: "Show security information"
        )
        
        @Flag(name: .long, help: "Output as JSON")
        var json = false
        
        func run() throws {
            let security = try SecurityInfo.current()
            
            if json {
                let encoder = JSONEncoder()
                encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
                let data = try encoder.encode(security)
                print(String(data: data, encoding: .utf8)!)
            } else {
                print("╭─────────────────────────────────────────────────────────────────╮")
                print("│  Security Information                                          │")
                print("╰─────────────────────────────────────────────────────────────────╯")
                print("")
                print("  FileVault:           \(security.fileVaultEnabled ? "✓ Enabled" : "✗ Disabled")")
                print("  SIP Status:          \(security.sipEnabled ? "✓ Enabled" : "✗ Disabled")")
                print("  Secure Boot:         \(security.secureBootLevel)")
                print("  Firewall:            \(security.firewallEnabled ? "✓ Enabled" : "✗ Disabled")")
                print("  Gatekeeper:          \(security.gatekeeperEnabled ? "✓ Enabled" : "✗ Disabled")")
                print("  Remote Login:        \(security.remoteLoginEnabled ? "Enabled" : "Disabled")")
                print("  Find My Mac:         \(security.findMyMacEnabled ? "Enabled" : "Disabled")")
                print("")
            }
        }
    }
    
    struct Certificates: ParsableCommand {
        static let configuration = CommandConfiguration(
            abstract: "List installed certificates"
        )
        
        @Option(name: .shortAndLong, help: "Keychain to query (system, login, all)")
        var keychain: String = "all"
        
        @Flag(name: .long, help: "Output as JSON")
        var json = false
        
        func run() throws {
            let certs = try CertificateManager.listCertificates(keychain: keychain)
            
            if json {
                let encoder = JSONEncoder()
                encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
                let data = try encoder.encode(certs)
                print(String(data: data, encoding: .utf8)!)
            } else {
                print("╭─────────────────────────────────────────────────────────────────╮")
                print("│  Installed Certificates                                        │")
                print("╰─────────────────────────────────────────────────────────────────╯")
                print("")
                
                for cert in certs {
                    let icon = cert.isValid ? "✓" : "✗"
                    print("  \(icon) \(cert.commonName)")
                    print("    Issuer:  \(cert.issuer)")
                    print("    Expires: \(cert.expirationDate)")
                    print("")
                }
            }
        }
    }
}

// MARK: - Enrollment Command
struct Enrollment: ParsableCommand {
    static let configuration = CommandConfiguration(
        abstract: "MDM enrollment information and actions",
        subcommands: [Check.self, Details.self],
        defaultSubcommand: Check.self
    )
    
    struct Check: ParsableCommand {
        static let configuration = CommandConfiguration(
            abstract: "Check MDM enrollment status"
        )
        
        func run() throws {
            let status = try MDMStatus.current()
            
            if status.isEnrolled {
                print("✓ Device is enrolled in MDM")
                if status.isDEPEnrolled {
                    print("  └─ Enrolled via DEP/ADE (Automated Device Enrollment)")
                }
                if status.isUserApproved {
                    print("  └─ User-approved enrollment")
                }
            } else {
                print("✗ Device is not enrolled in MDM")
            }
        }
    }
    
    struct Details: ParsableCommand {
        static let configuration = CommandConfiguration(
            abstract: "Show detailed enrollment information"
        )
        
        @Flag(name: .long, help: "Output as JSON")
        var json = false
        
        func run() throws {
            let details = try EnrollmentDetails.current()
            
            if json {
                let encoder = JSONEncoder()
                encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
                let data = try encoder.encode(details)
                print(String(data: data, encoding: .utf8)!)
            } else {
                print("╭─────────────────────────────────────────────────────────────────╮")
                print("│  MDM Enrollment Details                                        │")
                print("╰─────────────────────────────────────────────────────────────────╯")
                print("")
                print("  Enrolled:           \(details.isEnrolled ? "Yes" : "No")")
                print("  Enrollment Type:    \(details.enrollmentType)")
                print("  DEP Enrolled:       \(details.isDEPEnrolled ? "Yes" : "No")")
                print("  User Approved:      \(details.isUserApproved ? "Yes" : "No")")
                
                if let serverURL = details.serverURL {
                    print("  Server URL:         \(serverURL)")
                }
                if let topic = details.pushTopic {
                    print("  Push Topic:         \(topic)")
                }
                if let enrollDate = details.enrollmentDate {
                    print("  Enrollment Date:    \(enrollDate)")
                }
                print("")
            }
        }
    }
}

// MARK: - Generate Command
struct Generate: ParsableCommand {
    static let configuration = CommandConfiguration(
        abstract: "Generate MDM commands and profiles",
        subcommands: [Command.self, Profile.self],
        defaultSubcommand: Command.self
    )
    
    struct Command: ParsableCommand {
        static let configuration = CommandConfiguration(
            abstract: "Generate MDM command plist"
        )
        
        @Argument(help: "Command type (DeviceInformation, ProfileList, SecurityInfo, etc.)")
        var requestType: String
        
        @Option(name: .shortAndLong, help: "Output file (default: stdout)")
        var output: String?
        
        @Option(name: .long, help: "Custom command UUID")
        var uuid: String?
        
        func run() throws {
            let command = try MDMCommandGenerator.generate(
                requestType: requestType,
                uuid: uuid
            )
            
            if let outputPath = output {
                try command.write(toFile: outputPath, atomically: true, encoding: .utf8)
                print("✓ Command written to \(outputPath)")
            } else {
                print(command)
            }
        }
    }
    
    struct Profile: ParsableCommand {
        static let configuration = CommandConfiguration(
            abstract: "Generate configuration profile template"
        )
        
        @Argument(help: "Profile type (wifi, vpn, restrictions, passcode, certificate)")
        var profileType: String
        
        @Option(name: .shortAndLong, help: "Profile identifier")
        var identifier: String = "com.example.profile"
        
        @Option(name: .shortAndLong, help: "Organization name")
        var organization: String = "Organization"
        
        @Option(name: .shortAndLong, help: "Output file")
        var output: String?
        
        func run() throws {
            let profile = try ProfileGenerator.generate(
                type: profileType,
                identifier: identifier,
                organization: organization
            )
            
            if let outputPath = output {
                try profile.write(toFile: outputPath, atomically: true, encoding: .utf8)
                print("✓ Profile written to \(outputPath)")
            } else {
                print(profile)
            }
        }
    }
}

// MARK: - Server Command (MDM Server Interaction)
struct Server: ParsableCommand {
    static let configuration = CommandConfiguration(
        abstract: "Interact with MDM servers (NanoMDM, MicroMDM compatible)",
        subcommands: [
            ServerConnect.self,
            ServerPush.self,
            ServerEnqueue.self,
            ServerVersion.self
        ],
        defaultSubcommand: ServerVersion.self
    )
}

struct ServerConnect: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "connect",
        abstract: "Test connection to MDM server"
    )
    
    @Option(name: .shortAndLong, help: "MDM server URL (e.g., https://mdm.example.com)")
    var url: String
    
    @Option(name: .shortAndLong, help: "API key for authentication")
    var apiKey: String?
    
    func run() async throws {
        guard let serverURL = URL(string: url) else {
            print("✗ Invalid URL: \(url)")
            return
        }
        
        let client = MDMServerClient(serverURL: serverURL, apiKey: apiKey)
        
        print("Connecting to \(url)...")
        
        do {
            let version = try await client.getVersion()
            print("✓ Connected successfully")
            print("  Server Version: \(version)")
        } catch {
            print("✗ Connection failed: \(error)")
        }
    }
}

struct ServerVersion: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "version",
        abstract: "Get MDM server version"
    )
    
    @Option(name: .shortAndLong, help: "MDM server URL")
    var url: String
    
    func run() async throws {
        guard let serverURL = URL(string: url) else {
            print("✗ Invalid URL")
            return
        }
        
        let client = MDMServerClient(serverURL: serverURL)
        
        do {
            let version = try await client.getVersion()
            print("Server Version: \(version)")
        } catch {
            print("✗ Error: \(error)")
        }
    }
}

struct ServerPush: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "push",
        abstract: "Send APNs push to wake a device"
    )
    
    @Option(name: .shortAndLong, help: "MDM server URL")
    var url: String
    
    @Option(name: .shortAndLong, help: "API key")
    var apiKey: String
    
    @Argument(help: "Enrollment ID (device UDID or enrollment identifier)")
    var enrollmentId: String
    
    func run() async throws {
        guard let serverURL = URL(string: url) else {
            print("✗ Invalid URL")
            return
        }
        
        let client = MDMServerClient(serverURL: serverURL, apiKey: apiKey)
        
        print("Sending push to \(enrollmentId)...")
        
        do {
            let response = try await client.sendPush(enrollmentID: enrollmentId)
            
            if let error = response.error {
                print("✗ Push failed: \(error)")
            } else {
                print("✓ Push sent successfully")
                if let id = response.id {
                    print("  APNs Message ID: \(id)")
                }
            }
        } catch {
            print("✗ Error: \(error)")
        }
    }
}

struct ServerEnqueue: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "enqueue",
        abstract: "Queue an MDM command to a device"
    )
    
    @Option(name: .shortAndLong, help: "MDM server URL")
    var url: String
    
    @Option(name: .shortAndLong, help: "API key")
    var apiKey: String
    
    @Argument(help: "Enrollment ID")
    var enrollmentId: String
    
    @Argument(help: "Command type (DeviceInformation, ProfileList, SecurityInfo, etc.)")
    var requestType: String
    
    @Flag(name: .long, help: "Don't send push after queueing")
    var noPush = false
    
    @Option(name: .long, help: "Command plist file (instead of request type)")
    var file: String?
    
    func run() async throws {
        guard let serverURL = URL(string: url) else {
            print("✗ Invalid URL")
            return
        }
        
        let client = MDMServerClient(serverURL: serverURL, apiKey: apiKey)
        
        let command = MDMCommand(requestType: requestType)
        
        print("Queueing \(requestType) command to \(enrollmentId)...")
        
        do {
            let response = try await client.enqueueCommand(
                enrollmentID: enrollmentId,
                command: command,
                noPush: noPush
            )
            
            print("✓ Command queued successfully")
            if let uuid = response.commandUUID {
                print("  Command UUID: \(uuid)")
            }
            if let type = response.requestType {
                print("  Request Type: \(type)")
            }
            if let pushErr = response.pushError {
                print("  Push Warning: \(pushErr)")
            }
        } catch {
            print("✗ Error: \(error)")
        }
    }
}
