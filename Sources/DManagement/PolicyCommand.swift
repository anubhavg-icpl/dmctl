import ArgumentParser
import Foundation

struct Policy: ParsableCommand {
    static let configuration = CommandConfiguration(
        abstract: "macOS security policy utilities (Gatekeeper, code signing, TCC, and more)",
        subcommands: [
            Status.self,
            Verify.self,
            Check.self,
            TCC.self,
            SystemExtensions.self,
            Generate.self
        ],
        defaultSubcommand: Status.self
    )
    
    // MARK: - Status
    struct Status: ParsableCommand {
        static let configuration = CommandConfiguration(
            commandName: "status",
            abstract: "Show current Gatekeeper policy"
        )
        
        @Flag(name: .long, help: "Output as JSON")
        var json = false
        
        func run() throws {
            let status = SecurityPolicyManager.getGatekeeperStatus()
            
            if json {
                let encoder = JSONEncoder()
                encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
                let data = try encoder.encode(status)
                print(String(decoding: data, as: UTF8.self))
                return
            }
            
            print("╭──────────────────────────────╮")
            print("│  Gatekeeper Status           │")
            print("╰──────────────────────────────╯")
            print("  Enabled:        \(status.isEnabled ? "Yes" : "No")")
            print("  Level:          \(status.level.rawValue)")
            print("  Identified Dev: \(status.allowIdentifiedDevelopers ? "Allowed" : "Blocked")")
        }
    }
    
    // MARK: - Verify
    struct Verify: ParsableCommand {
        static let configuration = CommandConfiguration(
            commandName: "verify",
            abstract: "Inspect code signature for an app or binary"
        )
        
        @Argument(help: "Path to application or binary")
        var path: String
        
        @Flag(name: .long, help: "Output as JSON")
        var json = false
        
        func run() throws {
            let info = SecurityPolicyManager.verifyCodeSignature(at: path)
            
            if json {
                let encoder = JSONEncoder()
                encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
                let data = try encoder.encode(info)
                print(String(decoding: data, as: UTF8.self))
                return
            }
            
            print("╭──────────────────────────────╮")
            print("│  Code Signature              │")
            print("╰──────────────────────────────╯")
            print("  Path:        \(path)")
            print("  Signed:      \(info.isSigned ? "Yes" : "No")")
            if let error = info.error {
                print("  Error:       \(error)")
            }
            if info.isSigned {
                print("  Valid:       \(info.isValid ? "Yes" : "No")")
                print("  Notarized:   \(info.isNotarized ? "Yes" : "No")")
                print("  App Store:   \(info.isAppStore ? "Yes" : "No")")
                if let team = info.teamID {
                    print("  Team ID:     \(team)")
                }
                if let identity = info.signingIdentity {
                    print("  Identity:    \(identity)")
                }
                if !info.certificates.isEmpty {
                    print("  Certificates:")
                    for cert in info.certificates {
                        print("    • \(cert)")
                    }
                }
            }
        }
    }
    
    // MARK: - Policy check
    struct Check: ParsableCommand {
        static let configuration = CommandConfiguration(
            commandName: "check",
            abstract: "Evaluate an app against an allow/block policy"
        )
        
        @Argument(help: "Path to application or binary")
        var path: String
        
        @Option(name: .long, parsing: .upToNextOption, help: "Bundle IDs to allow")
        var allowBundle: [String] = []
        
        @Option(name: .long, parsing: .upToNextOption, help: "Bundle IDs to block")
        var blockBundle: [String] = []
        
        @Option(name: .long, parsing: .upToNextOption, help: "Developer Team IDs to allow")
        var allowTeam: [String] = []
        
        @Option(name: .long, parsing: .upToNextOption, help: "Developer Team IDs to block")
        var blockTeam: [String] = []
        
        @Flag(name: .long, help: "Allow unsigned binaries")
        var allowUnsigned = false
        
        @Flag(name: .long, help: "Require notarized apps")
        var requireNotarized = false
        
        @Flag(name: .long, help: "Require Mac App Store apps")
        var requireAppStore = false
        
        @Option(name: .long, help: "Default action when no rule matches (allow, block, audit)")
        var defaultAction: PolicyAction = .allow
        
        @Flag(name: .long, help: "Output as JSON")
        var json = false
        
        func run() throws {
            var policy = AppPolicy()
            policy.allowedBundleIDs = Set(allowBundle)
            policy.blockedBundleIDs = Set(blockBundle)
            policy.allowedTeamIDs = Set(allowTeam)
            policy.blockedTeamIDs = Set(blockTeam)
            policy.requireSigned = !allowUnsigned
            policy.requireNotarized = requireNotarized
            policy.requireAppStore = requireAppStore
            policy.defaultAction = defaultAction
            
            let result = SecurityPolicyManager.checkAppAgainstPolicy(at: path, policy: policy)
            let signature = SecurityPolicyManager.verifyCodeSignature(at: path)
            
            if json {
                let report = PolicyCheckReport(path: path, policy: policy, result: result, signature: signature)
                let encoder = JSONEncoder()
                encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
                let data = try encoder.encode(report)
                print(String(decoding: data, as: UTF8.self))
                return
            }
            
            print("╭──────────────────────────────╮")
            print("│  Policy Evaluation           │")
            print("╰──────────────────────────────╯")
            print("  Path:           \(path)")
            print("  Result:         \(result.allowed ? "✓ Allowed" : "✗ Blocked")")
            print("  Reason:         \(result.reason)")
            print("  Matched Rule:   \(result.matchedRule)")
            print("  Signed:         \(signature.isSigned ? "Yes" : "No")")
            if signature.isSigned {
                if let team = signature.teamID {
                    print("  Team ID:       \(team)")
                }
                if let identity = signature.signingIdentity {
                    print("  Identity:      \(identity)")
                }
            }
        }
    }
    
    // MARK: - TCC/PPPC status
    struct TCC: ParsableCommand {
        static let configuration = CommandConfiguration(
            commandName: "tcc",
            abstract: "List cached TCC/PPPC decisions"
        )
        
        @Flag(name: .long, help: "Only include system database entries")
        var systemOnly = false
        
        @Option(name: .long, help: "Filter by service name or identifier")
        var service: String?
        
        @Flag(name: .long, help: "Output as JSON")
        var json = false
        
        func run() throws {
            var entries = SecurityPolicyManager.getTCCStatus()
            
            if systemOnly {
                entries = entries.filter { $0.isSystemLevel }
            }
            
            if let filter = service?.lowercased(), !filter.isEmpty {
                entries = entries.filter {
                    $0.service.lowercased().contains(filter) ||
                    $0.serviceName.lowercased().contains(filter)
                }
            }
            
            if json {
                let encoder = JSONEncoder()
                encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
                let data = try encoder.encode(entries)
                print(String(decoding: data, as: UTF8.self))
                return
            }
            
            if entries.isEmpty {
                print("No TCC entries found for the specified filter.")
                return
            }
            
            print("Service                          Scope    Decision")
            print("──────────────────────────────── ──────── ────────")
            for entry in entries {
                let scope = entry.isSystemLevel ? "System" : "User"
                let decision: String
                if let allowed = entry.allowed {
                    decision = allowed ? "Allowed" : "Denied"
                } else {
                    decision = "Unknown"
                }
                let name = pad(entry.serviceName, width: 30)
                let scopeColumn = pad(scope, width: 8)
                print("\(name)  \(scopeColumn)  \(decision)")
            }
        }
    }
    
    // MARK: - System Extensions
    struct SystemExtensions: ParsableCommand {
        static let configuration = CommandConfiguration(
            commandName: "sysext",
            abstract: "List installed system extensions"
        )
        
        @Option(name: .long, help: "Filter by Team ID")
        var team: String?
        
        @Option(name: .long, help: "Filter by bundle identifier substring")
        var bundle: String?
        
        @Flag(name: .long, help: "Output as JSON")
        var json = false
        
        func run() throws {
            var extensions = SecurityPolicyManager.getSystemExtensions()
            
            if let teamFilter = team?.lowercased(), !teamFilter.isEmpty {
                extensions = extensions.filter { ($0.teamID ?? "").lowercased().contains(teamFilter) }
            }
            
            if let bundleFilter = bundle?.lowercased(), !bundleFilter.isEmpty {
                extensions = extensions.filter { $0.bundleIdentifier.lowercased().contains(bundleFilter) }
            }
            
            if json {
                let encoder = JSONEncoder()
                encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
                let data = try encoder.encode(extensions)
                print(String(decoding: data, as: UTF8.self))
                return
            }
            
            if extensions.isEmpty {
                print("No system extensions match the provided filters.")
                return
            }
            
            print("Bundle Identifier                           Team        Version      State")
            print("─────────────────────────────────────────── ─────────── ─────────── ─────")
            for ext in extensions {
                let teamID = ext.teamID ?? "?"
                let version = ext.version ?? "?"
                let identifierColumn = pad(ext.bundleIdentifier, width: 43)
                let teamColumn = pad(teamID, width: 10)
                let versionColumn = pad(version, width: 11)
                print("\(identifierColumn) \(teamColumn) \(versionColumn) \(ext.state)")
            }
        }
    }
    
    // MARK: - Generate profiles
    struct Generate: ParsableCommand {
        static let configuration = CommandConfiguration(
            commandName: "generate",
            abstract: "Generate security-related configuration profiles",
            subcommands: [PPPC.self, SystemExtension.self, Gatekeeper.self],
            defaultSubcommand: PPPC.self
        )
        
        struct PPPC: ParsableCommand {
            static let configuration = CommandConfiguration(
                commandName: "pppc",
                abstract: "Generate a PPPC (Privacy) profile"
            )
            
            @Option(name: .shortAndLong, help: "Profile identifier")
            var identifier: String = "com.example.pppc"
            
            @Option(name: .shortAndLong, help: "Organization name")
            var organization: String = "Organization"
            
            @Option(name: .shortAndLong, help: "Output file path")
            var output: String?
            
            @Option(name: .long, parsing: .upToNextOption, help: "Bundle identifiers to allow")
            var allowBundle: [String] = []
            
            @Option(name: .long, parsing: .upToNextOption, help: "Bundle identifiers to deny")
            var denyBundle: [String] = []
            
            @Option(name: .long, help: "Team identifier applied to the rules")
            var teamIdentifier: String?
            
            func run() throws {
                var rules: [PPPCRule] = []
                rules += allowBundle.map { PPPCRule(bundleIdentifier: $0, teamIdentifier: teamIdentifier, codeRequirement: nil, allowed: true, authorization: .allow) }
                rules += denyBundle.map { PPPCRule(bundleIdentifier: $0, teamIdentifier: teamIdentifier, codeRequirement: nil, allowed: false, authorization: .deny) }
                
                guard !rules.isEmpty else {
                    throw ValidationError("Provide at least one --allow-bundle or --deny-bundle entry")
                }
                
                let profile = SecurityPolicyManager.generatePPPCProfile(
                    identifier: identifier,
                    organization: organization,
                    rules: rules
                )
                
                if let outputPath = output {
                    try profile.write(toFile: outputPath, atomically: true, encoding: .utf8)
                    print("✓ PPPC profile written to \(outputPath)")
                } else {
                    print(profile)
                }
            }
        }
        
        struct SystemExtension: ParsableCommand {
            static let configuration = CommandConfiguration(
                commandName: "sysext",
                abstract: "Generate a System Extension profile"
            )
            
            @Option(name: .shortAndLong, help: "Profile identifier")
            var identifier: String = "com.example.sysext"
            
            @Option(name: .shortAndLong, help: "Organization name")
            var organization: String = "Organization"
            
            @Option(name: .shortAndLong, help: "Output file path")
            var output: String?
            
            @Option(name: .long, parsing: .upToNextOption, help: "Allowed Team IDs")
            var allowTeam: [String] = []
            
            @Option(name: .long, parsing: .upToNextOption, help: "Allowed extensions in TEAMID:bundle.identifier format")
            var allowExtension: [String] = []
            
            func run() throws {
                if allowTeam.isEmpty && allowExtension.isEmpty {
                    throw ValidationError("Provide --allow-team and/or --allow-extension entries")
                }
                
                var grouped: [String: [String]] = [:]
                for entry in allowExtension {
                    let parts = entry.split(separator: ":", maxSplits: 1).map { String($0) }
                    guard parts.count == 2 else {
                        throw ValidationError("Invalid --allow-extension value: \(entry). Use TEAMID:bundle.identifier")
                    }
                    grouped[parts[0], default: []].append(parts[1])
                }
                
                let allowedExtensions = grouped.map { (teamID: $0.key, bundleIDs: $0.value) }
                let profile = SecurityPolicyManager.generateSystemExtensionProfile(
                    identifier: identifier,
                    organization: organization,
                    allowedTeamIDs: allowTeam,
                    allowedExtensions: allowedExtensions
                )
                
                if let outputPath = output {
                    try profile.write(toFile: outputPath, atomically: true, encoding: .utf8)
                    print("✓ System Extension profile written to \(outputPath)")
                } else {
                    print(profile)
                }
            }
        }
        
        struct Gatekeeper: ParsableCommand {
            static let configuration = CommandConfiguration(
                commandName: "gatekeeper",
                abstract: "Generate a Gatekeeper enforcement profile"
            )
            
            @Option(name: .shortAndLong, help: "Profile identifier")
            var identifier: String = "com.example.gatekeeper"
            
            @Option(name: .shortAndLong, help: "Organization name")
            var organization: String = "Organization"
            
            @Option(name: .long, help: "Gatekeeper level (disabled, appStoreOnly, appStoreAndIdentified)")
            var level: GatekeeperLevel = .appStoreAndIdentified
            
            @Flag(name: .long, help: "Allow users to override Gatekeeper")
            var allowOverride = false
            
            @Option(name: .shortAndLong, help: "Output file path")
            var output: String?
            
            func run() throws {
                let profile = SecurityPolicyManager.generateGatekeeperProfile(
                    identifier: identifier,
                    organization: organization,
                    level: level,
                    disableOverride: !allowOverride
                )
                
                if let outputPath = output {
                    try profile.write(toFile: outputPath, atomically: true, encoding: .utf8)
                    print("✓ Gatekeeper profile written to \(outputPath)")
                } else {
                    print(profile)
                }
            }
        }
    }
}

private func pad(_ value: String, width: Int) -> String {
    guard value.count < width else { return value }
    return value + String(repeating: " ", count: width - value.count)
}

private struct PolicyCheckReport: Codable {
    let path: String
    let policy: AppPolicy
    let result: PolicyResult
    let signature: CodeSignatureInfo
}

extension GatekeeperLevel: ExpressibleByArgument {
    init?(argument: String) {
        switch argument.lowercased() {
        case "disabled":
            self = .disabled
        case "appstoreonly", "app-store-only", "appstore":
            self = .appStoreOnly
        case "appstoreandidentified", "app-store-and-identified", "identified":
            self = .appStoreAndIdentified
        default:
            return nil
        }
    }
}

extension PolicyAction: ExpressibleByArgument {}
