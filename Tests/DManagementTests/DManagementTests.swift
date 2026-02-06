import XCTest
@testable import DManagement

final class DManagementTests: XCTestCase {
    
    func testMDMCommandGeneration() throws {
        // Test simple command generation
        let command = try MDMCommandGenerator.generate(requestType: "ProfileList")
        XCTAssertTrue(command.contains("ProfileList"))
        XCTAssertTrue(command.contains("CommandUUID"))
        XCTAssertTrue(command.contains("RequestType"))
    }
    
    func testDeviceInformationCommand() throws {
        let command = try MDMCommandGenerator.generate(requestType: "DeviceInformation")
        XCTAssertTrue(command.contains("DeviceInformation"))
        XCTAssertTrue(command.contains("Queries"))
        XCTAssertTrue(command.contains("UDID"))
        XCTAssertTrue(command.contains("SerialNumber"))
    }
    
    func testUnknownCommandThrows() {
        XCTAssertThrowsError(try MDMCommandGenerator.generate(requestType: "InvalidCommand"))
    }
    
    func testProfileGeneration() throws {
        // Test WiFi profile generation
        let wifiProfile = try ProfileGenerator.generate(
            type: "wifi",
            identifier: "com.test.wifi",
            organization: "Test Org"
        )
        XCTAssertTrue(wifiProfile.contains("com.apple.wifi.managed"))
        XCTAssertTrue(wifiProfile.contains("com.test.wifi"))
        XCTAssertTrue(wifiProfile.contains("Test Org"))
    }
    
    func testVPNProfileGeneration() throws {
        let vpnProfile = try ProfileGenerator.generate(
            type: "vpn",
            identifier: "com.test.vpn",
            organization: "Test Org"
        )
        XCTAssertTrue(vpnProfile.contains("com.apple.vpn.managed"))
        XCTAssertTrue(vpnProfile.contains("IKEv2"))
    }
    
    func testUnknownProfileTypeThrows() {
        XCTAssertThrowsError(try ProfileGenerator.generate(
            type: "unknown",
            identifier: "com.test",
            organization: "Test"
        ))
    }
    
    func testGatekeeperProfileGenerationIncludesSettings() {
        let profile = SecurityPolicyManager.generateGatekeeperProfile(
            identifier: "com.test.gatekeeper",
            organization: "Test Org",
            level: .appStoreOnly,
            disableOverride: true
        )
        XCTAssertTrue(profile.contains("com.apple.systempolicy.control"))
        XCTAssertTrue(profile.contains("DisableOverride"))
    }
}
