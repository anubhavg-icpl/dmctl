import Foundation
import Security

/// MDM Server Client - Communicates with NanoMDM or compatible MDM servers
/// Uses Apple's MDM protocol over HTTP with binary plist encoding
class MDMServerClient {
    
    let serverURL: URL
    let apiKey: String?
    
    init(serverURL: URL, apiKey: String? = nil) {
        self.serverURL = serverURL
        self.apiKey = apiKey
    }
    
    // MARK: - API Endpoints
    
    /// Enqueue an MDM command to a device
    func enqueueCommand(enrollmentID: String, command: MDMCommand, noPush: Bool = false) async throws -> EnqueueResponse {
        var urlString = serverURL.appendingPathComponent("/v1/enqueue/\(enrollmentID)").absoluteString
        if noPush {
            urlString += "?nopush=1"
        }
        
        guard let url = URL(string: urlString) else {
            throw MDMClientError.invalidURL
        }
        
        var request = URLRequest(url: url)
        request.httpMethod = "PUT"
        request.setValue("application/x-apple-aspen-mdm", forHTTPHeaderField: "Content-Type")
        addBasicAuth(to: &request)
        
        // Encode command to binary plist
        request.httpBody = try encodeCommandToPlist(command)
        
        let (data, response) = try await URLSession.shared.data(for: request)
        
        guard let httpResponse = response as? HTTPURLResponse else {
            throw MDMClientError.invalidResponse
        }
        
        guard httpResponse.statusCode == 200 else {
            throw MDMClientError.serverError(httpResponse.statusCode, String(data: data, encoding: .utf8))
        }
        
        return try JSONDecoder().decode(EnqueueResponse.self, from: data)
    }
    
    /// Send APNs push notification to wake device
    func sendPush(enrollmentID: String) async throws -> PushResponse {
        let url = serverURL.appendingPathComponent("/v1/push/\(enrollmentID)")
        
        var request = URLRequest(url: url)
        request.httpMethod = "GET"
        addBasicAuth(to: &request)
        
        let (data, response) = try await URLSession.shared.data(for: request)
        
        guard let httpResponse = response as? HTTPURLResponse else {
            throw MDMClientError.invalidResponse
        }
        
        guard httpResponse.statusCode == 200 else {
            throw MDMClientError.serverError(httpResponse.statusCode, String(data: data, encoding: .utf8))
        }
        
        return try JSONDecoder().decode(PushResponse.self, from: data)
    }
    
    /// Upload APNs push certificate
    func uploadPushCert(certPEM: String, keyPEM: String) async throws -> PushCertResponse {
        let url = serverURL.appendingPathComponent("/v1/pushcert")
        
        var request = URLRequest(url: url)
        request.httpMethod = "PUT"
        request.setValue("application/x-pem-file", forHTTPHeaderField: "Content-Type")
        addBasicAuth(to: &request)
        
        // Combine cert and key
        let pemData = (certPEM + "\n" + keyPEM).data(using: .utf8)
        request.httpBody = pemData
        
        let (data, response) = try await URLSession.shared.data(for: request)
        
        guard let httpResponse = response as? HTTPURLResponse else {
            throw MDMClientError.invalidResponse
        }
        
        guard httpResponse.statusCode == 200 else {
            throw MDMClientError.serverError(httpResponse.statusCode, String(data: data, encoding: .utf8))
        }
        
        return try JSONDecoder().decode(PushCertResponse.self, from: data)
    }
    
    /// Check server version
    func getVersion() async throws -> String {
        let url = serverURL.appendingPathComponent("/version")
        
        var request = URLRequest(url: url)
        request.httpMethod = "GET"
        
        let (data, _) = try await URLSession.shared.data(for: request)
        
        if let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
           let version = json["version"] as? String {
            return version
        }
        
        return String(data: data, encoding: .utf8) ?? "Unknown"
    }
    
    // MARK: - Check-in Simulation (for testing)
    
    /// Simulate device check-in (Authenticate message)
    func simulateAuthenticate(udid: String, topic: String, serialNumber: String? = nil) async throws -> Data {
        let url = serverURL.appendingPathComponent("/mdm")
        
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/x-apple-aspen-mdm-checkin", forHTTPHeaderField: "Content-Type")
        
        // Build Authenticate plist
        var authDict: [String: Any] = [
            "MessageType": "Authenticate",
            "UDID": udid,
            "Topic": topic
        ]
        
        if let serial = serialNumber {
            authDict["SerialNumber"] = serial
        }
        
        request.httpBody = try PropertyListSerialization.data(fromPropertyList: authDict, format: .binary, options: 0)
        
        let (data, _) = try await URLSession.shared.data(for: request)
        return data
    }
    
    /// Simulate TokenUpdate check-in
    func simulateTokenUpdate(udid: String, topic: String, pushToken: Data, pushMagic: String) async throws -> Data {
        let url = serverURL.appendingPathComponent("/mdm")
        
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/x-apple-aspen-mdm-checkin", forHTTPHeaderField: "Content-Type")
        
        let tokenUpdateDict: [String: Any] = [
            "MessageType": "TokenUpdate",
            "UDID": udid,
            "Topic": topic,
            "Token": pushToken,
            "PushMagic": pushMagic
        ]
        
        request.httpBody = try PropertyListSerialization.data(fromPropertyList: tokenUpdateDict, format: .binary, options: 0)
        
        let (data, _) = try await URLSession.shared.data(for: request)
        return data
    }
    
    // MARK: - Private Helpers
    
    private func addBasicAuth(to request: inout URLRequest) {
        guard let apiKey = apiKey else { return }
        
        let credentials = "nanomdm:\(apiKey)"
        if let credData = credentials.data(using: .utf8) {
            let base64Creds = credData.base64EncodedString()
            request.setValue("Basic \(base64Creds)", forHTTPHeaderField: "Authorization")
        }
    }
    
    private func encodeCommandToPlist(_ command: MDMCommand) throws -> Data {
        let commandDict: [String: Any] = [
            "CommandUUID": command.uuid,
            "Command": [
                "RequestType": command.requestType
            ] as [String: Any]
        ]
        
        return try PropertyListSerialization.data(fromPropertyList: commandDict, format: .binary, options: 0)
    }
}

// MARK: - Models

struct MDMCommand {
    let uuid: String
    let requestType: String
    var payload: [String: Any] = [:]
    
    init(requestType: String, uuid: String = UUID().uuidString, payload: [String: Any] = [:]) {
        self.uuid = uuid
        self.requestType = requestType
        self.payload = payload
    }
    
    func toPlist() -> [String: Any] {
        var cmdDict: [String: Any] = ["RequestType": requestType]
        for (key, value) in payload {
            cmdDict[key] = value
        }
        
        return [
            "CommandUUID": uuid,
            "Command": cmdDict
        ]
    }
}

struct EnqueueResponse: Codable {
    let commandUUID: String?
    let requestType: String?
    let pushError: String?
    
    enum CodingKeys: String, CodingKey {
        case commandUUID = "command_uuid"
        case requestType = "request_type"
        case pushError = "push_error"
    }
}

struct PushResponse: Codable {
    let id: String?
    let error: String?
}

struct PushCertResponse: Codable {
    let topic: String
}

enum MDMClientError: Error, CustomStringConvertible {
    case invalidURL
    case invalidResponse
    case serverError(Int, String?)
    case encodingError
    case decodingError
    
    var description: String {
        switch self {
        case .invalidURL:
            return "Invalid server URL"
        case .invalidResponse:
            return "Invalid response from server"
        case .serverError(let code, let message):
            return "Server error \(code): \(message ?? "Unknown")"
        case .encodingError:
            return "Failed to encode request"
        case .decodingError:
            return "Failed to decode response"
        }
    }
}

// MARK: - Check-in Message Builders

enum CheckInMessage {
    
    /// Build Authenticate message plist
    static func authenticate(udid: String, topic: String, serialNumber: String? = nil, model: String? = nil) -> [String: Any] {
        var dict: [String: Any] = [
            "MessageType": "Authenticate",
            "UDID": udid,
            "Topic": topic,
            "BuildVersion": ProcessInfo.processInfo.operatingSystemVersionString
        ]
        
        if let serial = serialNumber {
            dict["SerialNumber"] = serial
        }
        if let model = model {
            dict["Model"] = model
        }
        
        return dict
    }
    
    /// Build TokenUpdate message plist
    static func tokenUpdate(udid: String, topic: String, token: Data, pushMagic: String, unlockToken: Data? = nil) -> [String: Any] {
        var dict: [String: Any] = [
            "MessageType": "TokenUpdate",
            "UDID": udid,
            "Topic": topic,
            "Token": token,
            "PushMagic": pushMagic
        ]
        
        if let unlock = unlockToken {
            dict["UnlockToken"] = unlock
        }
        
        return dict
    }
    
    /// Build CheckOut message plist
    static func checkOut(udid: String, topic: String) -> [String: Any] {
        return [
            "MessageType": "CheckOut",
            "UDID": udid,
            "Topic": topic
        ]
    }
    
    /// Build command result report
    static func commandResult(udid: String, commandUUID: String, status: String, errorChain: [[String: Any]]? = nil) -> [String: Any] {
        var dict: [String: Any] = [
            "UDID": udid,
            "CommandUUID": commandUUID,
            "Status": status
        ]
        
        if let errors = errorChain {
            dict["ErrorChain"] = errors
        }
        
        return dict
    }
    
    /// Encode to binary plist
    static func encode(_ message: [String: Any]) throws -> Data {
        return try PropertyListSerialization.data(fromPropertyList: message, format: .binary, options: 0)
    }
}
