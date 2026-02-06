import Foundation
import Security

// MARK: - Certificate Models
struct CertificateInfo: Codable {
    let commonName: String
    let issuer: String
    let serialNumber: String
    let expirationDate: String
    let isValid: Bool
    let keychain: String
}

// MARK: - Certificate Manager (Using Security Framework)
enum CertificateManager {
    
    static func listCertificates(keychain: String) throws -> [CertificateInfo] {
        var certs: [CertificateInfo] = []
        
        // Build query for certificates using Security framework
        var query: [String: Any] = [
            kSecClass as String: kSecClassCertificate,
            kSecReturnRef as String: true,
            kSecMatchLimit as String: kSecMatchLimitAll
        ]
        
        // Optionally specify keychain
        if keychain.lowercased() == "system" {
            if let systemKeychain = getSystemKeychain() {
                query[kSecMatchSearchList as String] = [systemKeychain]
            }
        } else if keychain.lowercased() == "login" {
            if let loginKeychain = getLoginKeychain() {
                query[kSecMatchSearchList as String] = [loginKeychain]
            }
        }
        
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        
        guard status == errSecSuccess, let items = result as? [SecCertificate] else {
            return certs
        }
        
        for cert in items {
            if let certInfo = parseCertificate(cert, keychain: keychain) {
                certs.append(certInfo)
            }
        }
        
        return certs
    }
    
    private static func getSystemKeychain() -> SecKeychain? {
        var keychain: SecKeychain?
        let status = SecKeychainOpen("/Library/Keychains/System.keychain", &keychain)
        return status == errSecSuccess ? keychain : nil
    }
    
    private static func getLoginKeychain() -> SecKeychain? {
        var keychain: SecKeychain?
        let status = SecKeychainCopyDefault(&keychain)
        return status == errSecSuccess ? keychain : nil
    }
    
    private static func parseCertificate(_ cert: SecCertificate, keychain: String) -> CertificateInfo? {
        // Get common name
        var commonName: CFString?
        SecCertificateCopyCommonName(cert, &commonName)
        let name = (commonName as String?) ?? "Unknown"
        
        // Parse certificate details using Security framework
        var issuer = "Unknown"
        var serialNumber = "Unknown"
        var expirationDate = "Unknown"
        var isValid = true
        
        // Get certificate values
        let keys: [CFString] = [
            kSecOIDX509V1IssuerName,
            kSecOIDX509V1SerialNumber,
            kSecOIDX509V1ValidityNotAfter
        ]
        
        if let values = SecCertificateCopyValues(cert, keys as CFArray, nil) as? [String: Any] {
            // Parse issuer
            if let issuerDict = values[kSecOIDX509V1IssuerName as String] as? [String: Any],
               let issuerValue = issuerDict[kSecPropertyKeyValue as String] as? [[String: Any]] {
                for component in issuerValue {
                    if let label = component[kSecPropertyKeyLabel as String] as? String,
                       label == "2.5.4.3", // Common Name OID
                       let value = component[kSecPropertyKeyValue as String] as? String {
                        issuer = value
                        break
                    }
                }
                // Fallback: get organization name
                if issuer == "Unknown" {
                    for component in issuerValue {
                        if let label = component[kSecPropertyKeyLabel as String] as? String,
                           label == "2.5.4.10", // Organization OID
                           let value = component[kSecPropertyKeyValue as String] as? String {
                            issuer = value
                            break
                        }
                    }
                }
            }
            
            // Parse serial number
            if let serialDict = values[kSecOIDX509V1SerialNumber as String] as? [String: Any],
               let serial = serialDict[kSecPropertyKeyValue as String] as? String {
                serialNumber = serial
            }
            
            // Parse expiration date
            if let expiryDict = values[kSecOIDX509V1ValidityNotAfter as String] as? [String: Any],
               let expiryValue = expiryDict[kSecPropertyKeyValue as String] {
                if let date = expiryValue as? Date {
                    let formatter = DateFormatter()
                    formatter.dateStyle = .medium
                    formatter.timeStyle = .short
                    expirationDate = formatter.string(from: date)
                    isValid = date > Date()
                } else if let expiryNum = expiryValue as? NSNumber {
                    let date = Date(timeIntervalSinceReferenceDate: expiryNum.doubleValue)
                    let formatter = DateFormatter()
                    formatter.dateStyle = .medium
                    formatter.timeStyle = .short
                    expirationDate = formatter.string(from: date)
                    isValid = date > Date()
                }
            }
        }
        
        // Additional validation via trust evaluation
        var trust: SecTrust?
        let policy = SecPolicyCreateBasicX509()
        if SecTrustCreateWithCertificates(cert, policy, &trust) == errSecSuccess,
           let trust = trust {
            var error: CFError?
            isValid = SecTrustEvaluateWithError(trust, &error) && isValid
        }
        
        return CertificateInfo(
            commonName: name,
            issuer: issuer,
            serialNumber: serialNumber,
            expirationDate: expirationDate,
            isValid: isValid,
            keychain: keychain
        )
    }
}
