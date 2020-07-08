import Foundation
import Capacitor
import LocalAuthentication
import Security

/**
 * Please read the Capacitor iOS Plugin Development Guide
 * here: https://capacitor.ionicframework.com/docs/plugins/ios
 */
@objc(BiometricAuth)
public class BiometricAuth: CAPPlugin {
    let codeKey = "code"

    @objc func isAvailable(_ call: CAPPluginCall) {
        var authError: NSError?
        let localAuthenticationContext = LAContext()
        localAuthenticationContext.localizedFallbackTitle = "Gebruik toegangscode"
        if localAuthenticationContext.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &authError) {
            call.resolve(["has": true])
        } else {
            guard let error = authError else {
                return
            }
            var errorCode = 0
            if #available(iOS 11.0, macOS 10.13, *) {
                switch error.code {
                case LAError.biometryNotAvailable.rawValue:
                    errorCode = 1

                case LAError.biometryLockout.rawValue:
                    errorCode = 2 //"Authentication could not continue because the user has been locked out of biometric authentication, due to failing authentication too many times."

                case LAError.biometryNotEnrolled.rawValue:
                    errorCode = 3//message = "Authentication could not start because the user has not enrolled in biometric authentication."

                default:
                    errorCode = 999 //"Did not find error code on LAError object"
                }
            }
            else {
                switch error.code {
                case LAError.touchIDLockout.rawValue:
                    errorCode = 2

                case LAError.touchIDNotAvailable.rawValue:
                    errorCode = 1

                case LAError.touchIDNotEnrolled.rawValue:
                    errorCode = 3

                default:
                    errorCode = 999
                }
            }

            call.resolve(["has": false, "status": errorCode])
        }
    }

    @objc func store(_ call: CAPPluginCall) {
        let localAuthenticationContext = LAContext()
        localAuthenticationContext.localizedFallbackTitle = "Gebruik toegangscode"

        if !localAuthenticationContext.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: nil) {
            call.resolve(["stored": false])
            return
        }

        guard let code = call.getString("code") else {
            call.resolve(["stored": false])
            return
        }

        let data = code.data(using: .utf8)!

        if KeyChain.save(key: self.codeKey, data: data) == noErr {
            call.resolve(["stored": true])
        } else {
            call.resolve(["stored": false])
        }
    }

    @objc func verify(_ call: CAPPluginCall) {
        let localAuthenticationContext = LAContext()
        let reasonString = call.getString("reason") ?? "To access the secure data"
        localAuthenticationContext.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: reasonString) { success, evaluateError in
            if success {
                if let data = KeyChain.load(key: self.codeKey, context: localAuthenticationContext) {
                    call.resolve(["verified": true, "code": String(data: data, encoding: .utf8)])
                } else {
                    call.reject("Auth failed", nil, ["verified": false, "status": "no-data-available"] as? Error)
                }
            } else {
                var errorCode = 0
                guard let error = evaluateError else {
                    return
                }
                switch error._code {

                case LAError.authenticationFailed.rawValue:
                    errorCode = 10 //"The user failed to provide valid credentials"

                case LAError.appCancel.rawValue:
                    errorCode = 11 // "Authentication was cancelled by application"

                case LAError.invalidContext.rawValue:
                    errorCode = 12 // "The context is invalid"

                case LAError.notInteractive.rawValue:
                    errorCode = 13 // "Not interactive"

                case LAError.passcodeNotSet.rawValue:
                    errorCode = 14 // "Passcode is not set on the device"

                case LAError.systemCancel.rawValue:
                    errorCode = 15 // "Authentication was cancelled by the system"

                case LAError.userCancel.rawValue:
                    errorCode = 16 // "The user did cancel"

                case LAError.userFallback.rawValue:
                    errorCode = 17 // "The user chose to use the fallback"

                default:
                    errorCode = self.evaluatePolicyFailErrorMessageForLA(errorCode: error._code)
                }

                call.reject("Auth failed", nil, ["verified": false, "status": errorCode] as? Error)
            }
        }
    }

    @objc func evaluatePolicyFailErrorMessageForLA(errorCode: Int) -> Int {
        var errorCode = 0
        if #available(iOS 11.0, macOS 10.13, *) {
            switch errorCode {
            case LAError.biometryNotAvailable.rawValue:
                errorCode = 1

            case LAError.biometryLockout.rawValue:
                errorCode = 2 //"Authentication could not continue because the user has been locked out of biometric authentication, due to failing authentication too many times."

            case LAError.biometryNotEnrolled.rawValue:
                errorCode = 3//message = "Authentication could not start because the user has not enrolled in biometric authentication."

            default:
                errorCode = 999 //"Did not find error code on LAError object"
            }
        } else {
            switch errorCode {
            case LAError.touchIDLockout.rawValue:
                errorCode = 2

            case LAError.touchIDNotAvailable.rawValue:
                errorCode = 1

            case LAError.touchIDNotEnrolled.rawValue:
                errorCode = 3

            default:
                errorCode = 999
            }
        }

        return errorCode;
    }
}

class KeyChain {

    class func save(key: String, data: Data) -> OSStatus {
        let query = [
            kSecClass as String       : kSecClassGenericPassword as String,
            kSecAttrAccount as String : key,
            kSecAttrAccessControl as String: getBioSecAccessControl(),
            kSecValueData as String   : data ] as [String : Any]

        SecItemDelete(query as CFDictionary)

        return SecItemAdd(query as CFDictionary, nil)
    }

    class func load(key: String, context: LAContext) -> Data? {
        let query = [
            kSecClass as String       : kSecClassGenericPassword,
            kSecAttrAccount as String : key,
            kSecReturnData as String  : kCFBooleanTrue!,
            kSecMatchLimit as String  : kSecMatchLimitOne,
            kSecUseAuthenticationContext as String: context] as [String : Any]

        var dataTypeRef: AnyObject? = nil

        let status: OSStatus = SecItemCopyMatching(query as CFDictionary, &dataTypeRef)

        if status == noErr {
            return dataTypeRef as! Data?
        } else {
            return nil
        }
    }

    class func createUniqueID() -> String {
        let uuid: CFUUID = CFUUIDCreate(nil)
        let cfStr: CFString = CFUUIDCreateString(nil, uuid)

        let swiftString: String = cfStr as String
        return swiftString
    }

    static func getBioSecAccessControl() -> SecAccessControl {
        var access: SecAccessControl?
        var error: Unmanaged<CFError>?

        access = SecAccessControlCreateWithFlags(nil,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            .userPresence,
            &error)

        precondition(access != nil, "SecAccessControlCreateWithFlags failed")
        return access!
    }
}

extension Data {

    init<T>(from value: T) {
        var value = value
        self.init(buffer: UnsafeBufferPointer(start: &value, count: 1))
    }

    func to<T>(type: T.Type) -> T {
        return self.withUnsafeBytes { $0.load(as: T.self) }
    }
}
