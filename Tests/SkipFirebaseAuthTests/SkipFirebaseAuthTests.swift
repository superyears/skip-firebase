// Copyright 2024–2026 Skip
// SPDX-License-Identifier: MPL-2.0
import XCTest
import OSLog
import Foundation
#if !SKIP
import FirebaseCore
import FirebaseAuth
#else
import SkipFirebaseCore
import SkipFirebaseAuth
#endif

let logger: Logger = Logger(subsystem: "SkipBase", category: "Tests")

@MainActor final class SkipFirebaseAuthTests: XCTestCase {
    func testSkipFirebaseAuthTests() async throws {
        if false {
            let auth: Auth = Auth.auth()
            let _: Auth = Auth.auth(app: FirebaseApp.app()!)
            let listener = auth.addStateDidChangeListener({ _, _ in })
#if SKIP || os(iOS)
            let phoneProvider = PhoneAuthProvider.provider(auth: auth)
            let _: AuthCredential = phoneProvider.credential(withVerificationID: "verification-id", verificationCode: "123456")
            phoneProvider.verifyPhoneNumber("+15555550123") { _, _ in }
            let _: String = try await phoneProvider.verifyPhoneNumber("+15555550123")
            let _: PhoneAuthVerificationResult = try await phoneProvider.verifyPhoneNumberResult("+15555550123")
#endif
            do {
                let signIn = try await auth.signInAnonymously()
                XCTAssertNotNil(signIn.user.metadata.creationDate)
                XCTAssertNotNil(signIn.user.metadata.lastSignInDate)
            } catch {
            }
            auth.removeStateDidChangeListener(listener)
        }
    }
}
