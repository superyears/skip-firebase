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
            let _: (String, String) async throws -> EmailSignInResult = auth.signInResult(withEmail:password:)
            let phoneProvider = PhoneAuthProvider.provider(auth: auth)
            let _: AuthCredential = phoneProvider.credential(withVerificationID: "verification-id", verificationCode: "123456")
            phoneProvider.verifyPhoneNumber("+15555550123") { _, _ in }
            let _: String = try await phoneProvider.verifyPhoneNumber("+15555550123")
            let _: PhoneAuthVerificationResult = try await phoneProvider.verifyPhoneNumberResult("+15555550123")
            let _: (AuthCredential) -> PhoneMultiFactorAssertion = PhoneMultiFactorGenerator.assertion(with:)
            let _: (PhoneMultiFactorInfo, Any?, MultiFactorSession, @escaping (String?, Error?) -> Void) -> Void = phoneProvider.verifyPhoneNumber(with:uiDelegate:multiFactorSession:completion:)
            let _: (PhoneMultiFactorInfo, Any?, MultiFactorSession) async throws -> String = phoneProvider.verifyPhoneNumber(with:uiDelegate:multiFactorSession:)
            let _: (PhoneMultiFactorInfo, Any?, MultiFactorSession, TimeInterval, PhoneAuthResendingToken?) async throws -> PhoneAuthVerificationResult = phoneProvider.verifyPhoneNumberResult(with:uiDelegate:multiFactorSession:timeout:forceResendingToken:)
            let _: (MultiFactorResolver) -> [MultiFactorInfo] = { $0.hints }
            let _: (MultiFactorResolver) -> MultiFactorSession = { $0.session }
            let _: (MultiFactorResolver) -> Auth = { $0.auth }
            let _: (Error) -> AuthErrorCode? = authErrorCode(for:)
            let _: (Error) -> MultiFactorResolver? = multiFactorResolver(for:)
            let _: (MultiFactorResolver, MultiFactorAssertion) async throws -> AuthDataResult = { resolver, assertion in
                try await resolver.resolveSignIn(with: assertion)
            }
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
