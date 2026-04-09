// Copyright 2025–2026 Skip
// SPDX-License-Identifier: MPL-2.0
#if !SKIP_BRIDGE
#if SKIP
import Foundation
import SkipFirebaseCore
import android.app.Activity
import kotlinx.coroutines.tasks.await
import android.net.Uri
import java.util.concurrent.TimeUnit
import skip.ui.__

// https://firebase.google.com/docs/reference/swift/firebaseauth/api/reference/Classes/Auth
// https://firebase.google.com/docs/reference/android/com/google/firebase/auth/FirebaseAuth

/// Shared first-factor email/password sign-in outcome.
///
/// On Android, callers outside transpiled `SKIP` code should prefer `signInResult(withEmail:password:)`
/// for MFA-aware flows because the underlying Kotlin exception type is not preserved once it crosses back
/// into native Swift.
public enum EmailSignInResult {
    case signedIn(AuthDataResult)
    case secondFactorRequired(MultiFactorResolver)
}

public final class Auth {
    public let platformValue: com.google.firebase.auth.FirebaseAuth

    public init(platformValue: com.google.firebase.auth.FirebaseAuth) {
        self.platformValue = platformValue
    }

    public static func auth() -> Auth {
        Auth(platformValue: com.google.firebase.auth.FirebaseAuth.getInstance())
    }

    public static func auth(app: FirebaseApp) -> Auth {
        Auth(platformValue: com.google.firebase.auth.FirebaseAuth.getInstance(app.app))
    }

    public var app: FirebaseApp {
        FirebaseApp(app: platformValue.getApp())
    }

    public var currentUser: User? {
        guard let user = platformValue.currentUser else { return nil }
        return User(user)
    }

    /// Throws `FirebaseAuthInvalidUserException`/`FirebaseAuthInvalidCredentialsException`/`FirebaseAuthInvalidCredentialsException`
    /// https://firebase.google.com/docs/reference/android/com/google/firebase/auth/FirebaseAuth#signInWithEmailAndPassword(java.lang.String,java.lang.String)
    public func signIn(withEmail email: String, password: String) async throws -> AuthDataResult {
        let result = platformValue.signInWithEmailAndPassword(email, password).await()
        return AuthDataResult(result)
    }

    /// Shared async sign-in API for MFA-aware email/password sign-in.
    ///
    /// Use this on Android when the caller is native Swift code rather than transpiled `SKIP` code.
    /// In that case, Firebase's `FirebaseAuthMultiFactorException` cannot be recovered reliably at the
    /// call site, so this API normalizes the flow to either a signed-in result or a resolver.
    public func signInResult(withEmail email: String, password: String) async throws -> EmailSignInResult {
        do {
            let result = try await signIn(withEmail: email, password: password)
            return .signedIn(result)
        } catch {
            if let resolver = multiFactorResolver(for: error) {
                return .secondFactorRequired(resolver)
            }
            throw error
        }
    }

    /// Throws `FirebaseAuthWeakPasswordException`/`FirebaseAuthInvalidCredentialsException`/`FirebaseAuthUserCollisionException`
    /// https://firebase.google.com/docs/reference/android/com/google/firebase/auth/FirebaseAuth#createUserWithEmailAndPassword(java.lang.String,java.lang.String)
    public func createUser(withEmail email: String, password: String) async throws -> AuthDataResult {
        let result = platformValue.createUserWithEmailAndPassword(email, password).await()
        return AuthDataResult(result)
    }

    /// Does not throw from Kotlin
    public func signOut() throws {
        platformValue.signOut()
    }

    /// Throws `FirebaseAuthInvalidUserException`
    public func sendPasswordReset(withEmail email: String) async throws {
        platformValue.sendPasswordResetEmail(email).await()
    }

    /// Throws `Exception`
    public func signInAnonymously() async throws -> AuthDataResult {
        let result = platformValue.signInAnonymously().await()
        return AuthDataResult(result)
    }

    public func useEmulator(withHost host: String, port: Int) {
        platformValue.useEmulator(host, port)
    }

    /// Throws `FirebaseAuthInvalidCredentialsException`
    /// https://firebase.google.com/docs/reference/android/com/google/firebase/auth/FirebaseAuth#signInWithCredential(com.google.firebase.auth.AuthCredential)
    public func signIn(with credential: AuthCredential) async throws -> AuthDataResult {
        let result = try platformValue.signInWithCredential(credential.platformValue).await()
        return AuthDataResult(result)
    }

    /// iOS-style completion API for sign-in with credential
    public func signIn(with credential: AuthCredential, completion: @escaping (AuthDataResult?, Error?) -> Void) {
        platformValue
            .signInWithCredential(credential.platformValue)
            .addOnSuccessListener { result in
                completion(AuthDataResult(result), nil)
            }
            .addOnFailureListener { exception in
                completion(nil, mapAuthNSError(exception))
            }
    }

    /// Interactive sign-in using an `OAuthProvider` (OIDC/SAML). Requires current Activity.
    /// Throws if there is no foreground Activity.
    /// https://firebase.google.com/docs/reference/android/com/google/firebase/auth/FirebaseAuth#startActivityForSignInWithProvider(android.app.Activity,com.google.firebase.auth.OAuthProvider)
    public func signIn(with provider: OAuthProvider) async throws -> AuthDataResult {
        guard let activity: Activity = UIApplication.shared.androidActivity else {
            throw NSError(domain: "SkipFirebaseAuth", code: -10, userInfo: [NSLocalizedDescriptionKey: "No current Android activity available for OAuth sign-in"])
        }
        let result = try platformValue.startActivityForSignInWithProvider(activity, provider.buildPlatformProvider()).await()
        return AuthDataResult(result)
    }

    /// Whether the specific URL is handled by Auth.
    /// On Android, map this to email-link detection.
    public func canHandle(_ url: URL) -> Bool {
        platformValue.isSignInWithEmailLink(url.absoluteString)
    }

    /// iOS-style completion API for interactive provider sign-in
    public func signIn(with provider: OAuthProvider, completion: @escaping (AuthDataResult?, Error?) -> Void) {
        guard let activity: Activity = UIApplication.shared.androidActivity else {
            completion(nil, NSError(domain: "SkipFirebaseAuth", code: -10, userInfo: [NSLocalizedDescriptionKey: "No current Android activity available for OAuth sign-in"]))
            return
        }
        platformValue
            .startActivityForSignInWithProvider(activity, provider.buildPlatformProvider())
            .addOnSuccessListener { result in
                completion(AuthDataResult(result), nil)
            }
            .addOnFailureListener { exception in
                completion(nil, mapAuthNSError(exception))
            }
    }

    /// iOS-compatible API to fetch sign-in methods for an email
    public func fetchSignInMethods(forEmail email: String, completion: @escaping ([String]?, Error?) -> Void) {
        platformValue
            .fetchSignInMethodsForEmail(email)
            .addOnSuccessListener { result in
                guard let methods = result.getSignInMethods() else { completion([], nil); return }
                var swift: [String] = []
                let iterator = methods.iterator()
                while iterator.hasNext() {
                    if let v = iterator.next() {
                        swift.append(String(describing: v))
                    }
                }
                completion(swift, nil)
            }
            .addOnFailureListener { exception in
                completion(nil, mapAuthNSError(exception))
            }
    }

    public func addStateDidChangeListener(_ listener: @escaping (Auth, User?) -> Void) -> AuthStateListener {
        let stateListener = com.google.firebase.auth.FirebaseAuth.AuthStateListener { auth in
            let user = auth.currentUser != nil ? User(auth.currentUser!) : nil
            listener(Auth(platformValue: auth), user)
        }
        platformValue.addAuthStateListener(stateListener)
        return AuthStateListener(platformValue: stateListener)
    }

    public func removeStateDidChangeListener(_ listenerHandle: Any) {
        if let handle = listenerHandle as? AuthStateListener {
            platformValue.removeAuthStateListener(handle.platformValue)
        }
    }
}

public class AuthDataResult: Equatable, KotlinConverting<com.google.firebase.auth.AuthResult> {
    public let platformValue: com.google.firebase.auth.AuthResult

    public init(_ platformValue: com.google.firebase.auth.AuthResult) {
        self.platformValue = platformValue
    }

    // SKIP @nooverride
    public override func kotlin(nocopy: Bool = false) -> com.google.firebase.auth.AuthResult {
        platformValue
    }

    public var description: String {
        platformValue.toString()
    }

    public static func == (lhs: Self, rhs: Self) -> Bool {
        lhs.platformValue == rhs.platformValue
    }

    public var user: User {
        User(platformValue.user!)
    }

    public var additionalUserInfo: AdditionalUserInfo? {
        guard let info = platformValue.additionalUserInfo else { return nil }
        return AdditionalUserInfo(info)
    }
}

public class AuthStateListener {
    public let platformValue: com.google.firebase.auth.FirebaseAuth.AuthStateListener

    public init(platformValue: com.google.firebase.auth.FirebaseAuth.AuthStateListener) {
        self.platformValue = platformValue
    }
}

public class User: Equatable, KotlinConverting<com.google.firebase.auth.FirebaseUser> {
    public let platformValue: com.google.firebase.auth.FirebaseUser

    public init(_ platformValue: com.google.firebase.auth.FirebaseUser) {
        self.platformValue = platformValue
    }

    // Bridging this function creates a Swift function that "overrides" nothing
    // SKIP @nobridge
    public override func kotlin(nocopy: Bool = false) -> com.google.firebase.auth.FirebaseUser {
        platformValue
    }

    public var description: String {
        platformValue.toString()
    }

    public static func == (lhs: Self, rhs: Self) -> Bool {
        lhs.platformValue == rhs.platformValue
    }

    public var isAnonymous: Bool {
        platformValue.isAnonymous
    }
    
    public var isEmailVerified: Bool {
        platformValue.isEmailVerified
    }

    public var providerID: String? {
        platformValue.providerId
    }

    public var uid: String {
        platformValue.uid
    }

    public var displayName: String? {
        platformValue.displayName
    }

    public var photoURL: URL? {
        guard let uri = platformValue.photoUrl else { return nil }
        return URL(string: uri.toString())!
    }

    public var email: String? {
        platformValue.email
    }

    public var phoneNumber: String? {
        platformValue.phoneNumber
    }

    public var metadata: UserMetadata {
        UserMetadata(platformValue.metadata)
    }

    public func createProfileChangeRequest() -> UserProfileChangeRequest {
        return UserProfileChangeRequest(self)
    }

    
    /// Throws `FirebaseAuthInvalidUserException`
    /// https://firebase.google.com/docs/reference/android/com/google/firebase/auth/FirebaseUser#sendemailverification
    public func sendEmailVerification() async throws {
        platformValue.sendEmailVerification().await()
    }
    
    /// Throws `FirebaseAuthInvalidUserException`/`FirebaseAuthRecentLoginRequiredException`
    /// https://firebase.google.com/docs/reference/android/com/google/firebase/auth/FirebaseUser#reauthenticate(com.google.firebase.auth.AuthCredential)
    public func reauthenticate(with credential: AuthCredential) async throws {
        platformValue.reauthenticate(credential.platformValue).await()
    }

    /// Link generic credential
    /// https://firebase.google.com/docs/reference/android/com/google/firebase/auth/FirebaseUser#linkwithcredential
    public func link(with credential: AuthCredential) async throws -> AuthDataResult {
        let result = try platformValue.linkWithCredential(credential.platformValue).await()
        return AuthDataResult(result)
    }

    /// iOS-style completion API for link with credential
    public func link(with credential: AuthCredential, completion: @escaping (AuthDataResult?, Error?) -> Void) {
        platformValue
            .linkWithCredential(credential.platformValue)
            .addOnSuccessListener { result in
                completion(AuthDataResult(result), nil)
            }
            .addOnFailureListener { exception in
                completion(nil, mapAuthNSError(exception))
            }
    }

    /// Interactive link with provider using current Activity
    /// https://firebase.google.com/docs/reference/android/com/google/firebase/auth/FirebaseUser#startactivityforlinkwithprovider(android.app.Activity,com.google.firebase.auth.OAuthProvider)
    public func link(with provider: OAuthProvider) async throws -> AuthDataResult {
        guard let activity: Activity = UIApplication.shared.androidActivity else {
            throw NSError(domain: "SkipFirebaseAuth", code: -11, userInfo: [NSLocalizedDescriptionKey: "No current Android activity available for OAuth link"])
        }
        let result = try platformValue.startActivityForLinkWithProvider(activity, provider.buildPlatformProvider()).await()
        return AuthDataResult(result)
    }

    /// Interactive reauthenticate with provider using current Activity
    /// https://firebase.google.com/docs/reference/android/com/google/firebase/auth/FirebaseUser#startactivityforreauthenticatewithprovider(android.app.Activity,com.google.firebase.auth.OAuthProvider)
    public func reauthenticate(with provider: OAuthProvider) async throws -> AuthDataResult {
        guard let activity: Activity = UIApplication.shared.androidActivity else {
            throw NSError(domain: "SkipFirebaseAuth", code: -12, userInfo: [NSLocalizedDescriptionKey: "No current Android activity available for OAuth reauthenticate"])
        }
        let result = try platformValue.startActivityForReauthenticateWithProvider(activity, provider.buildPlatformProvider()).await()
        return AuthDataResult(result)
    }

    /// Throws `FirebaseAuthInvalidUserException`/`FirebaseAuthRecentLoginRequiredException`
    /// https://firebase.google.com/docs/reference/android/com/google/firebase/auth/FirebaseUser#delete()
    public func delete() async throws {
        platformValue.delete().await()
    }

    public func getIDToken(forcingRefresh: Bool = false) async throws -> String {
        let result = try platformValue.getIdToken(forcingRefresh).await()
        guard let token = result.token else {
            throw NSError(domain: "FirebaseAuthError", code: -1, userInfo: [
                NSLocalizedDescriptionKey: "Failed to get ID token"
            ])
        }
        return token
    }
}

public let PhoneMultiFactorID = "phone"
public let TotpMultiFactorID = "totp"

public class MultiFactorSession {
    fileprivate let platformValue: com.google.firebase.auth.MultiFactorSession

    fileprivate init(_ platformValue: com.google.firebase.auth.MultiFactorSession) {
        self.platformValue = platformValue
    }
}

open class MultiFactorInfo {
    fileprivate let platformValue: com.google.firebase.auth.MultiFactorInfo

    fileprivate init(_ platformValue: com.google.firebase.auth.MultiFactorInfo) {
        self.platformValue = platformValue
    }

    public var uid: String {
        platformValue.getUid()
    }

    public var displayName: String? {
        platformValue.getDisplayName()
    }

    public var enrollmentDate: Date {
        Date(timeIntervalSince1970: Double(platformValue.getEnrollmentTimestamp()))
    }

    public var factorID: String {
        platformValue.getFactorId()
    }
}

public final class PhoneMultiFactorInfo : MultiFactorInfo {
    public static let PhoneMultiFactorID = "phone"
    public static let TOTPMultiFactorID = "totp"

    fileprivate var phonePlatformValue: com.google.firebase.auth.PhoneMultiFactorInfo {
        platformValue as! com.google.firebase.auth.PhoneMultiFactorInfo
    }

    fileprivate init(_ platformValue: com.google.firebase.auth.PhoneMultiFactorInfo) {
        super.init(platformValue)
    }

    public var phoneNumber: String {
        phonePlatformValue.getPhoneNumber()
    }
}

open class MultiFactorAssertion {
    fileprivate let platformValue: com.google.firebase.auth.MultiFactorAssertion

    fileprivate init(_ platformValue: com.google.firebase.auth.MultiFactorAssertion) {
        self.platformValue = platformValue
    }

    public var factorID: String {
        platformValue.getFactorId()
    }
}

public final class PhoneMultiFactorAssertion : MultiFactorAssertion {
    fileprivate init(_ platformValue: com.google.firebase.auth.PhoneMultiFactorAssertion) {
        super.init(platformValue)
    }
}

public final class PhoneMultiFactorGenerator {
    public static let factorID: String = com.google.firebase.auth.PhoneMultiFactorGenerator.FACTOR_ID

    public static func assertion(with credential: AuthCredential) -> PhoneMultiFactorAssertion {
        let phoneCredential = credential.platformValue as! com.google.firebase.auth.PhoneAuthCredential
        return PhoneMultiFactorAssertion(com.google.firebase.auth.PhoneMultiFactorGenerator.getAssertion(phoneCredential))
    }
}

public final class MultiFactorResolver {
    fileprivate let platformValue: com.google.firebase.auth.MultiFactorResolver

    fileprivate init(_ platformValue: com.google.firebase.auth.MultiFactorResolver) {
        self.platformValue = platformValue
    }

    public var session: MultiFactorSession {
        MultiFactorSession(platformValue.getSession())
    }

    public var hints: [MultiFactorInfo] {
        var swift: [MultiFactorInfo] = []
        let iterator = platformValue.getHints().iterator()
        while iterator.hasNext() {
            if let hint = iterator.next() {
                swift.append(wrapMultiFactorInfo(hint))
            }
        }
        return swift
    }

    public var auth: Auth {
        Auth(platformValue: platformValue.getFirebaseAuth())
    }

    public func resolveSignIn(with assertion: MultiFactorAssertion) async throws -> AuthDataResult {
		let result = try await platformValue.resolveSignIn(assertion.platformValue).await()
        return AuthDataResult(result)
    }

    public func resolveSignIn(with assertion: MultiFactorAssertion, completion: @escaping (AuthDataResult?, Error?) -> Void) {
        platformValue
            .resolveSignIn(assertion.platformValue)
            .addOnSuccessListener { result in
                completion(AuthDataResult(result), nil)
            }
            .addOnFailureListener { exception in
                completion(nil, mapAuthNSError(exception))
            }
    }
}

fileprivate func wrapMultiFactorInfo(_ platformValue: com.google.firebase.auth.MultiFactorInfo) -> MultiFactorInfo {
    if let phoneInfo = platformValue as? com.google.firebase.auth.PhoneMultiFactorInfo {
        return PhoneMultiFactorInfo(phoneInfo)
    } else {
        return MultiFactorInfo(platformValue)
    }
}

/// Additional user information associated with an auth result
public final class AdditionalUserInfo: KotlinConverting<com.google.firebase.auth.AdditionalUserInfo> {
    public let platformValue: com.google.firebase.auth.AdditionalUserInfo

    public init(_ platformValue: com.google.firebase.auth.AdditionalUserInfo) {
        self.platformValue = platformValue
    }

    // SKIP @nooverride
    public override func kotlin(nocopy: Bool = false) -> com.google.firebase.auth.AdditionalUserInfo {
        platformValue
    }

    public var isNewUser: Bool { platformValue.isNewUser }
    public var providerID: String? { platformValue.getProviderId() }
    public var username: String? { platformValue.getUsername() }

    /// Minimal compatibility: profile not bridged on Android
    public var profile: [AnyHashable: Any]? { nil }
}

// MARK: - iOS-compatible Auth error surface

public let AuthErrorDomain = "FIRAuthErrorDomain"
public let AuthErrorUserInfoEmailKey = "FIRAuthErrorUserInfoEmailKey"
public let AuthErrorUserInfoMultiFactorResolverKey = "FIRAuthErrorUserInfoMultiFactorResolverKey"

public enum AuthErrorCode: Int {
    case accountExistsWithDifferentCredential = 17012
    case secondFactorRequired = 17078
    case missingMultiFactorSession = 17081
    case missingMultiFactorInfo = 17082
    case invalidMultiFactorSession = 17083
    case multiFactorInfoNotFound = 17084
    case secondFactorAlreadyEnrolled = 17087
    case maximumSecondFactorCountExceeded = 17088
    case unsupportedFirstFactor = 17089
}

fileprivate final class AuthNSError : NSError {
    private var additionalUserInfo: [String: Any] = [:]
    private var multiFactorResolverValue: MultiFactorResolver?

    init(
        code: Int,
        userInfo: [String: Any] = [:],
        multiFactorResolver: MultiFactorResolver? = nil
    ) {
        super.init(domain: "FIRAuthErrorDomain", code: code, userInfo: userInfo)
        self.additionalUserInfo = userInfo
        self.multiFactorResolverValue = multiFactorResolver
    }

    override var userInfo: [String : Any] {
        var info = additionalUserInfo
        if let multiFactorResolverValue {
            info[AuthErrorUserInfoMultiFactorResolverKey] = multiFactorResolverValue
        }
        return info
    }
}

fileprivate func firebaseAuthException(for error: Error) -> com.google.firebase.auth.FirebaseAuthException? {
    if let authException = error as? com.google.firebase.auth.FirebaseAuthException {
        return authException
    }

    var throwable: Throwable?
    if let exception = error as? Exception {
        throwable = exception
    } else if let nsError = error as? NSError, let exception = nsError as? Exception {
        throwable = exception
    }

    while let currentThrowable = throwable {
        if let authException = currentThrowable as? com.google.firebase.auth.FirebaseAuthException {
            return authException
        }
        throwable = currentThrowable.cause
    }

    return nil
}

fileprivate func firebaseAuthMultiFactorException(for error: Error) -> com.google.firebase.auth.FirebaseAuthMultiFactorException? {
    firebaseAuthException(for: error) as? com.google.firebase.auth.FirebaseAuthMultiFactorException
}

fileprivate func mappedAuthErrorCode(for exception: com.google.firebase.auth.FirebaseAuthException) -> AuthErrorCode? {
    if exception is com.google.firebase.auth.FirebaseAuthMultiFactorException {
        return .secondFactorRequired
    }
    if exception is com.google.firebase.auth.FirebaseAuthUserCollisionException {
        return .accountExistsWithDifferentCredential
    }

    switch exception.getErrorCode() {
    case "ERROR_MISSING_MULTI_FACTOR_SESSION":
        return .missingMultiFactorSession
    case "ERROR_MISSING_MULTI_FACTOR_INFO":
        return .missingMultiFactorInfo
    case "ERROR_INVALID_MULTI_FACTOR_SESSION":
        return .invalidMultiFactorSession
    case "ERROR_MULTI_FACTOR_INFO_NOT_FOUND":
        return .multiFactorInfoNotFound
    case "ERROR_SECOND_FACTOR_ALREADY_ENROLLED":
        return .secondFactorAlreadyEnrolled
    case "ERROR_MAXIMUM_SECOND_FACTOR_COUNT_EXCEEDED":
        return .maximumSecondFactorCountExceeded
    case "ERROR_UNSUPPORTED_FIRST_FACTOR":
        return .unsupportedFirstFactor
    default:
        return nil
    }
}

/// Best-effort extraction of a Firebase auth error code from a platform error.
///
/// On Android, this first inspects the underlying `FirebaseAuthException` chain before attempting
/// any `NSError` compatibility mapping.
public func authErrorCode(for error: Error) -> AuthErrorCode? {
    // On Android, Firebase exposes MFA through FirebaseAuthMultiFactorException.
    // Prefer the underlying exception chain over NSError projection.
    if let authException = firebaseAuthException(for: error) {
        return mappedAuthErrorCode(for: authException)
    }
    if let authError = error as? AuthNSError, let code = AuthErrorCode(rawValue: authError.code) {
        return code
    }
    if let nsError = error as? NSError,
       nsError.domain == AuthErrorDomain,
       let code = AuthErrorCode(rawValue: nsError.code) {
        return code
    }
    return nil
}

/// Best-effort extraction of a `MultiFactorResolver` from a platform error.
///
/// On Android, this follows Firebase's native contract and prefers
/// `FirebaseAuthMultiFactorException.getResolver()`.
public func multiFactorResolver(for error: Error) -> MultiFactorResolver? {
    // On Android, this is the canonical MFA path:
    // (task.exception as FirebaseAuthMultiFactorException).resolver
    if let multiFactorException = firebaseAuthMultiFactorException(for: error) {
        return MultiFactorResolver(multiFactorException.getResolver())
    }
    if let authError = error as? AuthNSError, let resolver = authError.userInfo[AuthErrorUserInfoMultiFactorResolverKey] as? MultiFactorResolver {
        return resolver
    }
    if let nsError = error as? NSError {
        if let resolver = nsError.userInfo[AuthErrorUserInfoMultiFactorResolverKey] as? MultiFactorResolver {
            return resolver
        }
    }
    return nil
}

/// Map Android auth exceptions to iOS-style NSError when feasible
fileprivate func mapAuthNSError(_ exception: Exception) -> Error {
    if let multiFactor = exception as? com.google.firebase.auth.FirebaseAuthMultiFactorException {
        return AuthNSError(
            code: AuthErrorCode.secondFactorRequired.rawValue,
            multiFactorResolver: MultiFactorResolver(multiFactor.getResolver())
        )
    }
    if let collision = exception as? com.google.firebase.auth.FirebaseAuthUserCollisionException {
        var userInfo: [String: Any] = [:]
        // Try to extract email if available
        if let emailProvider = (collision as? com.google.firebase.auth.FirebaseAuthException) {
            // Some exceptions expose the email via getMessage or provider data; best effort only
            let message = String(describing: emailProvider.message ?? "")
            if message.contains("@") { // naive check for email-like token
                userInfo[AuthErrorUserInfoEmailKey] = message
            }
        }
        return AuthNSError(code: AuthErrorCode.accountExistsWithDifferentCredential.rawValue, userInfo: userInfo)
    }
    if let authException = exception as? com.google.firebase.auth.FirebaseAuthException,
       let mappedCode = mappedAuthErrorCode(for: authException) {
        return AuthNSError(code: mappedCode.rawValue)
    }
    return ErrorException(exception)
}

// Provide a FirebaseAuth namespace so app code can reference `FirebaseAuth.User` on Android
public enum FirebaseAuth {
    public typealias User = SkipFirebaseAuth.User
}

public class UserMetadata {
    // On iOS, UserMetadata is never nil but its properties can be. On Android, it's the opposite.
    public let userMetadata: com.google.firebase.auth.FirebaseUserMetadata?

    public init(_ userMetadata: com.google.firebase.auth.FirebaseUserMetadata?) {
        self.userMetadata = userMetadata
    }

    public var creationDate: Date? {
        guard let milliseconds = userMetadata?.getCreationTimestamp() else { return nil }
        return Date(timeIntervalSince1970: Double(milliseconds) / 1000)
    }

    public var lastSignInDate: Date? {
        guard let milliseconds = userMetadata?.getLastSignInTimestamp() else { return nil }
        return Date(timeIntervalSince1970: Double(milliseconds) / 1000)
    }
}

public class UserProfileChangeRequest/*: KotlinConverting<com.google.firebase.auth.UserProfileChangeRequest>*/ {
    var user: User

    fileprivate init(user: User) {
        self.user = user
    }

    public var displayName: String?

    /// Throws `FirebaseAuthInvalidUserException`
    /// https://firebase.google.com/docs/reference/android/com/google/firebase/auth/FirebaseUser#updateProfile(com.google.firebase.auth.UserProfileChangeRequest)
    public func commitChanges() async throws {
        let builder = com.google.firebase.auth.UserProfileChangeRequest.Builder()

        if let displayName {
            builder.setDisplayName(displayName)
        }

        let platformChangeRequest: com.google.firebase.auth.UserProfileChangeRequest = builder.build()

        user.platformValue.updateProfile(platformChangeRequest).await()
    }
}

public class AuthCredential: KotlinConverting<com.google.firebase.auth.AuthCredential> {
    public let platformValue: com.google.firebase.auth.AuthCredential
    
    public init(_ platformValue: com.google.firebase.auth.AuthCredential) {
        self.platformValue = platformValue
    }

    // Bridging this function creates a Swift function that "overrides" nothing
    // SKIP @nobridge
    public override func kotlin(nocopy: Bool = false) -> com.google.firebase.auth.AuthCredential {
        platformValue
    }
}

public class EmailAuthProvider {
    public static func credential(withEmail email: String, password: String) -> AuthCredential {
        let credential = com.google.firebase.auth.EmailAuthProvider.getCredential(email, password)
        return AuthCredential(credential)
    }
}

public final class PhoneAuthResendingToken {
    fileprivate let platformValue: com.google.firebase.auth.PhoneAuthProvider.ForceResendingToken

    fileprivate init(_ platformValue: com.google.firebase.auth.PhoneAuthProvider.ForceResendingToken) {
        self.platformValue = platformValue
    }
}

public enum PhoneAuthVerificationResult {
    case codeSent(verificationID: String, resendingToken: PhoneAuthResendingToken?)
    case verificationCompleted(AuthCredential)
}

fileprivate final class PhoneAuthVerificationState {
    private let lock = NSLock()
    private var didResume = false
    private let onResult: (PhoneAuthVerificationResult) -> Void
    private let onFailure: (Error) -> Void
    private let onCompletion: () -> Void

    init(
        onResult: @escaping (PhoneAuthVerificationResult) -> Void,
        onFailure: @escaping (Error) -> Void,
        onCompletion: @escaping () -> Void
    ) {
        self.onResult = onResult
        self.onFailure = onFailure
        self.onCompletion = onCompletion
    }

    func succeed(with result: PhoneAuthVerificationResult) {
        lock.lock()
        guard !didResume else {
            lock.unlock()
            return
        }
        didResume = true
        lock.unlock()
        android.util.Log.d("SkipFirebaseAuth", "Phone auth bridge resuming success")
        onCompletion()
        onResult(result)
    }

    func fail(with error: Error) {
        lock.lock()
        guard !didResume else {
            lock.unlock()
            return
        }
        didResume = true
        lock.unlock()
        android.util.Log.d("SkipFirebaseAuth", "Phone auth bridge resuming failure")
        onCompletion()
        onFailure(error)
    }
}

fileprivate final class PhoneAuthStateDidChangeCallbacks : com.google.firebase.auth.PhoneAuthProvider.OnVerificationStateChangedCallbacks {
    private let state: PhoneAuthVerificationState

    init(state: PhoneAuthVerificationState) {
        self.state = state
        super.init()
    }

    public override func onVerificationCompleted(credential: com.google.firebase.auth.PhoneAuthCredential) {
        android.util.Log.d("SkipFirebaseAuth", "Phone auth verification completed with credential")
        state.succeed(with: .verificationCompleted(AuthCredential(credential)))
    }

    public override func onVerificationFailed(exception: com.google.firebase.FirebaseException) {
        android.util.Log.e("SkipFirebaseAuth", "Phone auth verification failed", exception)
        state.fail(with: mapAuthNSError(exception))
    }

    public override func onCodeSent(verificationId: String, forceResendingToken: com.google.firebase.auth.PhoneAuthProvider.ForceResendingToken) {
        android.util.Log.d("SkipFirebaseAuth", "Phone auth code sent for verification ID: \(verificationId)")
        state.succeed(with: .codeSent(verificationID: verificationId, resendingToken: PhoneAuthResendingToken(forceResendingToken)))
    }

    public override func onCodeAutoRetrievalTimeOut(verificationId: String) {
        android.util.Log.d("SkipFirebaseAuth", "Phone auth auto retrieval timed out for verification ID: \(verificationId)")
        // We resolve the async result on the first actionable outcome:
        // either a verification ID is issued or a credential is returned directly.
    }
}

fileprivate func unsupportedPhoneAuthCompletionError() -> Error {
    NSError(
        domain: "SkipFirebaseAuth",
        code: -13,
        userInfo: [
            NSLocalizedDescriptionKey: "Phone auth completed without a verification ID. Use verifyPhoneNumberResult to handle instant verification on Android."
        ]
    )
}

// https://firebase.google.com/docs/reference/swift/firebaseauth/api/reference/Classes/PhoneAuthProvider
// https://firebase.google.com/docs/reference/android/com/google/firebase/auth/PhoneAuthProvider
public final class PhoneAuthProvider {
    private static let activeVerificationCallbacksLock = NSLock()
    private static var activeVerificationCallbacks: [String: PhoneAuthStateDidChangeCallbacks] = [:]

    private let auth: com.google.firebase.auth.FirebaseAuth

    private init(auth: com.google.firebase.auth.FirebaseAuth) {
        self.auth = auth
    }

    public static let id: String = com.google.firebase.auth.PhoneAuthProvider.PROVIDER_ID

    public static func provider() -> PhoneAuthProvider {
        PhoneAuthProvider(auth: com.google.firebase.auth.FirebaseAuth.getInstance())
    }

    public static func provider(auth: Auth) -> PhoneAuthProvider {
        PhoneAuthProvider(auth: auth.platformValue)
    }

    public func credential(withVerificationID verificationID: String, verificationCode: String) -> AuthCredential {
        AuthCredential(com.google.firebase.auth.PhoneAuthProvider.getCredential(verificationID, verificationCode))
    }

    @MainActor
    private func makeVerificationCallbacks(
        onResult: @escaping (PhoneAuthVerificationResult) -> Void,
        onFailure: @escaping (Error) -> Void
    ) -> PhoneAuthStateDidChangeCallbacks {
        let callbackID = UUID().uuidString

        let state = PhoneAuthVerificationState(
            onResult: onResult,
            onFailure: onFailure,
            onCompletion: {
                PhoneAuthProvider.unregisterVerificationCallbacks(callbackID)
            }
        )
        let callbacks = PhoneAuthStateDidChangeCallbacks(state: state)
        PhoneAuthProvider.registerVerificationCallbacks(callbacks, callbackID: callbackID)
        return callbacks
    }

    @MainActor
    private func makeVerificationBuilder(
        timeout: TimeInterval = 60.0,
        forceResendingToken: PhoneAuthResendingToken? = nil,
        callbacks: PhoneAuthStateDidChangeCallbacks
    ) -> com.google.firebase.auth.PhoneAuthOptions.Builder {
        let builder = com.google.firebase.auth.PhoneAuthOptions.newBuilder(auth)
            .setTimeout(Int64(max(timeout, 0.0).rounded()), TimeUnit.SECONDS)
            .setCallbacks(callbacks)

        if let activity: Activity = UIApplication.shared.androidActivity {
            builder.setActivity(activity)
        }
        if let forceResendingToken {
            builder.setForceResendingToken(forceResendingToken.platformValue)
        }
        return builder
    }

    @MainActor
    private func startVerification(
        _ phoneNumber: String,
        uiDelegate: Any? = nil,
        timeout: TimeInterval = 60.0,
        forceResendingToken: PhoneAuthResendingToken? = nil,
        onResult: @escaping (PhoneAuthVerificationResult) -> Void,
        onFailure: @escaping (Error) -> Void
    ) {
        _ = uiDelegate
        let callbacks = makeVerificationCallbacks(onResult: onResult, onFailure: onFailure)
        let builder = makeVerificationBuilder(timeout: timeout, forceResendingToken: forceResendingToken, callbacks: callbacks)
            .setPhoneNumber(phoneNumber)

        com.google.firebase.auth.PhoneAuthProvider.verifyPhoneNumber(builder.build())
    }

    @MainActor
    private func startVerification(
        with multiFactorInfo: PhoneMultiFactorInfo,
        uiDelegate: Any? = nil,
        multiFactorSession: MultiFactorSession,
        timeout: TimeInterval = 60.0,
        forceResendingToken: PhoneAuthResendingToken? = nil,
        onResult: @escaping (PhoneAuthVerificationResult) -> Void,
        onFailure: @escaping (Error) -> Void
    ) {
        _ = uiDelegate
        let callbacks = makeVerificationCallbacks(onResult: onResult, onFailure: onFailure)
        let builder = makeVerificationBuilder(timeout: timeout, forceResendingToken: forceResendingToken, callbacks: callbacks)
            .setMultiFactorSession(multiFactorSession.platformValue)
            .setMultiFactorHint(multiFactorInfo.phonePlatformValue)

        com.google.firebase.auth.PhoneAuthProvider.verifyPhoneNumber(builder.build())
    }

    /// iOS-compatible completion API. If Android completes verification without issuing a verification ID,
    /// the completion receives an error and callers should switch to `verifyPhoneNumberResult`.
    @MainActor
    public func verifyPhoneNumber(
        _ phoneNumber: String,
        uiDelegate: Any? = nil,
        completion: @escaping (String?, Error?) -> Void
    ) {
        startVerification(
            phoneNumber,
            uiDelegate: uiDelegate,
            onResult: { result in
                switch result {
                case .codeSent(let verificationID, _):
                    completion(verificationID, nil)
                case .verificationCompleted:
                    completion(nil, unsupportedPhoneAuthCompletionError())
                }
            },
            onFailure: { error in
                completion(nil, error)
            }
        )
    }

    /// iOS-compatible completion API for second-factor sign-in. If Android completes verification
    /// without issuing a verification ID, the completion receives an error and callers should switch
    /// to `verifyPhoneNumberResult(with:uiDelegate:multiFactorSession:timeout:forceResendingToken:)`.
    @MainActor
    public func verifyPhoneNumber(
        with multiFactorInfo: PhoneMultiFactorInfo,
        uiDelegate: Any? = nil,
        multiFactorSession: MultiFactorSession,
        completion: @escaping (String?, Error?) -> Void
    ) {
        startVerification(
            with: multiFactorInfo,
            uiDelegate: uiDelegate,
            multiFactorSession: multiFactorSession,
            onResult: { result in
                switch result {
                case .codeSent(let verificationID, _):
                    completion(verificationID, nil)
                case .verificationCompleted:
                    completion(nil, unsupportedPhoneAuthCompletionError())
                }
            },
            onFailure: { error in
                completion(nil, error)
            }
        )
    }

    /// iOS-compatible async API. If Android completes verification without issuing a verification ID,
    /// this throws and callers should switch to `verifyPhoneNumberResult`.
    @MainActor
    public func verifyPhoneNumber(_ phoneNumber: String, uiDelegate: Any? = nil) async throws -> String {
        let verificationID = try await withCheckedThrowingContinuation { continuation in
            startVerification(
                phoneNumber,
                uiDelegate: uiDelegate,
                onResult: { result in
                    android.util.Log.d("SkipFirebaseAuth", "Phone auth string continuation resume(returning/throwing:)")
                    switch result {
                    case .codeSent(let verificationID, _):
                        continuation.resume(returning: verificationID)
                    case .verificationCompleted:
                        continuation.resume(throwing: unsupportedPhoneAuthCompletionError())
                    }
                },
                onFailure: { error in
                    android.util.Log.d("SkipFirebaseAuth", "Phone auth string continuation resume(throwing:)")
                    continuation.resume(throwing: error)
                }
            )
        }
        android.util.Log.d("SkipFirebaseAuth", "Phone auth async string returned to caller")
        return verificationID
    }

    /// iOS-compatible async API for second-factor sign-in. If Android completes verification without
    /// issuing a verification ID, this throws and callers should switch to
    /// `verifyPhoneNumberResult(with:uiDelegate:multiFactorSession:timeout:forceResendingToken:)`.
    @MainActor
    public func verifyPhoneNumber(
        with multiFactorInfo: PhoneMultiFactorInfo,
        uiDelegate: Any? = nil,
        multiFactorSession: MultiFactorSession
    ) async throws -> String {
        let verificationID = try await withCheckedThrowingContinuation { continuation in
            startVerification(
                with: multiFactorInfo,
                uiDelegate: uiDelegate,
                multiFactorSession: multiFactorSession,
                onResult: { result in
                    android.util.Log.d("SkipFirebaseAuth", "Phone MFA string continuation resume(returning/throwing:)")
                    switch result {
                    case .codeSent(let verificationID, _):
                        continuation.resume(returning: verificationID)
                    case .verificationCompleted:
                        continuation.resume(throwing: unsupportedPhoneAuthCompletionError())
                    }
                },
                onFailure: { error in
                    android.util.Log.d("SkipFirebaseAuth", "Phone MFA string continuation resume(throwing:)")
                    continuation.resume(throwing: error)
                }
            )
        }
        android.util.Log.d("SkipFirebaseAuth", "Phone MFA async string returned to caller")
        return verificationID
    }

    /// Async phone verification API that returns the first actionable Firebase result:
    /// either a verification ID was sent or Android completed instant verification with a credential.
    /// The `uiDelegate` parameter is ignored on Android and exists for source compatibility with Apple platforms.
    @MainActor
    public func verifyPhoneNumberResult(
        _ phoneNumber: String,
        uiDelegate: Any? = nil,
        timeout: TimeInterval = 60.0,
        forceResendingToken: PhoneAuthResendingToken? = nil
    ) async throws -> PhoneAuthVerificationResult {
        let result = try await withCheckedThrowingContinuation { continuation in
            startVerification(
                phoneNumber,
                uiDelegate: uiDelegate,
                timeout: timeout,
                forceResendingToken: forceResendingToken,
                onResult: { result in
                    android.util.Log.d("SkipFirebaseAuth", "Phone auth result continuation resume(returning:)")
                    continuation.resume(returning: result)
                },
                onFailure: { error in
                    android.util.Log.d("SkipFirebaseAuth", "Phone auth result continuation resume(throwing:)")
                    continuation.resume(throwing: error)
                }
            )
        }
        android.util.Log.d("SkipFirebaseAuth", "Phone auth async result returned to caller")
        return result
    }

    /// Async second-factor phone verification API that returns the first actionable Firebase result:
    /// either a verification ID was sent or Android completed instant verification with a credential.
    /// The `uiDelegate` parameter is ignored on Android and exists for source compatibility with Apple platforms.
    @MainActor
    public func verifyPhoneNumberResult(
        with multiFactorInfo: PhoneMultiFactorInfo,
        uiDelegate: Any? = nil,
        multiFactorSession: MultiFactorSession,
        timeout: TimeInterval = 60.0,
        forceResendingToken: PhoneAuthResendingToken? = nil
    ) async throws -> PhoneAuthVerificationResult {
        let result = try await withCheckedThrowingContinuation { continuation in
            startVerification(
                with: multiFactorInfo,
                uiDelegate: uiDelegate,
                multiFactorSession: multiFactorSession,
                timeout: timeout,
                forceResendingToken: forceResendingToken,
                onResult: { result in
                    android.util.Log.d("SkipFirebaseAuth", "Phone MFA result continuation resume(returning:)")
                    continuation.resume(returning: result)
                },
                onFailure: { error in
                    android.util.Log.d("SkipFirebaseAuth", "Phone MFA result continuation resume(throwing:)")
                    continuation.resume(throwing: error)
                }
            )
        }
        android.util.Log.d("SkipFirebaseAuth", "Phone MFA async result returned to caller")
        return result
    }

    private static func registerVerificationCallbacks(_ callbacks: PhoneAuthStateDidChangeCallbacks, callbackID: String) {
        activeVerificationCallbacksLock.lock()
        defer { activeVerificationCallbacksLock.unlock() }
        activeVerificationCallbacks[callbackID] = callbacks
    }

    private static func unregisterVerificationCallbacks(_ callbackID: String) {
        activeVerificationCallbacksLock.lock()
        defer { activeVerificationCallbacksLock.unlock() }
        activeVerificationCallbacks.removeValue(forKey: callbackID)
    }
}

// https://firebase.google.com/docs/reference/swift/firebaseauth/api/reference/Classes/OAuthProvider
// https://firebase.google.com/docs/reference/android/com/google/firebase/auth/OAuthProvider
public final class OAuthProvider {
    public let providerID: String
    public var customParameters: [String : String] = [:]
    public var scopes: [String] = []

    public init(providerID: String) {
        self.providerID = providerID
    }

    /// Build Android OAuthProvider from current configuration
    internal func buildPlatformProvider() -> com.google.firebase.auth.OAuthProvider {
        let builder = com.google.firebase.auth.OAuthProvider.newBuilder(providerID)
        for (key, value) in customParameters {
            builder.addCustomParameter(key, value)
        }
        if !scopes.isEmpty {
            builder.setScopes(scopes.toList())
        }
        return builder.build()
    }

    /// iOS-compatible API. Starts interactive OAuth flow and returns a credential in the completion.
    public func getCredentialWith(_ presentingAnchor: Any?, completion: @escaping (AuthCredential?, Error?) -> Void) {
        guard let activity: Activity = UIApplication.shared.androidActivity else {
            completion(nil, NSError(domain: "SkipFirebaseAuth", code: -10, userInfo: [NSLocalizedDescriptionKey: "No current Android activity available for OAuth sign-in"]))
            return
        }
        let auth = com.google.firebase.auth.FirebaseAuth.getInstance()
        auth.startActivityForSignInWithProvider(activity, buildPlatformProvider())
            .addOnSuccessListener { result in
                if let cred = result.credential {
                    completion(AuthCredential(cred), nil)
                } else {
                    completion(nil, nil)
                }
            }
            .addOnFailureListener { exception in
                completion(nil, ErrorException(exception))
            }
    }

    /// Build an OAuth credential from tokens
    public static func credential(providerID: String, idToken: String? = nil, rawNonce: String? = nil, accessToken: String? = nil) -> AuthCredential {
        let builder = com.google.firebase.auth.OAuthProvider.newCredentialBuilder(providerID)
        if let idToken, let rawNonce {
            builder.setIdTokenWithRawNonce(idToken, rawNonce)
        } else if let idToken {
            builder.setIdToken(idToken)
        }
        if let accessToken {
            builder.setAccessToken(accessToken)
        }
        return AuthCredential(builder.build())
    }
	
    /// Convenience instance API matching iOS style
    public func credential(withIDToken idToken: String? = nil, accessToken: String? = nil, rawNonce: String? = nil) -> AuthCredential {
        return OAuthProvider.credential(providerID: providerID, idToken: idToken, rawNonce: rawNonce, accessToken: accessToken)
    }
}

#else
import Foundation
import FirebaseAuth

/// Shared first-factor email/password sign-in outcome.
///
/// This mirrors the Android helper API so shared app code can opt into a typed MFA-aware sign-in
/// path on both platforms.
public enum EmailSignInResult {
    case signedIn(AuthDataResult)
    case secondFactorRequired(MultiFactorResolver)
}

public final class PhoneAuthResendingToken {
    fileprivate init() {
    }
}

public enum PhoneAuthVerificationResult {
    case codeSent(verificationID: String, resendingToken: PhoneAuthResendingToken?)
    case verificationCompleted(AuthCredential)
}

/// Best-effort extraction of a Firebase auth error code from a platform error.
public func authErrorCode(for error: Error) -> AuthErrorCode? {
    let nsError = error as NSError
    guard nsError.domain == AuthErrorDomain else {
        return nil
    }
    return AuthErrorCode(rawValue: nsError.code)
}

/// Best-effort extraction of a `MultiFactorResolver` from a platform error.
public func multiFactorResolver(for error: Error) -> MultiFactorResolver? {
    let nsError = error as NSError
    return nsError.userInfo[AuthErrorUserInfoMultiFactorResolverKey] as? MultiFactorResolver
}

@available(iOS 13, tvOS 13, macCatalyst 13, *)
public extension Auth {
    /// Shared async sign-in API for MFA-aware email/password sign-in.
    ///
    /// This mirrors the Android helper API. Native iOS callers may still use FirebaseAuth's
    /// `signIn(withEmail:password:)` directly and inspect the thrown `NSError`, but this method
    /// provides the same typed result shape as Android for shared code that imports `SkipFirebaseAuth`.
    func signInResult(withEmail email: String, password: String) async throws -> EmailSignInResult {
        do {
            let result = try await signIn(withEmail: email, password: password)
            return .signedIn(result)
        } catch {
            if let resolver = multiFactorResolver(for: error) {
                return .secondFactorRequired(resolver)
            }
            throw error
        }
    }
}

#if os(iOS)
@available(iOS 13, tvOS 13, macCatalyst 13, *)
public extension PhoneAuthProvider {
    /// Async phone verification API that mirrors the Android wrapper.
    /// On Apple platforms, `timeout` and `forceResendingToken` are ignored because the native API
    /// only yields a verification ID or an error.
    @MainActor
    func verifyPhoneNumberResult(
        _ phoneNumber: String,
        uiDelegate: Any? = nil,
        timeout: TimeInterval = 60.0,
        forceResendingToken: PhoneAuthResendingToken? = nil
    ) async throws -> PhoneAuthVerificationResult {
        _ = timeout
        _ = forceResendingToken

        let verificationID = try await verifyPhoneNumber(phoneNumber, uiDelegate: uiDelegate as? FirebaseAuth.AuthUIDelegate)
        return .codeSent(verificationID: verificationID, resendingToken: nil)
    }

    /// Async second-factor phone verification API that mirrors the Android wrapper.
    /// On Apple platforms, `timeout` and `forceResendingToken` are ignored because the native API
    /// only yields a verification ID or an error.
    @MainActor
    func verifyPhoneNumberResult(
        with multiFactorInfo: PhoneMultiFactorInfo,
        uiDelegate: Any? = nil,
        multiFactorSession: MultiFactorSession,
        timeout: TimeInterval = 60.0,
        forceResendingToken: PhoneAuthResendingToken? = nil
    ) async throws -> PhoneAuthVerificationResult {
        _ = timeout
        _ = forceResendingToken

        let verificationID = try await verifyPhoneNumber(
            with: multiFactorInfo,
            uiDelegate: uiDelegate as? FirebaseAuth.AuthUIDelegate,
            multiFactorSession: multiFactorSession
        )
        return .codeSent(verificationID: verificationID, resendingToken: nil)
    }
}

@available(iOS 13, tvOS 13, macCatalyst 13, *)
public extension PhoneMultiFactorGenerator {
    /// Convenience overload so shared code can pass the generic auth credential wrapper type used on Android.
    static func assertion(with credential: AuthCredential) -> PhoneMultiFactorAssertion {
        guard let phoneCredential = credential as? PhoneAuthCredential else {
            fatalError("PhoneMultiFactorGenerator.assertion(with:) requires a PhoneAuthCredential.")
        }
        return Self.assertion(with: phoneCredential)
    }
}
#endif

#endif
#endif
