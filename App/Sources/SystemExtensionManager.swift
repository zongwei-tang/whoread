// NOT YET COMPILED (see WhoReadApp.swift).
import Foundation
import SystemExtensions
import WhoReadUIModel

/// Activates the Endpoint Security system extension (OSSystemExtensionRequest). The app must
/// run from /Applications for activation to succeed.
@MainActor
final class SystemExtensionManager: NSObject, OSSystemExtensionRequestDelegate {
    static let shared = SystemExtensionManager()
    /// Called when a request finishes or fails (uninstall flow).
    /// Called with true when the request succeeded (`.willCompleteAfterReboot` counts as success).
    var onFinish: ((Bool) -> Void)?

    var extensionIdentifier: String {
        (Bundle.main.object(forInfoDictionaryKey: "WhoReadExtensionBundleID") as? String) ?? "com.example.whoread.extension"
    }

    func activate() {
        DaemonConnection.shared.onboarding.extensionState = .waiting
        let request = OSSystemExtensionRequest.activationRequest(forExtensionWithIdentifier: extensionIdentifier, queue: .main)
        request.delegate = self
        OSSystemExtensionManager.shared.submitRequest(request)
    }

    func deactivate() {
        let request = OSSystemExtensionRequest.deactivationRequest(forExtensionWithIdentifier: extensionIdentifier, queue: .main)
        request.delegate = self
        OSSystemExtensionManager.shared.submitRequest(request)
    }

    nonisolated func request(_ request: OSSystemExtensionRequest, actionForReplacingExtension existing: OSSystemExtensionProperties,
                             withExtension ext: OSSystemExtensionProperties) -> OSSystemExtensionRequest.ReplacementAction {
        .replace
    }

    nonisolated func requestNeedsUserApproval(_ request: OSSystemExtensionRequest) {
        Task { @MainActor in DaemonConnection.shared.onboarding.extensionState = .waiting }
    }

    nonisolated func request(_ request: OSSystemExtensionRequest, didFinishWithResult result: OSSystemExtensionRequest.Result) {
        Task { @MainActor in
            // .willCompleteAfterReboot: the extension is not active until the next restart.
            DaemonConnection.shared.onboarding.extensionState = result == .completed ? .done : .needsRestart
            self.onFinish?(true)
        }
    }

    nonisolated func request(_ request: OSSystemExtensionRequest, didFailWithError error: any Error) {
        Task { @MainActor in
            DaemonConnection.shared.onboarding.extensionState = .failed(error.localizedDescription)
            self.onFinish?(false)
        }
    }
}
