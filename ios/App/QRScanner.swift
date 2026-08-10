import SwiftUI
import AVFoundation
import AudioToolbox

/// JoinCode is the payload encoded in an admin panel's "join QR". Scanning it
/// fills in a full network configuration with no typing.
struct JoinCode: Decodable {
    var kind: String?
    var network_name: String
    var psk: String
    var overlay_cidr: String?
    var rendezvous_servers: [String]?
    var rendezvous_auth: String? // credential for servers that require one
    var trackers: [String]?      // this network's top trackers (incl. private ones)
    // Crypto profile — must match every node, so the QR carries it too.
    var cipher: String?          // "chacha" or "aesgcm"
    var post_quantum: Bool?      // absent = on (quantum-safe default)
    var pq_auth: Bool?           // absent = on (quantum-safe default)

    /// Parse a scanned string into a JoinCode (must look like an APGO join code).
    static func parse(_ s: String) -> JoinCode? {
        guard let data = s.data(using: .utf8),
              let jc = try? JSONDecoder().decode(JoinCode.self, from: data),
              !jc.network_name.isEmpty, !jc.psk.isEmpty else { return nil }
        if let k = jc.kind, k != "apgo-join" { return nil }
        return jc
    }
}

/// QRScannerView presents the camera and calls `onFound` with the first decoded
/// QR string, then dismisses itself.
struct QRScannerView: UIViewControllerRepresentable {
    var onFound: (String) -> Void
    @Environment(\.dismiss) private var dismiss

    func makeCoordinator() -> Coordinator { Coordinator(self) }

    func makeUIViewController(context: Context) -> ScannerVC {
        let vc = ScannerVC()
        vc.onFound = { code in
            context.coordinator.handle(code)
        }
        return vc
    }
    func updateUIViewController(_ vc: ScannerVC, context: Context) {}

    final class Coordinator {
        let parent: QRScannerView
        private var done = false
        init(_ parent: QRScannerView) { self.parent = parent }
        func handle(_ code: String) {
            guard !done else { return }
            done = true
            parent.onFound(code)
            parent.dismiss()
        }
    }
}

/// ScannerVC runs an AVCaptureSession that reports QR codes.
final class ScannerVC: UIViewController, AVCaptureMetadataOutputObjectsDelegate {
    var onFound: ((String) -> Void)?
    private let session = AVCaptureSession()
    private var preview: AVCaptureVideoPreviewLayer?

    override func viewDidLoad() {
        super.viewDidLoad()
        view.backgroundColor = .black
        guard let device = AVCaptureDevice.default(for: .video),
              let input = try? AVCaptureDeviceInput(device: device),
              session.canAddInput(input) else { showError(); return }
        session.addInput(input)

        let output = AVCaptureMetadataOutput()
        guard session.canAddOutput(output) else { showError(); return }
        session.addOutput(output)
        output.setMetadataObjectsDelegate(self, queue: .main)
        output.metadataObjectTypes = [.qr]

        let layer = AVCaptureVideoPreviewLayer(session: session)
        layer.videoGravity = .resizeAspectFill
        layer.frame = view.layer.bounds
        view.layer.addSublayer(layer)
        preview = layer

        addHint()
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            self?.session.startRunning()
        }
    }

    override func viewDidLayoutSubviews() {
        super.viewDidLayoutSubviews()
        preview?.frame = view.layer.bounds
    }

    override func viewWillDisappear(_ animated: Bool) {
        super.viewWillDisappear(animated)
        if session.isRunning { session.stopRunning() }
    }

    func metadataOutput(_ output: AVCaptureMetadataOutput,
                        didOutput objects: [AVMetadataObject],
                        from connection: AVCaptureConnection) {
        guard let obj = objects.first as? AVMetadataMachineReadableCodeObject,
              let str = obj.stringValue else { return }
        session.stopRunning()
        AudioServicesPlaySystemSound(kSystemSoundID_Vibrate)
        onFound?(str)
    }

    private func addHint() {
        let label = UILabel()
        label.text = "Point at the APGO “Join QR” on the admin panel"
        label.textColor = .white
        label.numberOfLines = 0
        label.textAlignment = .center
        label.font = .systemFont(ofSize: 15, weight: .medium)
        label.translatesAutoresizingMaskIntoConstraints = false
        let bg = UIView()
        bg.backgroundColor = UIColor.black.withAlphaComponent(0.5)
        bg.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(bg)
        bg.addSubview(label)
        NSLayoutConstraint.activate([
            bg.leadingAnchor.constraint(equalTo: view.leadingAnchor),
            bg.trailingAnchor.constraint(equalTo: view.trailingAnchor),
            bg.bottomAnchor.constraint(equalTo: view.bottomAnchor),
            bg.topAnchor.constraint(equalTo: view.safeAreaLayoutGuide.bottomAnchor, constant: -96),
            label.leadingAnchor.constraint(equalTo: bg.leadingAnchor, constant: 20),
            label.trailingAnchor.constraint(equalTo: bg.trailingAnchor, constant: -20),
            label.topAnchor.constraint(equalTo: bg.topAnchor, constant: 16),
        ])
    }

    private func showError() {
        let label = UILabel()
        label.text = "Camera unavailable"
        label.textColor = .white
        label.textAlignment = .center
        label.frame = view.bounds
        label.autoresizingMask = [.flexibleWidth, .flexibleHeight]
        view.addSubview(label)
    }
}
