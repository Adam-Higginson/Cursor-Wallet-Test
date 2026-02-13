// QRScannerView.swift
// AVFoundation-based QR code scanner wrapped for SwiftUI.
//
// Uses UIViewControllerRepresentable to bridge AVCaptureSession into SwiftUI.
// On detection, calls the onScan closure with the scanned string.

import SwiftUI
import AVFoundation

// MARK: - QRScannerView

/// A SwiftUI view that presents a camera preview and scans QR codes.
/// Calls `onScan` with the decoded string when a QR code is detected.
public struct QRScannerView: UIViewControllerRepresentable {
    public let onScan: (String) -> Void
    public let onError: (String) -> Void

    public init(onScan: @escaping (String) -> Void, onError: @escaping (String) -> Void) {
        self.onScan = onScan
        self.onError = onError
    }

    public func makeUIViewController(context: Context) -> QRScannerViewController {
        let controller = QRScannerViewController()
        controller.onScan = onScan
        controller.onError = onError
        return controller
    }

    public func updateUIViewController(_ uiViewController: QRScannerViewController, context: Context) {
        // No updates needed — the capture session runs continuously
    }
}

// MARK: - QRScannerViewController

/// UIKit view controller that manages the AVCaptureSession for QR scanning.
public class QRScannerViewController: UIViewController, AVCaptureMetadataOutputObjectsDelegate {
    var onScan: ((String) -> Void)?
    var onError: ((String) -> Void)?

    private let captureSession = AVCaptureSession()
    private var previewLayer: AVCaptureVideoPreviewLayer?
    private var hasScanned = false

    public override func viewDidLoad() {
        super.viewDidLoad()
        view.backgroundColor = .black
        setupCamera()
    }

    public override func viewDidLayoutSubviews() {
        super.viewDidLayoutSubviews()
        previewLayer?.frame = view.bounds
    }

    public override func viewWillAppear(_ animated: Bool) {
        super.viewWillAppear(animated)
        if !captureSession.isRunning {
            DispatchQueue.global(qos: .userInitiated).async { [weak self] in
                self?.captureSession.startRunning()
            }
        }
    }

    public override func viewWillDisappear(_ animated: Bool) {
        super.viewWillDisappear(animated)
        if captureSession.isRunning {
            captureSession.stopRunning()
        }
    }

    // MARK: Camera Setup

    private func setupCamera() {
        guard let videoCaptureDevice = AVCaptureDevice.default(for: .video) else {
            onError?("No camera available on this device.")
            return
        }

        let videoInput: AVCaptureDeviceInput
        do {
            videoInput = try AVCaptureDeviceInput(device: videoCaptureDevice)
        } catch {
            onError?("Could not access camera: \(error.localizedDescription)")
            return
        }

        guard captureSession.canAddInput(videoInput) else {
            onError?("Could not add camera input to capture session.")
            return
        }
        captureSession.addInput(videoInput)

        let metadataOutput = AVCaptureMetadataOutput()
        guard captureSession.canAddOutput(metadataOutput) else {
            onError?("Could not add metadata output to capture session.")
            return
        }
        captureSession.addOutput(metadataOutput)

        metadataOutput.setMetadataObjectsDelegate(self, queue: DispatchQueue.main)
        metadataOutput.metadataObjectTypes = [.qr]

        let preview = AVCaptureVideoPreviewLayer(session: captureSession)
        preview.videoGravity = .resizeAspectFill
        preview.frame = view.bounds
        view.layer.addSublayer(preview)
        self.previewLayer = preview

        // Add a viewfinder overlay
        addViewfinderOverlay()

        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            self?.captureSession.startRunning()
        }
    }

    private func addViewfinderOverlay() {
        let overlayView = UIView(frame: view.bounds)
        overlayView.backgroundColor = .clear
        overlayView.isUserInteractionEnabled = false
        view.addSubview(overlayView)

        // Semi-transparent border around a clear center square
        let maskLayer = CAShapeLayer()
        let outerPath = UIBezierPath(rect: overlayView.bounds)
        let side = min(overlayView.bounds.width, overlayView.bounds.height) * 0.7
        let scanRect = CGRect(
            x: (overlayView.bounds.width - side) / 2,
            y: (overlayView.bounds.height - side) / 2,
            width: side,
            height: side
        )
        let innerPath = UIBezierPath(roundedRect: scanRect, cornerRadius: 12)
        outerPath.append(innerPath)
        outerPath.usesEvenOddFillRule = true
        maskLayer.path = outerPath.cgPath
        maskLayer.fillRule = .evenOdd
        maskLayer.fillColor = UIColor.black.withAlphaComponent(0.5).cgColor
        overlayView.layer.addSublayer(maskLayer)

        // White corner brackets
        let bracketLayer = CAShapeLayer()
        bracketLayer.strokeColor = UIColor.white.cgColor
        bracketLayer.fillColor = UIColor.clear.cgColor
        bracketLayer.lineWidth = 3
        let bracketPath = UIBezierPath()
        let corner: CGFloat = 30

        // Top-left
        bracketPath.move(to: CGPoint(x: scanRect.minX, y: scanRect.minY + corner))
        bracketPath.addLine(to: CGPoint(x: scanRect.minX, y: scanRect.minY))
        bracketPath.addLine(to: CGPoint(x: scanRect.minX + corner, y: scanRect.minY))
        // Top-right
        bracketPath.move(to: CGPoint(x: scanRect.maxX - corner, y: scanRect.minY))
        bracketPath.addLine(to: CGPoint(x: scanRect.maxX, y: scanRect.minY))
        bracketPath.addLine(to: CGPoint(x: scanRect.maxX, y: scanRect.minY + corner))
        // Bottom-right
        bracketPath.move(to: CGPoint(x: scanRect.maxX, y: scanRect.maxY - corner))
        bracketPath.addLine(to: CGPoint(x: scanRect.maxX, y: scanRect.maxY))
        bracketPath.addLine(to: CGPoint(x: scanRect.maxX - corner, y: scanRect.maxY))
        // Bottom-left
        bracketPath.move(to: CGPoint(x: scanRect.minX + corner, y: scanRect.maxY))
        bracketPath.addLine(to: CGPoint(x: scanRect.minX, y: scanRect.maxY))
        bracketPath.addLine(to: CGPoint(x: scanRect.minX, y: scanRect.maxY - corner))

        bracketLayer.path = bracketPath.cgPath
        overlayView.layer.addSublayer(bracketLayer)
    }

    // MARK: AVCaptureMetadataOutputObjectsDelegate

    public func metadataOutput(
        _ output: AVCaptureMetadataOutput,
        didOutput metadataObjects: [AVMetadataObject],
        from connection: AVCaptureConnection
    ) {
        // Only process the first QR code, and only once
        guard !hasScanned,
              let metadataObject = metadataObjects.first as? AVMetadataMachineReadableCodeObject,
              metadataObject.type == .qr,
              let scannedString = metadataObject.stringValue else {
            return
        }

        hasScanned = true
        captureSession.stopRunning()

        // Haptic feedback on successful scan
        let generator = UINotificationFeedbackGenerator()
        generator.notificationOccurred(.success)

        onScan?(scannedString)
    }
}
