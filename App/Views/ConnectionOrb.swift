import SwiftUI
import NetworkExtension
import FptnShared

struct ConnectionOrb: View {
    let status: NEVPNStatus
    let palette: ThemePalette
    let isBusy: Bool
    let localizer: Localizer
    let action: () -> Void

    @State private var pulse = false
    @State private var spin = false

    private var color: Color {
        switch status {
        case .connected: return palette.success
        case .connecting, .reasserting: return palette.warning
        case .disconnecting: return palette.accentSecondary
        case .disconnected, .invalid: return palette.textSecondary
        @unknown default: return palette.textSecondary
        }
    }

    private var icon: String {
        switch status {
        case .connected: return "lock.fill"
        case .connecting, .reasserting: return "arrow.triangle.2.circlepath"
        case .disconnecting: return "xmark"
        case .disconnected, .invalid: return "power"
        @unknown default: return "questionmark"
        }
    }

    var body: some View {
        Button(action: action) {
            ZStack {
                ForEach(0..<3) { ring in
                    Circle()
                        .stroke(color.opacity(0.14 - Double(ring) * 0.03), lineWidth: 1)
                        .frame(width: 208 + CGFloat(ring) * 30, height: 208 + CGFloat(ring) * 30)
                        .scaleEffect(pulse ? 1.02 : 0.98)
                        .animation(
                            .easeInOut(duration: 2.4 + Double(ring) * 0.4)
                                .repeatForever(autoreverses: true)
                                .delay(Double(ring) * 0.15),
                            value: pulse
                        )
                }

                Circle()
                    .stroke(palette.orb, style: StrokeStyle(lineWidth: 2, dash: [3, 9]))
                    .frame(width: 206, height: 206)
                    .rotationEffect(.degrees(spin ? 360 : 0))
                    .animation(.linear(duration: 18).repeatForever(autoreverses: false), value: spin)

                Circle()
                    .fill(
                        RadialGradient(
                            colors: [color.opacity(0.20), palette.backgroundBottom],
                            center: .center,
                            startRadius: 10,
                            endRadius: 105
                        )
                    )
                    .frame(width: 188, height: 188)
                    .overlay(
                        Circle()
                            .stroke(color.opacity(0.65), lineWidth: 1.4)
                    )
                    .shadow(color: color.opacity(0.35), radius: 28)

                VStack(spacing: 9) {
                    Image(systemName: icon)
                        .font(.system(size: 30, weight: .semibold))
                        .foregroundStyle(color)
                    Text(isBusy ? localizer.text(.orbWorking) : statusLabel)
                        .font(.system(size: 10, weight: .bold, design: .rounded))
                        .tracking(1.8)
                        .foregroundStyle(palette.textSecondary)
                }
            }
            .frame(width: 250, height: 250)
            .contentShape(Circle())
        }
        .buttonStyle(.plain)
        .accessibilityLabel(statusLabel)
        .onAppear {
            pulse = true
            spin = true
        }
    }

    private var statusLabel: String {
        switch status {
        case .connected: return localizer.text(.orbConnected)
        case .connecting, .reasserting: return localizer.text(.orbConnecting)
        case .disconnecting: return localizer.text(.orbClosing)
        case .disconnected, .invalid: return localizer.text(.orbTapToStart)
        @unknown default: return localizer.text(.orbUnknown)
        }
    }
}
