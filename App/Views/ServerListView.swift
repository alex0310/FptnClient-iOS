import SwiftUI
import FptnCore
import FptnShared

struct ServerListView: View {
    @EnvironmentObject private var model: AppModel

    private var palette: ThemePalette { model.palette }

    var body: some View {
        NavigationStack {
            ScrollView(showsIndicators: false) {
                VStack(alignment: .leading, spacing: 16) {
                    header
                    if model.servers.isEmpty {
                        emptyState
                    } else {
                        ForEach(model.servers, id: \.id) { server in
                            ServerRow(
                                server: server,
                                palette: palette,
                                isPreferred: model.settings.preferredServerID == server.id,
                                localizer: model.l10n
                            ) {
                                model.settings.preferredServerID = server.id
                            }
                        }
                        Button {
                            model.settings.preferredServerID = nil
                        } label: {
                            Text(model.l10n.text(.serversUseAutomaticRace))
                                .font(.system(size: 13, weight: .semibold, design: .rounded))
                                .foregroundStyle(palette.accent)
                                .frame(maxWidth: .infinity)
                                .padding(.vertical, 13)
                                .background(Capsule().stroke(palette.accent.opacity(0.35), lineWidth: 1))
                        }
                        .buttonStyle(.plain)
                    }
                }
                .padding(.horizontal, 20)
                .padding(.top, 14)
                .padding(.bottom, 30)
            }
            .background(palette.background.ignoresSafeArea())
            .navigationTitle(model.l10n.text(.tabServers))
            .navigationBarTitleDisplayMode(.inline)
            .toolbarBackground(palette.backgroundBottom, for: .navigationBar)
            .toolbarBackground(.visible, for: .navigationBar)
        }
    }

    private var header: some View {
        VStack(alignment: .leading, spacing: 7) {
            Text(model.l10n.text(.serversTokenPool))
                .font(.system(size: 10, weight: .bold, design: .rounded))
                .tracking(1.8)
                .foregroundStyle(palette.textSecondary)
            Text(model.l10n.text(.commonEndpointsCount, model.servers.count))
                .font(.system(size: 25, weight: .bold, design: .rounded))
                .foregroundStyle(palette.textPrimary)
            Text(model.l10n.text(.serversLoginRaceExplanation))
                .font(.system(size: 12, weight: .medium, design: .rounded))
                .foregroundStyle(palette.textSecondary)
        }
    }

    private var emptyState: some View {
        GlassCard(palette: palette) {
            VStack(alignment: .leading, spacing: 10) {
                Image(systemName: "tray")
                    .font(.system(size: 24))
                    .foregroundStyle(palette.accent)
                Text(model.l10n.text(.serversNoServers))
                    .font(.system(size: 17, weight: .bold, design: .rounded))
                    .foregroundStyle(palette.textPrimary)
                Text(model.l10n.text(.serversEmptyExplanation))
                    .font(.system(size: 12, weight: .medium, design: .rounded))
                    .foregroundStyle(palette.textSecondary)
            }
        }
    }
}

private struct ServerRow: View {
    let server: FPTNServer
    let palette: ThemePalette
    let isPreferred: Bool
    let localizer: Localizer
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            HStack(spacing: 13) {
                ZStack {
                    RoundedRectangle(cornerRadius: 14, style: .continuous)
                        .fill(palette.surfaceStrong)
                        .frame(width: 50, height: 50)
                    Text(server.displayCountryCode ?? "··")
                        .font(.system(size: 13, weight: .bold, design: .rounded))
                        .foregroundStyle(palette.accent)
                }
                VStack(alignment: .leading, spacing: 4) {
                    HStack(spacing: 6) {
                        Text(server.name)
                            .font(.system(size: 15, weight: .semibold, design: .rounded))
                            .foregroundStyle(palette.textPrimary)
                            .lineLimit(1)
                        if server.isCensoredZone {
                            Text(localizer.text(.serversRealityBadge))
                                .font(.system(size: 8, weight: .bold, design: .rounded))
                                .tracking(0.8)
                                .foregroundStyle(palette.warning)
                                .padding(.horizontal, 6)
                                .padding(.vertical, 3)
                                .background(Capsule().fill(palette.warning.opacity(0.12)))
                        }
                    }
                    Text("\(server.host):\(String(server.port))")
                        .font(.system(size: 11, weight: .medium, design: .monospaced))
                        .foregroundStyle(palette.textSecondary)
                        .lineLimit(1)
                }
                Spacer()
                Image(systemName: isPreferred ? "pin.fill" : "chevron.right")
                    .font(.system(size: 12, weight: .semibold))
                    .foregroundStyle(isPreferred ? palette.accent : palette.textSecondary.opacity(0.5))
            }
            .padding(14)
            .background(
                RoundedRectangle(cornerRadius: 22, style: .continuous)
                    .fill(palette.surface)
                    .overlay(
                        RoundedRectangle(cornerRadius: 22, style: .continuous)
                            .stroke(
                                isPreferred ? palette.accent.opacity(0.55) : Color.white.opacity(0.07),
                                lineWidth: 1
                            )
                    )
            )
        }
        .buttonStyle(.plain)
    }
}
