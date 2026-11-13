import SwiftUI
import FptnShared
import NetworkExtension

struct DashboardView: View {
    @EnvironmentObject private var model: AppModel

    private var palette: ThemePalette { model.palette }

    var body: some View {
        NavigationStack {
            ScrollView(showsIndicators: false) {
                VStack(spacing: 22) {
                    header
                    ConnectionOrb(
                        status: model.status,
                        palette: palette,
                        isBusy: model.isBusy,
                        localizer: model.l10n
                    ) {
                        Task { await model.toggleConnection() }
                    }
                    statusCopy
                    if model.token == nil {
                        importPrompt
                    } else {
                        actionButton
                        stats
                        serverCard
                        splitCard
                    }
                }
                .padding(.horizontal, 20)
                .padding(.top, 12)
                .padding(.bottom, 30)
            }
            .background(palette.background.ignoresSafeArea())
            .toolbar(.hidden, for: .navigationBar)
        }
    }

    private var header: some View {
        HStack(alignment: .center) {
            VStack(alignment: .leading, spacing: 5) {
                Text("FPTN")
                    .font(.system(size: 11, weight: .bold, design: .rounded))
                    .tracking(3.2)
                    .foregroundStyle(palette.textSecondary)
                Text(model.serviceName)
                    .font(.system(size: 27, weight: .bold, design: .rounded))
                    .foregroundStyle(palette.textPrimary)
                    .lineLimit(1)
            }
            Spacer()
            StatusPill(
                text: model.statusTitle,
                color: model.statusColor(palette)
            )
        }
    }

    private var statusCopy: some View {
        VStack(spacing: 8) {
            Text(model.statusTitle)
                .font(.system(size: 30, weight: .bold, design: .rounded))
                .foregroundStyle(palette.textPrimary)
            Text(model.statusDetail)
                .font(.system(size: 13, weight: .medium, design: .rounded))
                .foregroundStyle(palette.textSecondary)
                .multilineTextAlignment(.center)
                .frame(maxWidth: 300)
        }
    }

    private var importPrompt: some View {
        GlassCard(palette: palette) {
            VStack(alignment: .leading, spacing: 12) {
                Text(model.l10n.text(.dashboardBringYourOwnAccess))
                    .font(.system(size: 17, weight: .bold, design: .rounded))
                    .foregroundStyle(palette.textPrimary)
                Text(model.l10n.text(.dashboardTokenExplanation))
                    .font(.system(size: 13, weight: .medium, design: .rounded))
                    .foregroundStyle(palette.textSecondary)
                NavigationLink {
                    TokenImportView()
                } label: {
                    Text(model.l10n.text(.dashboardImportToken))
                        .font(.system(size: 14, weight: .semibold, design: .rounded))
                        .foregroundStyle(Color.black.opacity(0.8))
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 13)
                        .background(
                            LinearGradient(
                                colors: [palette.accent, palette.accentSecondary],
                                startPoint: .leading,
                                endPoint: .trailing
                            ),
                            in: Capsule()
                        )
                }
                .buttonStyle(.plain)
            }
        }
    }

    private var actionButton: some View {
        PrimaryButton(
            title: model.isConnected
                ? model.l10n.text(.dashboardDisconnect)
                : model.l10n.text(.dashboardConnect),
            systemImage: model.isConnected ? "stop.fill" : "bolt.fill",
            palette: palette,
            isLoading: model.isBusy
        ) {
            Task { await model.toggleConnection() }
        }
    }

    private var stats: some View {
        HStack(spacing: 10) {
            StatTile(
                label: model.l10n.text(.dashboardServers),
                value: "\(model.servers.count)",
                icon: "server.rack",
                palette: palette
            )
            StatTile(
                label: model.l10n.text(.dashboardPool),
                value: model.strategyTitle,
                icon: "square.stack.3d.up",
                palette: palette
            )
            StatTile(
                label: model.l10n.text(.dashboardSplit),
                value: model.l10n.text(
                    model.settings.splitTunnelEnabled ? .commonOn : .commonOff
                ),
                icon: "arrow.triangle.branch",
                palette: palette
            )
        }
    }

    private var serverCard: some View {
        GlassCard(palette: palette) {
            VStack(alignment: .leading, spacing: 13) {
                SectionHeader(
                    title: model.l10n.text(.dashboardSelectedRoute),
                    palette: palette
                )
                HStack(spacing: 12) {
                    ZStack {
                        Circle()
                            .fill(palette.accent.opacity(0.15))
                            .frame(width: 42, height: 42)
                        Image(systemName: "point.3.connected.trianglepath.dotted")
                            .font(.system(size: 16, weight: .semibold))
                            .foregroundStyle(palette.accent)
                    }
                    VStack(alignment: .leading, spacing: 3) {
                        Text(model.l10n.text(.dashboardAutomaticRace))
                            .font(.system(size: 15, weight: .semibold, design: .rounded))
                            .foregroundStyle(palette.textPrimary)
                        Text(model.l10n.text(.dashboardAutomaticRaceExplanation))
                            .font(.system(size: 11, weight: .medium, design: .rounded))
                            .foregroundStyle(palette.textSecondary)
                    }
                    Spacer()
                    Text("\(model.servers.count)")
                        .font(.system(size: 17, weight: .bold, design: .rounded))
                        .foregroundStyle(palette.accent)
                }
            }
        }
    }

    private var splitCard: some View {
        GlassCard(palette: palette) {
            Toggle(isOn: $model.settings.splitTunnelEnabled) {
                VStack(alignment: .leading, spacing: 3) {
                    Text(model.l10n.text(.dashboardLocalNetworkBypass))
                        .font(.system(size: 15, weight: .semibold, design: .rounded))
                        .foregroundStyle(palette.textPrimary)
                    Text(model.l10n.text(.dashboardLocalNetworkBypassDetail))
                        .font(.system(size: 11, weight: .medium, design: .rounded))
                        .foregroundStyle(palette.textSecondary)
                }
            }
            .tint(palette.accent)
        }
    }
}
