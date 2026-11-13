import SwiftUI
import FptnShared

struct DiagnosticsView: View {
    @EnvironmentObject private var model: AppModel

    private var palette: ThemePalette { model.palette }

    var body: some View {
        List {
            Section {
                InfoRow(
                    label: model.l10n.text(.diagnosticsVPNState),
                    value: model.statusTitle,
                    palette: palette
                )
                InfoRow(
                    label: model.l10n.text(.diagnosticsService),
                    value: model.serviceName,
                    palette: palette
                )
                InfoRow(
                    label: model.l10n.text(.diagnosticsServers),
                    value: "\(model.servers.count)",
                    palette: palette
                )
                InfoRow(
                    label: model.l10n.text(.diagnosticsPreferred),
                    value: model.settings.preferredServerID
                        ?? model.l10n.text(.dashboardAutomaticRace),
                    palette: palette
                )
            } header: {
                header(model.l10n.text(.diagnosticsConnection))
            }
            .listRowBackground(palette.surface)

            Section {
                InfoRow(
                    label: model.l10n.text(.diagnosticsPool),
                    value: model.strategyTitle,
                    palette: palette
                )
                InfoRow(
                    label: model.l10n.text(.diagnosticsCensorship),
                    value: model.securityModeTitle,
                    palette: palette
                )
                InfoRow(
                    label: model.l10n.text(.diagnosticsOnDemand),
                    value: model.onDemandTitle,
                    palette: palette
                )
                InfoRow(
                    label: model.l10n.text(.diagnosticsSplitTunnel),
                    value: model.splitTunnelTitle,
                    palette: palette
                )
                InfoRow(
                    label: model.l10n.text(.diagnosticsCIDRs),
                    value: "\(model.settings.effectiveSplitCIDRs.count)",
                    palette: palette
                )
                InfoRow(
                    label: model.l10n.text(.diagnosticsImportedDomains),
                    value: "\(model.settings.splitDomains.count)",
                    palette: palette
                )
            } header: {
                header(model.l10n.text(.diagnosticsTransport))
            }
            .listRowBackground(palette.surface)

            Section {
                InfoRow(
                    label: model.l10n.text(.diagnosticsProtocol),
                    value: model.l10n.text(.diagnosticsProtocolValue),
                    palette: palette
                )
                InfoRow(
                    label: model.l10n.text(.diagnosticsTLS),
                    value: model.l10n.text(.diagnosticsTLSValue),
                    palette: palette
                )
                InfoRow(
                    label: model.l10n.text(.diagnosticsKeepalive),
                    value: model.l10n.text(.diagnosticsKeepaliveValue),
                    palette: palette
                )
                InfoRow(
                    label: model.l10n.text(.diagnosticsLifetime),
                    value: model.l10n.text(.diagnosticsLifetimeValue),
                    palette: palette
                )
            } header: {
                header(model.l10n.text(.diagnosticsCore))
            }
            .listRowBackground(palette.surface)
        }
        .scrollContentBackground(.hidden)
        .background(palette.background.ignoresSafeArea())
        .navigationTitle(model.l10n.text(.diagnosticsTitle))
        .navigationBarTitleDisplayMode(.inline)
        .toolbarBackground(palette.backgroundBottom, for: .navigationBar)
        .toolbarBackground(.visible, for: .navigationBar)
    }

    private func header(_ text: String) -> some View {
        Text(text.uppercased())
            .font(.system(size: 10, weight: .bold, design: .rounded))
            .tracking(1.4)
            .foregroundStyle(palette.textSecondary)
    }
}

private struct InfoRow: View {
    let label: String
    let value: String
    let palette: ThemePalette

    var body: some View {
        HStack(alignment: .firstTextBaseline) {
            Text(label)
                .font(.system(size: 13, weight: .medium, design: .rounded))
                .foregroundStyle(palette.textPrimary)
            Spacer(minLength: 12)
            Text(value)
                .font(.system(size: 11, weight: .medium, design: .monospaced))
                .foregroundStyle(palette.textSecondary)
                .multilineTextAlignment(.trailing)
                .lineLimit(2)
        }
    }
}
