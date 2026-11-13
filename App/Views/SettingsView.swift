import SwiftUI
import FptnShared

struct SettingsView: View {
    @EnvironmentObject private var model: AppModel

    private var palette: ThemePalette { model.palette }

    var body: some View {
        NavigationStack {
            List {
                accessSection
                appearanceSection
                tunnelSection
                diagnosticsSection
                aboutSection
            }
            .scrollContentBackground(.hidden)
            .background(palette.background.ignoresSafeArea())
            .navigationTitle(model.l10n.text(.settingsTitle))
            .navigationBarTitleDisplayMode(.inline)
            .toolbarBackground(palette.backgroundBottom, for: .navigationBar)
            .toolbarBackground(.visible, for: .navigationBar)
        }
    }

    private var accessSection: some View {
        Section {
            if model.token == nil {
                NavigationLink {
                    TokenImportView()
                } label: {
                    Label(
                        model.l10n.text(.settingsImportAccessToken),
                        systemImage: "key.fill"
                    )
                }
            } else {
                HStack {
                    Label(
                        model.l10n.text(.settingsTokenLoaded),
                        systemImage: "checkmark.seal.fill"
                    )
                    .foregroundStyle(palette.success)
                    Spacer()
                    Text(model.l10n.text(.commonServersCount, model.servers.count))
                        .font(.system(size: 12, weight: .medium, design: .rounded))
                        .foregroundStyle(palette.textSecondary)
                }
                NavigationLink {
                    TokenImportView()
                } label: {
                    Label(
                        model.l10n.text(.settingsReplaceToken),
                        systemImage: "arrow.triangle.2.circlepath"
                    )
                }
                Button(role: .destructive) {
                    Task { await model.clearToken() }
                } label: {
                    Label(
                        model.l10n.text(.settingsRemoveToken),
                        systemImage: "trash"
                    )
                }
            }
        } header: {
            sectionHeader(model.l10n.text(.settingsAccess))
        }
        .listRowBackground(palette.surface)
    }

    private var appearanceSection: some View {
        Section {
            HStack(spacing: 10) {
                ForEach(AppTheme.allCases) { theme in
                    Button {
                        model.settings.theme = theme.rawValue
                    } label: {
                        ThemeSwatch(
                            theme: theme,
                            isSelected: model.settings.theme == theme.rawValue,
                            localizer: model.l10n
                        )
                    }
                    .buttonStyle(.plain)
                }
            }
            .padding(.vertical, 4)
            Picker(selection: $model.settings.language) {
                Text(model.l10n.text(.settingsLanguageSystem))
                    .tag(AppLanguage.system)
                Text(model.l10n.text(.settingsLanguageEnglish))
                    .tag(AppLanguage.english)
                Text(model.l10n.text(.settingsLanguageRussian))
                    .tag(AppLanguage.russian)
            } label: {
                Text(model.l10n.text(.settingsLanguage))
            }
        } header: {
            sectionHeader(model.l10n.text(.settingsAppearance))
        }
        .listRowBackground(palette.surface)
    }

    private var tunnelSection: some View {
        Section {
            Picker(selection: $model.settings.strategy) {
                Text(model.l10n.text(.settingsDual)).tag("dual")
                Text(model.l10n.text(.settingsTriple)).tag("triple")
            } label: {
                Text(model.l10n.text(.settingsRollingPool))
            }
            Picker(selection: $model.settings.securityMode) {
                Text(model.l10n.text(.settingsPlainSNI)).tag("plain")
                Text(model.l10n.text(.settingsTLSObfuscation)).tag("obfuscated")
                Text(model.l10n.text(.settingsReality)).tag("reality")
            } label: {
                Text(model.l10n.text(.settingsCensorshipMode))
            }
            Toggle(
                model.l10n.text(.settingsBypassPrivateNetworks),
                isOn: $model.settings.splitTunnelEnabled
            )
            .tint(palette.accent)
            Toggle(
                model.l10n.text(.settingsConnectOnDemand),
                isOn: $model.settings.onDemandEnabled
            )
            .tint(palette.accent)
            .onChange(of: model.settings.onDemandEnabled) { _, enabled in
                Task { await model.applyOnDemandSetting(enabled) }
            }
            Text(model.l10n.text(.settingsOnDemandExplanation))
                .font(.system(size: 11, weight: .medium, design: .rounded))
                .foregroundStyle(palette.textSecondary)
            NavigationLink {
                SplitTunnelView()
            } label: {
                Label(
                    model.l10n.text(.settingsSplitTunnelCIDRs),
                    systemImage: "arrow.triangle.branch"
                )
            }
        } header: {
            sectionHeader(model.l10n.text(.settingsTunnel))
        }
        .listRowBackground(palette.surface)
    }

    private var diagnosticsSection: some View {
        Section {
            NavigationLink {
                DiagnosticsView()
            } label: {
                Label(
                    model.l10n.text(.settingsConnectionDiagnostics),
                    systemImage: "waveform.path.ecg"
                )
            }
        } header: {
            sectionHeader(model.l10n.text(.settingsDiagnostics))
        }
        .listRowBackground(palette.surface)
    }

    private var aboutSection: some View {
        Section {
            HStack {
                Text(model.l10n.text(.settingsVersion))
                Spacer()
                Text(Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "1.0")
                    .foregroundStyle(palette.textSecondary)
            }
            Text(model.l10n.text(.settingsAboutText))
                .font(.system(size: 11, weight: .medium, design: .rounded))
                .foregroundStyle(palette.textSecondary)
        } header: {
            sectionHeader(model.l10n.text(.settingsAbout))
        }
        .listRowBackground(palette.surface)
    }

    private func sectionHeader(_ text: String) -> some View {
        Text(text.uppercased())
            .font(.system(size: 10, weight: .bold, design: .rounded))
            .tracking(1.4)
            .foregroundStyle(palette.textSecondary)
    }
}
