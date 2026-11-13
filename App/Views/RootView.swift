import SwiftUI
import FptnShared
import NetworkExtension

struct RootView: View {
    @EnvironmentObject private var model: AppModel
    @State private var tab: AppTab = .home

    var body: some View {
        ZStack {
            model.palette.background.ignoresSafeArea()
            TabView(selection: $tab) {
                DashboardView()
                    .tag(AppTab.home)
                    .tabItem {
                        Label(model.l10n.text(.tabTunnel), systemImage: "shield.lefthalf.filled")
                    }
                ServerListView()
                    .tag(AppTab.servers)
                    .tabItem {
                        Label(model.l10n.text(.tabServers), systemImage: "globe")
                    }
                SettingsView()
                    .tag(AppTab.settings)
                    .tabItem {
                        Label(model.l10n.text(.tabSettings), systemImage: "slider.horizontal.3")
                    }
            }
            .tint(model.palette.accent)
            .toolbarBackground(model.palette.backgroundBottom, for: .tabBar)
            .toolbarBackground(.visible, for: .tabBar)
        }
        .preferredColorScheme(.dark)
        .onReceive(NotificationCenter.default.publisher(for: .NEVPNStatusDidChange)) { _ in
            Task { await model.refreshStatus() }
        }
        .task {
            await model.refreshStatus()
            await model.syncOnDemandSetting()
        }
        .alert(
            "FPTN",
            isPresented: Binding(
                get: { model.lastError != nil },
                set: { if !$0 { model.lastError = nil } }
            )
        ) {
            Button(model.l10n.text(.commonOk)) { model.lastError = nil }
        } message: {
            Text(model.lastError ?? "")
        }
    }
}

private enum AppTab: Hashable {
    case home
    case servers
    case settings
}
