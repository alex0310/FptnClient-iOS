import SwiftUI
import UniformTypeIdentifiers
import FptnCore
import FptnShared

struct SplitTunnelView: View {
    @EnvironmentObject private var model: AppModel

    @State private var cidrText = ""
    @State private var invalidLines: [String] = []
    @State private var bundledCount = 0
    @State private var showImporter = false
    @State private var appendImported = false
    @State private var importStatus: String?

    private var palette: ThemePalette { model.palette }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 18) {
                domainSection
                Divider().overlay(palette.textSecondary.opacity(0.2))
                cidrSection
            }
            .padding(20)
        }
        .background(palette.background.ignoresSafeArea())
        .navigationTitle(model.l10n.text(.splitTitle))
        .navigationBarTitleDisplayMode(.inline)
        .toolbarBackground(palette.backgroundBottom, for: .navigationBar)
        .toolbarBackground(.visible, for: .navigationBar)
        .onAppear {
            cidrText = model.settings.splitCIDRs.joined(separator: "\n")
            bundledCount = SplitTunnelRules.bundled().count
        }
        .fileImporter(
            isPresented: $showImporter,
            allowedContentTypes: [.plainText],
            allowsMultipleSelection: false
        ) { result in
            importFile(result)
        }
    }

    private var domainSection: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text(model.l10n.text(.splitDomainRules))
                .font(.system(size: 10, weight: .bold, design: .rounded))
                .tracking(1.6)
                .foregroundStyle(palette.textSecondary)

            HStack(spacing: 10) {
                countTile("\(bundledCount)", label: model.l10n.text(.splitBundled))
                countTile(
                    "\(model.settings.splitDomains.count)",
                    label: model.l10n.text(.splitImported)
                )
            }

            Text(model.l10n.text(.splitDomainExplanation))
                .font(.system(size: 12, weight: .medium, design: .rounded))
                .foregroundStyle(palette.textSecondary)

            Toggle(
                model.l10n.text(.splitAppendImported),
                isOn: $appendImported
            )
            .font(.system(size: 13, weight: .medium, design: .rounded))
            .tint(palette.accent)

            Button {
                showImporter = true
            } label: {
                Label(
                    model.l10n.text(.splitImportDomainList),
                    systemImage: "doc.badge.plus"
                )
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

            if !model.settings.splitDomains.isEmpty {
                Button(role: .destructive) {
                    model.settings.splitDomains = []
                    importStatus = model.l10n.text(.splitImportedListCleared)
                } label: {
                    Text(model.l10n.text(.splitClearImported))
                        .font(.system(size: 12, weight: .semibold, design: .rounded))
                }
                .buttonStyle(.plain)
            }

            if let importStatus {
                Text(importStatus)
                    .font(.system(size: 11, weight: .medium, design: .rounded))
                    .foregroundStyle(palette.textSecondary)
            }
        }
    }

    private var cidrSection: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text(model.l10n.text(.splitCIDRExclusions))
                .font(.system(size: 10, weight: .bold, design: .rounded))
                .tracking(1.6)
                .foregroundStyle(palette.textSecondary)

            Text(model.l10n.text(.splitCIDRExplanation))
                .font(.system(size: 12, weight: .medium, design: .rounded))
                .foregroundStyle(palette.textSecondary)

            TextEditor(text: $cidrText)
                .font(.system(size: 12, weight: .regular, design: .monospaced))
                .foregroundStyle(palette.textPrimary)
                .scrollContentBackground(.hidden)
                .padding(12)
                .frame(minHeight: 200)
                .background(
                    RoundedRectangle(cornerRadius: 20, style: .continuous)
                        .fill(palette.surface)
                        .overlay(
                            RoundedRectangle(cornerRadius: 20, style: .continuous)
                                .stroke(Color.white.opacity(0.08), lineWidth: 1)
                        )
                )
                .textInputAutocapitalization(.never)
                .autocorrectionDisabled()

            if !invalidLines.isEmpty {
                VStack(alignment: .leading, spacing: 4) {
                    Text(model.l10n.text(.splitIgnoredEntries))
                        .font(.system(size: 11, weight: .bold, design: .rounded))
                        .foregroundStyle(palette.warning)
                    ForEach(invalidLines, id: \.self) { line in
                        Text(line)
                            .font(.system(size: 11, design: .monospaced))
                            .foregroundStyle(palette.danger)
                    }
                }
            }

            PrimaryButton(
                title: model.l10n.text(.splitSaveCIDRRules),
                systemImage: "checkmark.circle.fill",
                palette: palette
            ) {
                saveCIDRs()
            }

            Button {
                cidrText = SharedSettings.defaultSplitCIDRs.joined(separator: "\n")
                invalidLines = []
            } label: {
                Text(model.l10n.text(.splitRestoreDefaults))
                    .font(.system(size: 12, weight: .semibold, design: .rounded))
                    .foregroundStyle(palette.accent)
            }
            .buttonStyle(.plain)
        }
    }

    private func countTile(_ value: String, label: String) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(value)
                .font(.system(size: 22, weight: .bold, design: .rounded))
                .foregroundStyle(palette.textPrimary)
            Text(label.uppercased())
                .font(.system(size: 9, weight: .bold, design: .rounded))
                .tracking(1.0)
                .foregroundStyle(palette.textSecondary)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(12)
        .background(
            RoundedRectangle(cornerRadius: 16, style: .continuous)
                .fill(palette.surface)
        )
    }

    private func saveCIDRs() {
        var valid: [String] = []
        var invalid: [String] = []
        for line in cidrText.split(whereSeparator: { $0.isNewline }) {
            let value = line.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !value.isEmpty else { continue }
            if IPPrefix(value) != nil {
                valid.append(value)
            } else {
                invalid.append(value)
            }
        }
        invalidLines = invalid
        guard invalid.isEmpty else { return }
        model.settings.splitCIDRs = valid
    }

    private func importFile(_ result: Result<[URL], Error>) {
        switch result {
        case let .success(urls):
            guard let url = urls.first else {
                importStatus = model.l10n.text(.splitNoFileSelected)
                return
            }
            let accessed = url.startAccessingSecurityScopedResource()
            defer {
                if accessed {
                    url.stopAccessingSecurityScopedResource()
                }
            }
            do {
                let text = try String(contentsOf: url, encoding: .utf8)
                let parsed = SplitTunnelRules.parse(text)
                guard !parsed.isEmpty else {
                    importStatus = model.l10n.text(.splitNoDomainRules)
                    return
                }
                if appendImported {
                    model.settings.splitDomains = SplitTunnelRules.merge(
                        model.settings.splitDomains,
                        parsed
                    )
                } else {
                    model.settings.splitDomains = parsed
                }
                importStatus = model.l10n.text(.splitImportedRules, parsed.count)
            } catch {
                importStatus = error.localizedDescription
            }
        case let .failure(error):
            importStatus = error.localizedDescription
        }
    }
}
