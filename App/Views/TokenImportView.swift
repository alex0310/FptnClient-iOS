import SwiftUI
import FptnShared

struct TokenImportView: View {
    @EnvironmentObject private var model: AppModel
    @Environment(\.dismiss) private var dismiss

    @State private var text = ""
    @State private var errorMessage: String?

    private var palette: ThemePalette { model.palette }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 18) {
                VStack(alignment: .leading, spacing: 7) {
                    Text(model.l10n.text(.tokenAccessToken))
                        .font(.system(size: 10, weight: .bold, design: .rounded))
                        .tracking(1.8)
                        .foregroundStyle(palette.textSecondary)
                    Text(model.l10n.text(.tokenHero))
                        .font(.system(size: 26, weight: .bold, design: .rounded))
                        .foregroundStyle(palette.textPrimary)
                    Text(model.l10n.text(.tokenExplanation))
                        .font(.system(size: 12, weight: .medium, design: .rounded))
                        .foregroundStyle(palette.textSecondary)
                }

                TextEditor(text: $text)
                    .font(.system(size: 12, weight: .regular, design: .monospaced))
                    .foregroundStyle(palette.textPrimary)
                    .scrollContentBackground(.hidden)
                    .padding(12)
                    .frame(minHeight: 180)
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

                if let errorMessage {
                    Text(errorMessage)
                        .font(.system(size: 12, weight: .medium, design: .rounded))
                        .foregroundStyle(palette.danger)
                }

                PrimaryButton(
                    title: model.l10n.text(.tokenValidateAndSave),
                    systemImage: "checkmark.shield.fill",
                    palette: palette
                ) {
                    save()
                }

                Button {
                    text = model.rawToken
                } label: {
                    Text(model.l10n.text(.tokenLoadStored))
                        .font(.system(size: 12, weight: .semibold, design: .rounded))
                        .foregroundStyle(palette.textSecondary)
                }
                .buttonStyle(.plain)
            }
            .padding(20)
        }
        .background(palette.background.ignoresSafeArea())
        .navigationTitle(model.l10n.text(.tokenImportTitle))
        .navigationBarTitleDisplayMode(.inline)
        .toolbarBackground(palette.backgroundBottom, for: .navigationBar)
        .toolbarBackground(.visible, for: .navigationBar)
        .onAppear {
            if text.isEmpty {
                text = model.rawToken
            }
        }
    }

    private func save() {
        do {
            try model.importToken(text)
            errorMessage = nil
            dismiss()
        } catch {
            errorMessage = model.message(for: error)
        }
    }
}
