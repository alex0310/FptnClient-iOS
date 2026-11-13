import SwiftUI
import FptnShared

struct GlassCard<Content: View>: View {
    let palette: ThemePalette
    @ViewBuilder var content: Content

    var body: some View {
        content
            .padding(18)
            .background(
                RoundedRectangle(cornerRadius: 24, style: .continuous)
                    .fill(palette.surface)
                    .overlay(
                        RoundedRectangle(cornerRadius: 24, style: .continuous)
                            .stroke(Color.white.opacity(0.10), lineWidth: 1)
                    )
            )
    }
}

struct StatusPill: View {
    let text: String
    let color: Color

    var body: some View {
        HStack(spacing: 7) {
            Circle()
                .fill(color)
                .frame(width: 7, height: 7)
                .shadow(color: color.opacity(0.8), radius: 6)
            Text(text.uppercased())
                .font(.system(size: 10, weight: .bold, design: .rounded))
                .tracking(1.4)
        }
        .foregroundStyle(color)
        .padding(.horizontal, 12)
        .padding(.vertical, 7)
        .background(Capsule().fill(color.opacity(0.12)))
        .overlay(Capsule().stroke(color.opacity(0.28), lineWidth: 1))
    }
}

struct PrimaryButton: View {
    let title: String
    let systemImage: String
    let palette: ThemePalette
    var isLoading = false
    var action: () -> Void

    var body: some View {
        Button(action: action) {
            HStack(spacing: 10) {
                if isLoading {
                    ProgressView()
                        .tint(Color.black.opacity(0.75))
                } else {
                    Image(systemName: systemImage)
                }
                Text(title)
                    .font(.system(size: 15, weight: .semibold, design: .rounded))
            }
            .frame(maxWidth: .infinity)
            .padding(.vertical, 15)
            .foregroundStyle(Color.black.opacity(0.82))
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
        .disabled(isLoading)
    }
}

struct StatTile: View {
    let label: String
    let value: String
    let icon: String
    let palette: ThemePalette

    var body: some View {
        VStack(alignment: .leading, spacing: 9) {
            Image(systemName: icon)
                .font(.system(size: 15, weight: .semibold))
                .foregroundStyle(palette.accent)
            Text(value)
                .font(.system(size: 20, weight: .bold, design: .rounded))
                .foregroundStyle(palette.textPrimary)
                .lineLimit(1)
                .minimumScaleFactor(0.7)
            Text(label.uppercased())
                .font(.system(size: 9, weight: .bold, design: .rounded))
                .tracking(1.1)
                .foregroundStyle(palette.textSecondary)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(14)
        .background(
            RoundedRectangle(cornerRadius: 18, style: .continuous)
                .fill(palette.surface)
        )
    }
}

struct SectionHeader: View {
    let title: String
    let palette: ThemePalette

    var body: some View {
        Text(title.uppercased())
            .font(.system(size: 10, weight: .bold, design: .rounded))
            .tracking(1.6)
            .foregroundStyle(palette.textSecondary)
            .frame(maxWidth: .infinity, alignment: .leading)
    }
}

struct ThemeSwatch: View {
    let theme: AppTheme
    let isSelected: Bool
    let localizer: Localizer

    var body: some View {
        let palette = ThemePalette(theme.tokens)
        VStack(alignment: .leading, spacing: 10) {
            ZStack {
                RoundedRectangle(cornerRadius: 16, style: .continuous)
                    .fill(palette.background)
                HStack(spacing: 7) {
                    Circle().fill(palette.accent).frame(width: 22, height: 22)
                    Circle().fill(palette.accentSecondary).frame(width: 14, height: 14)
                }
            }
            .frame(height: 74)
            HStack(spacing: 5) {
                Text(localizer.text(theme.titleKey))
                    .font(.system(size: 13, weight: .semibold, design: .rounded))
                    .foregroundStyle(palette.textPrimary)
                if isSelected {
                    Image(systemName: "checkmark.circle.fill")
                        .font(.system(size: 12))
                        .foregroundStyle(palette.accent)
                }
            }
            Text(localizer.text(theme.subtitleKey))
                .font(.system(size: 10, weight: .medium, design: .rounded))
                .foregroundStyle(palette.textSecondary)
                .lineLimit(1)
        }
        .padding(10)
        .background(
            RoundedRectangle(cornerRadius: 22, style: .continuous)
                .fill(palette.surface)
                .overlay(
                    RoundedRectangle(cornerRadius: 22, style: .continuous)
                        .stroke(
                            isSelected ? palette.accent.opacity(0.85) : Color.white.opacity(0.08),
                            lineWidth: isSelected ? 1.5 : 1
                        )
                )
        )
    }
}
