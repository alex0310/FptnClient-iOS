import SwiftUI
import FptnShared

/// Live RX/TX sparkline. All scaling and geometry come from `FptnShared`, so
/// this file only maps normalized points onto a SwiftUI `Path`.
struct TrafficChartView: View {
    let history: TrafficHistory
    let palette: ThemePalette
    let l10n: Localizer

    private var scale: Double {
        TrafficChartScale.scale(for: history.samples)
    }

    private var points: [TrafficChartPoint] {
        TrafficChartGeometry.points(for: history.samples, scale: scale)
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(alignment: .firstTextBaseline) {
                Text(l10n.text(.diagnosticsTrafficChartTitle))
                    .font(.system(size: 11, weight: .semibold, design: .rounded))
                    .foregroundStyle(palette.textPrimary)
                Spacer(minLength: 8)
                Text(TrafficFormatter.speed(scale))
                    .font(.system(size: 10, weight: .medium, design: .monospaced))
                    .foregroundStyle(palette.textSecondary)
            }
            plot
            legend
        }
        .padding(.vertical, 4)
    }

    private var plot: some View {
        GeometryReader { geometry in
            let size = geometry.size
            ZStack(alignment: .topLeading) {
                grid(size: size)
                if points.count >= 2 {
                    area(\.rxY, size: size, color: palette.accent)
                    line(\.rxY, size: size, color: palette.accent)
                    line(\.txY, size: size, color: palette.accentSecondary)
                } else {
                    Text(l10n.text(.diagnosticsTrafficChartEmpty))
                        .font(.system(size: 11, weight: .medium, design: .rounded))
                        .foregroundStyle(palette.textSecondary)
                        .frame(maxWidth: .infinity, maxHeight: .infinity)
                }
            }
        }
        .frame(height: 116)
    }

    private var legend: some View {
        HStack(spacing: 14) {
            legendItem(
                color: palette.accent,
                title: l10n.text(.diagnosticsTrafficChartRX)
            )
            legendItem(
                color: palette.accentSecondary,
                title: l10n.text(.diagnosticsTrafficChartTX)
            )
            Spacer(minLength: 0)
        }
    }

    private func legendItem(color: Color, title: String) -> some View {
        HStack(spacing: 5) {
            Circle()
                .fill(color)
                .frame(width: 6, height: 6)
            Text(title)
                .font(.system(size: 10, weight: .medium, design: .rounded))
                .foregroundStyle(palette.textSecondary)
        }
    }

    private func grid(size: CGSize) -> some View {
        var path = Path()
        for fraction in [0.25, 0.5, 0.75] {
            let y = size.height * fraction
            path.move(to: CGPoint(x: 0, y: y))
            path.addLine(to: CGPoint(x: size.width, y: y))
        }
        return path.stroke(
            palette.textSecondary.opacity(0.18),
            lineWidth: 0.5
        )
    }

    private func line(
        _ keyPath: KeyPath<TrafficChartPoint, Double>,
        size: CGSize,
        color: Color
    ) -> some View {
        linePath(keyPath, size: size)
            .stroke(
                color,
                style: StrokeStyle(lineWidth: 1.8, lineCap: .round, lineJoin: .round)
            )
    }

    private func area(
        _ keyPath: KeyPath<TrafficChartPoint, Double>,
        size: CGSize,
        color: Color
    ) -> some View {
        areaPath(keyPath, size: size)
            .fill(
                LinearGradient(
                    colors: [color.opacity(0.26), color.opacity(0.02)],
                    startPoint: .top,
                    endPoint: .bottom
                )
            )
    }

    private func linePath(
        _ keyPath: KeyPath<TrafficChartPoint, Double>,
        size: CGSize
    ) -> Path {
        var path = Path()
        for (index, point) in points.enumerated() {
            let position = CGPoint(
                x: point.x * size.width,
                y: point[keyPath: keyPath] * size.height
            )
            if index == 0 {
                path.move(to: position)
            } else {
                path.addLine(to: position)
            }
        }
        return path
    }

    private func areaPath(
        _ keyPath: KeyPath<TrafficChartPoint, Double>,
        size: CGSize
    ) -> Path {
        var path = linePath(keyPath, size: size)
        path.addLine(to: CGPoint(x: size.width, y: size.height))
        path.addLine(to: CGPoint(x: 0, y: size.height))
        path.closeSubpath()
        return path
    }
}
