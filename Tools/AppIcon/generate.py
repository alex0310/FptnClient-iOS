#!/usr/bin/env python3
"""Generate the original FPTN iOS app icon without external image tools.

The icon is a dark aurora field with a glowing tunnel orb. It is rendered at
1024x1024 with analytic anti-aliasing and written as an RGB PNG, which is what
an iOS app icon asset expects (no alpha channel).
"""

from __future__ import annotations

import math
import struct
import zlib
from pathlib import Path

SIZE = 1024
CENTER = SIZE / 2.0
OUT = (
    Path(__file__).resolve().parents[2]
    / "App"
    / "Assets.xcassets"
    / "AppIcon.appiconset"
    / "AppIcon-1024.png"
)


def clamp(value: float, low: float = 0.0, high: float = 1.0) -> float:
    return max(low, min(high, value))


def mix(a: tuple[float, float, float], b: tuple[float, float, float], t: float):
    t = clamp(t)
    return (
        a[0] + (b[0] - a[0]) * t,
        a[1] + (b[1] - a[1]) * t,
        a[2] + (b[2] - a[2]) * t,
    )


def add(base, color, alpha: float):
    alpha = clamp(alpha)
    return (
        base[0] + color[0] * alpha,
        base[1] + color[1] * alpha,
        base[2] + color[2] * alpha,
    )


def smoothstep(edge0: float, edge1: float, value: float) -> float:
    if edge0 == edge1:
        return 0.0 if value < edge0 else 1.0
    t = clamp((value - edge0) / (edge1 - edge0))
    return t * t * (3.0 - 2.0 * t)


def gaussian(distance: float, sigma: float) -> float:
    return math.exp(-(distance * distance) / (2.0 * sigma * sigma))


def orbit_distance(
    x: float,
    y: float,
    radius_x: float,
    radius_y: float,
    angle: float,
) -> float:
    dx = x - CENTER
    dy = y - CENTER
    cosine = math.cos(angle)
    sine = math.sin(angle)
    local_x = dx * cosine + dy * sine
    local_y = -dx * sine + dy * cosine
    radius = math.sqrt((local_x / radius_x) ** 2 + (local_y / radius_y) ** 2)
    return abs(radius - 1.0)


def pixel(x: int, y: int) -> tuple[float, float, float]:
    u = x / (SIZE - 1)
    v = y / (SIZE - 1)

    background = mix(
        (0.020, 0.060, 0.105),
        (0.004, 0.010, 0.026),
        clamp(u * 0.55 + v * 0.45),
    )
    background = add(
        background,
        (0.06, 0.46, 0.66),
        0.30 * gaussian(math.hypot(x - 820, y - 180) / SIZE, 0.23),
    )
    background = add(
        background,
        (0.16, 0.24, 0.86),
        0.24 * gaussian(math.hypot(x - 190, y - 850) / SIZE, 0.28),
    )

    distance = math.hypot(x - CENTER, y - CENTER)
    color = background

    glow = math.exp(-((distance - 250.0) / 150.0) ** 2)
    color = add(color, (0.10, 0.75, 0.82), 0.26 * glow)
    color = add(color, (0.20, 0.36, 1.00), 0.12 * glow)

    body_radius = 252.0
    body_alpha = smoothstep(body_radius + 1.5, body_radius - 1.5, distance)
    if body_alpha > 0.0:
        angle = math.atan2(y - CENTER, x - CENTER)
        hue = 0.5 + 0.5 * math.cos(angle - 0.55)
        edge = mix((0.18, 0.90, 0.78), (0.26, 0.48, 1.0), hue)
        body = mix((0.86, 1.0, 0.98), edge, smoothstep(0.0, body_radius, distance))
        body = mix(
            body,
            (0.02, 0.08, 0.14),
            smoothstep(body_radius * 0.68, body_radius, distance) * 0.55,
        )
        highlight = gaussian(
            math.hypot(x - (CENTER - 88), y - (CENTER - 112)),
            118.0,
        )
        body = add(body, (1.0, 1.0, 1.0), 0.42 * highlight)
        color = mix(color, body, body_alpha)

    core_radius = 118.0
    core_alpha = smoothstep(core_radius + 1.2, core_radius - 1.2, distance)
    if core_alpha > 0.0:
        core = mix(
            (0.008, 0.028, 0.055),
            (0.015, 0.070, 0.105),
            clamp(distance / core_radius),
        )
        color = mix(color, core, core_alpha)

    for ring_radius, thickness, ring_color, strength in (
        (core_radius, 6.0, (0.62, 1.0, 0.96), 0.78),
        (body_radius, 4.0, (0.75, 1.0, 0.98), 0.45),
    ):
        ring = smoothstep(thickness, 0.0, abs(distance - ring_radius))
        color = add(color, ring_color, strength * ring)

    for radius_x, radius_y, angle, thickness, ring_color, strength in (
        (360.0, 148.0, -0.42, 0.020, (0.30, 0.96, 0.86), 0.48),
        (430.0, 182.0, 0.58, 0.016, (0.34, 0.56, 1.0), 0.38),
    ):
        if distance > body_radius * 0.94:
            ring = smoothstep(thickness, 0.0, orbit_distance(
                x, y, radius_x, radius_y, angle
            ))
            color = add(color, ring_color, strength * ring)

    return (
        clamp(color[0]),
        clamp(color[1]),
        clamp(color[2]),
    )


def png_chunk(kind: bytes, data: bytes) -> bytes:
    payload = kind + data
    return (
        struct.pack(">I", len(data))
        + payload
        + struct.pack(">I", zlib.crc32(payload) & 0xFFFFFFFF)
    )


def write_png(path: Path) -> None:
    rows = bytearray()
    for y in range(SIZE):
        rows.append(0)
        for x in range(SIZE):
            r, g, b = pixel(x, y)
            rows.extend(
                (
                    int(r * 255.0 + 0.5),
                    int(g * 255.0 + 0.5),
                    int(b * 255.0 + 0.5),
                )
            )

    png = bytearray(b"\x89PNG\r\n\x1a\n")
    png.extend(
        png_chunk(
            b"IHDR",
            struct.pack(">IIBBBBB", SIZE, SIZE, 8, 2, 0, 0, 0),
        )
    )
    png.extend(png_chunk(b"IDAT", zlib.compress(bytes(rows), 9)))
    png.extend(png_chunk(b"IEND", b""))

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(png)
    print(f"wrote {path} ({len(png)} bytes)")


if __name__ == "__main__":
    write_png(OUT)
