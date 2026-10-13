#!/usr/bin/env python3
"""
Generate the per-Fs 1 kHz sine test vectors used by AUDIO_SOURCE=sine1khz.

Per the project SRS, the driver must support sample rates 8/16/44.1/48 kHz, and
Sow runs a 1 kHz tone at each of them.  We emit one C file per Fs into
src/audio_sine/.  Each file contains FOUR arrays covering the full matrix of
SRS-required resolutions (1.f) and channel modes (1.g):

    const int16_t  sine1khz_16bit_mono_pcm_<rate>[]     // (mandatory)
    const int32_t  sine1khz_32bit_mono_pcm_<rate>[]     // (optional)
    const int16_t  sine1khz_16bit_stereo_pcm_<rate>[]   // (optional)
    const int32_t  sine1khz_32bit_stereo_pcm_<rate>[]   // (optional)

Stereo content is L = R = the same 1 kHz mono tone, interleaved as
[L0, R0, L1, R1, ...].  Same waveform on both channels is the natural
interpretation of "1 kHz sine, stereo" for Sow -- the test still proves
the data path can carry an interleaved L/R buffer end-to-end without the
audio chain doing mono-to-stereo duplication itself.

audio_sine.c picks the matching array at compile time from FRAME_CLK_HZ
(file) + WORD_SIZE_BITS (16- vs 32-bit) + CHANNEL_MODE_ID (mono vs stereo).
The linker drops all the other 3 arrays via --gc-sections, so per-build
flash cost stays equal to a single array.

Loop length is sized to exactly **100 cycles of the 1 kHz tone** so wrapping
back to sample 0 is mathematically continuous at every Fs, including 44.1 kHz
(where one period spans 44.1 samples).  100 cycles works out to:

    Fs=8000   ->   800 samples (100 ms,   1.6 KB s16 /   3.2 KB s32)
    Fs=16000  ->  1600 samples (100 ms,   3.2 KB s16 /   6.4 KB s32)
    Fs=44100  ->  4410 samples (100 ms,   8.8 KB s16 /  17.6 KB s32)
    Fs=48000  ->  4800 samples (100 ms,   9.6 KB s16 /  19.2 KB s32)

Only ONE array is referenced by the build (audio_sine.c picks based on
WORD_SIZE_BITS), so --gc-sections drops the unused one and per-build flash
cost stays equal to a single array.

Output level: ffmpeg `lavfi sine` outputs at a fixed 1/8 of full-scale by
default (= -18.06 dBFS, empirically: peak s16 = 4095 = 0x0FFF), and there is
no `amplitude` parameter on the sine filter in the ffmpeg builds we target.
So we COMPENSATE with the `volume` filter: gain = level_dbfs + 18.06 dB.

A previous iteration applied `volume=<level>dB` without the +18 compensation
and shipped clips at -24 dBFS while labelling them -6 dBFS; this script
fixes that by computing the linear ratio (10^(level/20) / 0.125) so the
peak in the resulting .c file matches the requested level exactly.

Usage (run from .../tas2505/):

    # Regenerate ALL four files at the default -6 dBFS, 100-cycle clip
    python3 src/tools/gen_sine_pcm.py

    # Regenerate just one rate
    python3 src/tools/gen_sine_pcm.py --fs 44100

    # Quieter clip (-12 dBFS), all rates
    python3 src/tools/gen_sine_pcm.py --level -12

    # Longer clip (200 cycles instead of 100) -- still loop-clean
    python3 src/tools/gen_sine_pcm.py --cycles 200

The frequency is locked to 1000 Hz ; no --freq option is exposed.

Source-of-truth note: keep this script in tree even after the .c files have
been regenerated.  The C files are a build artifact; the script + ffmpeg
command are what proves "those samples are a 1 kHz sine, period."
"""

import argparse
import math
import os
import shutil
import struct
import subprocess
import sys

### Locked test-vector parameters
SINE_FREQ_HZ   = 1000        # only frequency this script will ever emit
SUPPORTED_FS   = (8000, 16000, 44100, 48000)
DEFAULT_CYCLES = 100         # 100 ms-ish clip length across rates

PREFIX_S16_MONO   = "sine1khz_16bit_mono_pcm"
PREFIX_S32_MONO   = "sine1khz_32bit_mono_pcm"
PREFIX_S16_STEREO = "sine1khz_16bit_stereo_pcm"
PREFIX_S32_STEREO = "sine1khz_32bit_stereo_pcm"


def need_tool(name):
    if shutil.which(name) is None:
        sys.exit(f"error: '{name}' not found. Install it (sudo apt install -y {name}).")


def cycles_to_samples(cycles, fs):
    """Number of samples for N cycles of SINE_FREQ_HZ at sample rate fs."""
    num = cycles * fs
    if num % SINE_FREQ_HZ != 0:
        sys.exit(f"internal: cycles={cycles} and fs={fs} produce a non-integer "
                 f"sample count -- pick a different --cycles value.")
    return num // SINE_FREQ_HZ


def run_ffmpeg_sine(fs, n_samples, level_dbfs, sample_fmt):
    """
    Run ffmpeg lavfi sine.  Returns raw little-endian mono PCM bytes
    (length = n_samples * bytes_per_sample).

    sample_fmt: "s16" -> int16 LE, "s32" -> int32 LE.

    lavfi sine itself has no amplitude knob and emits at peak = 1/8 FS
    (= -18.06 dBFS).  We chain a `volume` filter set to the linear gain
    that lifts that to the requested `level_dbfs`.
    """
    LAVFI_DEFAULT_PEAK = 0.125                       # 1/8 of full-scale, -18.06 dBFS
    target_linear      = math.pow(10.0, level_dbfs / 20.0)
    volume_gain        = target_linear / LAVFI_DEFAULT_PEAK
    duration_s         = n_samples / fs
    container          = "s16le" if sample_fmt == "s16" else "s32le"
    bps                = 2 if sample_fmt == "s16" else 4

    cmd = [
        "ffmpeg", "-hide_banner", "-loglevel", "warning",
        "-f", "lavfi",
        "-i", (f"sine=frequency={SINE_FREQ_HZ}"
               f":sample_rate={fs}"
               f":duration={duration_s:.9f}"),
        "-af", f"volume={volume_gain:.9f}",          # linear (not dB) -> exact
        "-ac", "1",
        "-sample_fmt", sample_fmt,
        "-f", container,
        "-t", f"{duration_s:.9f}",
        "pipe:1",
    ]
    res = subprocess.run(cmd, capture_output=True, check=False)
    if res.returncode != 0:
        sys.stderr.write(res.stderr.decode("utf-8", errors="replace"))
        sys.exit(f"ffmpeg failed (exit {res.returncode})")
    # Some ffmpeg versions emit slightly more samples than requested; trim.
    return res.stdout[: n_samples * bps]


def bytes_to_int16(buf):
    n = len(buf) // 2
    return list(struct.unpack(f"<{n}h", buf[: n * 2]))


def bytes_to_int32(buf):
    n = len(buf) // 4
    return list(struct.unpack(f"<{n}i", buf[: n * 4]))


### File templates

def fs_tag(fs):
    if fs == 8000:    return "8k"
    if fs == 16000:   return "16k"
    if fs == 44100:   return "44k"
    if fs == 48000:   return "48k"
    sys.exit(f"unsupported Fs: {fs}")


def var16_mono(fs):
    return f"{PREFIX_S16_MONO}_{fs_tag(fs)}"


def var32_mono(fs):
    return f"{PREFIX_S32_MONO}_{fs_tag(fs)}"


def var16_stereo(fs):
    return f"{PREFIX_S16_STEREO}_{fs_tag(fs)}"


def var32_stereo(fs):
    return f"{PREFIX_S32_STEREO}_{fs_tag(fs)}"


def mono_to_stereo(samples_mono):
    """L = R = mono interleaved as [L0, R0, L1, R1, ...]."""
    out = []
    for s in samples_mono:
        out.append(s)
        out.append(s)
    return out


def header_text():
    lines = [
        "/*",
        " * Declarations for the 1 kHz sine test vectors (one .c file per Fs).",
        " * Auto-generated by src/tools/gen_sine_pcm.py -- DO NOT EDIT BY HAND.",
        " *",
        f" * Pure {SINE_FREQ_HZ} Hz sine.  Each Fs ships four arrays covering",
        " * the full SRS 1.f x 1.g matrix:",
        " *",
        " *   sine1khz_16bit_mono_pcm_<rate>     int16_t   (mandatory)",
        " *   sine1khz_32bit_mono_pcm_<rate>     int32_t   (optional)",
        " *   sine1khz_16bit_stereo_pcm_<rate>   int16_t   (optional)",
        " *   sine1khz_32bit_stereo_pcm_<rate>   int32_t   (optional)",
        " *",
        " * Stereo layout: [L0, R0, L1, R1, ...] with L == R (same 1 kHz tone).",
        " *",
        " * Every array is exactly N integer cycles long so the loop boundary is",
        " * glitch-free even at 44.1 kHz (where one period spans 44.1 samples).",
        " *",
        " *   Fs (Hz) | mono samples | mono bytes (s16/s32) | stereo bytes (s16/s32) | cycles",
        " *   --------+--------------+----------------------+------------------------+-------",
        " *      8000 |          800 |       1600 /    3200 |        3200 /    6400  |    100",
        " *     16000 |         1600 |       3200 /    6400 |        6400 /   12800  |    100",
        " *     44100 |         4410 |       8820 /   17640 |       17640 /   35280  |    100",
        " *     48000 |         4800 |       9600 /   19200 |       19200 /   38400  |    100",
        " *",
        " * All four arrays for a given Fs ship in the same sine_<rate>.c file;",
        " * the linker drops the three unused ones via --gc-sections.  audio_sine.c",
        " * selects the array at compile time from FRAME_CLK_HZ (file) + WORD_SIZE_BITS",
        " * (resolution) + CHANNEL_MODE_ID (mono vs stereo).",
        " *",
        " * SPDX-License-Identifier: Apache-2.0",
        " */",
        "#ifndef AUDIO_SINE_SINE_H_",
        "#define AUDIO_SINE_SINE_H_",
        "",
        "#include <stdint.h>",
        "",
        "#ifdef __cplusplus",
        'extern "C" {',
        "#endif",
        "",
    ]
    for fs in SUPPORTED_FS:
        lines += [
            f"/* Fs = {fs} Hz */",
            f"extern const int16_t      {var16_mono(fs)}[];",
            f"extern const unsigned int {var16_mono(fs)}_len;",
            f"extern const int32_t      {var32_mono(fs)}[];",
            f"extern const unsigned int {var32_mono(fs)}_len;",
            f"extern const int16_t      {var16_stereo(fs)}[];   /* interleaved L,R,L,R, ... */",
            f"extern const unsigned int {var16_stereo(fs)}_len; /* total int16_t count (= 2 * frames) */",
            f"extern const int32_t      {var32_stereo(fs)}[];   /* interleaved L,R,L,R, ... */",
            f"extern const unsigned int {var32_stereo(fs)}_len; /* total int32_t count (= 2 * frames) */",
            "",
        ]
    lines += [
        "#ifdef __cplusplus",
        "}",
        "#endif",
        "",
        "#endif /* AUDIO_SINE_SINE_H_ */",
        "",
    ]
    return "\n".join(lines)


def source_file_text(fs, samples_s16, samples_s32, level_dbfs, cycles):
    n_frames = len(samples_s16)
    dur_ms   = n_frames * 1000.0 / fs

    stereo_s16 = mono_to_stereo(samples_s16)
    stereo_s32 = mono_to_stereo(samples_s32)

    head = [
        "/*",
        " * Auto-generated by src/tools/gen_sine_pcm.py -- DO NOT EDIT BY HAND.",
        " *",
        f" * 1 kHz sine wave, Fs = {fs} Hz.",
        f" *   - {n_frames} frames ({cycles} cycles of {SINE_FREQ_HZ} Hz, ~{dur_ms:.2f} ms)",
        f" *   - Level: {level_dbfs:+.1f} dBFS (lavfi sine + volume compensation, exact)",
        " *",
        " * Four parallel arrays (same waveform, every SRS resolution + channel combo):",
        f" *   {var16_mono(fs)}[]     -- int16_t mono   (mandatory)",
        f" *   {var32_mono(fs)}[]     -- int32_t mono   (optional)",
        f" *   {var16_stereo(fs)}[]   -- int16_t stereo L,R interleaved (optional)",
        f" *   {var32_stereo(fs)}[]   -- int32_t stereo L,R interleaved (optional)",
        " *",
        " * Stereo content is L == R == the same 1 kHz tone.  Linker --gc-sections",
        " * drops the three arrays audio_sine.c does not reference for this build.",
        " *",
        " * SPDX-License-Identifier: Apache-2.0",
        " */",
        "",
        '#include "sine.h"',
        "",
    ]

    def fmt_array(decl_type, var, samples, width_per_line, value_width):
        lines = [f"const {decl_type} {var}[] = {{"]
        for i in range(0, len(samples), width_per_line):
            chunk = samples[i : i + width_per_line]
            cells = ", ".join(f"{v:>{value_width}d}" for v in chunk)
            tail = "," if i + width_per_line < len(samples) else ""
            lines.append(f"\t{cells}{tail}")
        lines.append("};")
        lines.append("")
        lines.append(f"const unsigned int {var}_len =")
        lines.append(f"\tsizeof({var}) / sizeof({var}[0]);")
        lines.append("")
        return lines

    body = []
    body += fmt_array("int16_t", var16_mono(fs),   samples_s16,
                      width_per_line=12, value_width=7)
    body += fmt_array("int32_t", var32_mono(fs),   samples_s32,
                      width_per_line=6,  value_width=12)
    body += fmt_array("int16_t", var16_stereo(fs), stereo_s16,
                      width_per_line=12, value_width=7)
    body += fmt_array("int32_t", var32_stereo(fs), stereo_s32,
                      width_per_line=6,  value_width=12)

    return "\n".join(head + body)


def emit_files(out_dir, fs_list, level_dbfs, cycles):
    os.makedirs(out_dir, exist_ok=True)

    with open(os.path.join(out_dir, "sine.h"), "w") as f:
        f.write(header_text())

    results = []
    for fs in fs_list:
        n_samples   = cycles_to_samples(cycles, fs)

        s16_bytes   = run_ffmpeg_sine(fs, n_samples, level_dbfs, "s16")
        if len(s16_bytes) != n_samples * 2:
            sys.exit(f"ffmpeg s16: got {len(s16_bytes)//2} samples for Fs={fs} "
                     f"(expected {n_samples}); abort.")
        samples_s16 = bytes_to_int16(s16_bytes)

        s32_bytes   = run_ffmpeg_sine(fs, n_samples, level_dbfs, "s32")
        if len(s32_bytes) != n_samples * 4:
            sys.exit(f"ffmpeg s32: got {len(s32_bytes)//4} samples for Fs={fs} "
                     f"(expected {n_samples}); abort.")
        samples_s32 = bytes_to_int32(s32_bytes)

        c_path      = os.path.join(out_dir, f"sine_{fs_tag(fs)}.c")
        with open(c_path, "w") as f:
            f.write(source_file_text(fs, samples_s16, samples_s32,
                                     level_dbfs, cycles))

        results.append((fs, n_samples, c_path,
                        max(abs(v) for v in samples_s16),
                        max(abs(v) for v in samples_s32)))
    return results


def main():
    parser = argparse.ArgumentParser(
        description=(f"Generate src/audio_sine/sine_*.c -- pure {SINE_FREQ_HZ} Hz "
                     f"sine test vectors at all SRS-supported sample rates, "
                     f"both 16-bit (mandatory) and 32-bit (optional)."))
    parser.add_argument("--fs", type=int, choices=SUPPORTED_FS, default=None,
                        help=("emit only this rate (default: emit all four "
                              "rates so a single run prepares every build)"))
    parser.add_argument("--cycles", type=int, default=DEFAULT_CYCLES,
                        help=f"clip length in cycles of the 1 kHz tone "
                             f"(default {DEFAULT_CYCLES}; must divide "
                             f"cleanly for every selected Fs)")
    parser.add_argument("--level", type=float, default=-6.0,
                        help="output level in dBFS (default -6; use 0 for FS)")
    default_dir = os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        "..", "audio_sine")
    parser.add_argument("-d", "--out-dir", default=default_dir,
                        help="output directory (default ../audio_sine/)")
    args = parser.parse_args()

    if args.cycles <= 0:
        sys.exit("--cycles must be > 0")
    if args.level > 0:
        sys.exit("--level must be <= 0 dBFS (lavfi amplitude would clip)")

    need_tool("ffmpeg")

    fs_list = [args.fs] if args.fs else list(SUPPORTED_FS)
    out_dir = os.path.abspath(args.out_dir)
    results = emit_files(out_dir, fs_list, args.level, args.cycles)

    print(f"wrote {os.path.join(out_dir, 'sine.h')}")
    for fs, n_samples, c_path, peak16, peak32 in results:
        dur_ms = n_samples * 1000.0 / fs
        print(f"wrote {c_path}")
        print(f"  Fs={fs:5d} Hz  samples={n_samples}  "
              f"duration={dur_ms:.2f} ms  "
              f"peak16={peak16}  peak32={peak32}")
    print(f"\nFrequency=1000 Hz (locked), level={args.level:+.1f} dBFS, "
          f"cycles={args.cycles}")
    print("Each sine_<rate>.c contains 4 arrays:")
    print("  - int16_t mono   (mandatory)")
    print("  - int32_t mono   (optional)")
    print("  - int16_t stereo (optional)")
    print("  - int32_t stereo (optional)")
    print("Linker --gc-sections keeps only the array referenced by audio_sine.c.")


if __name__ == "__main__":
    main()
