TAS2505 I2S TX (xG27-DK2602A)
==============================

Overview
--------

This sample plays a short **mono** melody on **USART0** in I2S mode, intended
to drive a TI TAS2505 audio codec connected
to the board.

The audio source is mono (single stream from ``audio_pcm``,
``audio_short_songs``, or ``audio_sine``). The wire always carries two
channel slots per LRCLK frame, but how the sample fills TX buffers depends
on ``CHANNEL_MODE`` (see *Channel modes* below):

* ``mono_left`` / ``mono_right``: ``i2s_configure(channels=1)`` with driver
  **DMASPLIT** — mono app buffer ``[M0, M1, ...]``; driver LDMA feeds silence
  on one slot and samples on the other.
* ``stereo``: ``i2s_configure(channels=2)`` with interleaved ``[L0, R0, ...]``.
  Mono sources duplicate L=R in software; ``sine1khz`` can use native stereo
  clips when ``CHANNEL_MODE=stereo``.

True stereo (two distinct L/R streams) requires extending the audio
backend; it is left as an optional enhancement.

The sample requires a board overlay (``boards/xg27_rb4194a.overlay`` or
``boards/xg27_dk2602a.overlay``), which:

* Switches ``usart0`` to ``compatible = "silabs,efr32-usart-i2s"``.
* Routes **TX**, **RX**, **CLK**, and **CS** (word select) to PC0, PC1, PC2, and PC3.
* Disables the on-board **MX25R8035F** flash node, which otherwise owns
  USART0/PC0-PC3 as SPI on the xG27-DK2602A thunderboard, and drops the
  associated ``cs-gpios`` so PC3 is free for the I2S word-select line.

UART **console stays on USART1** (PA5/PA6); it does not conflict with this setup.

Before starting the I2S stream, the sample queues a few silent **pre-roll
blocks** so the codec has time to lock onto BCLK/LRCLK before any audio is
shifted out.

Requirements
------------

* Silicon Labs EFR32xG27 device (e.g. BRD4194A / ``xg27_rb4194a`` radio board, or
  BRD2602A / ``xg27_dk2602a`` dev kit).
* Optional: logic analyzer or TAS2505 / I2S codec on the selected pins.

Build options
-------------

The sample exposes CMake cache variables (``CMakeLists.txt``), passed with
``west build ... -- -D<name>=<value>``:

.. list-table::
   :header-rows: 1
   :widths: 20 15 65

   * - Variable
     - Default
     - Description
   * - ``AUDIO_SOURCE``
     - ``pcm``
     - ``pcm``: embedded ``song_pcm.c``; ``short_songs``: runtime PD melodies
       timed by ``FRAME_CLK_HZ`` (small flash); ``sine1khz``: pure 1 kHz tone
       from ``sine.c`` (locked to ``FRAME_CLK_HZ=16000``; SRS 2.b clock-validation
       test).
   * - ``FRAME_CLK_HZ``
     - ``16000``
     - I2S frame (sample) clock, in Hz.
   * - ``PLAYBACK_SECONDS``
     - ``30``
     - Used when regenerating ``song_pcm.c`` (``pcm`` mode only).
   * - ``WORD_SIZE``
     - ``16``
     - I2S sample word size in bits. Must be ``16`` or ``32``; CMake aborts
       with ``FATAL_ERROR`` for any other value.
   * - ``TAS2505_BOARD``
     - ``0``
     - Set ``1`` to run TAS2505 I2C init (overlay + codec wiring required).
   * - ``PLAYBACK_MODE``
     - ``one_shot``
     - ``one_shot``: play once, drain, then ``i2s_configure(off)`` gates
       BCLK/LRCLK on the pins. ``loopback``: replay the clip / playlist
       forever (no drain, clocks never stop).
   * - ``CHANNEL_MODE``
     - ``mono_right``
     - ``mono_left`` | ``mono_right`` | ``stereo`` (see below).

``WORD_SIZE`` selects between the two formats supported by the EFR32 USART-I2S
driver. The audio source is always mono; how it lands in the TX buffer
depends on ``CHANNEL_MODE``:

* ``WORD_SIZE=16`` -> ``usartI2sFormatW16D16`` (16-bit slot, 16-bit data).
* ``WORD_SIZE=32`` -> ``usartI2sFormatW32D16`` (32-bit slot, 16-bit data;
  16-bit payload in the **low half** of each word via ``SAMPLE_EXPAND`` in
  ``src/main.c``).

For ``channels=1`` builds (``mono_left``, ``mono_right``), each frame is one
mono sample ``{M}``; the driver places it on L or R via DMASPLIT. For
``stereo`` (``channels=2``), each frame is two slots wide (``{L, R}``).

Note: writing two distinct L/R streams (true stereo) is an optional future
enhancement and is intentionally not part of this sample.

Channel modes
~~~~~~~~~~~~~

The driver always emits two channel slots on the wire (L+R per LRCLK
frame). ``CHANNEL_MODE`` controls where the mono audio lands and which
``i2s_configure()`` channel count ``main.c`` uses:

.. list-table::
   :header-rows: 1
   :widths: 14 10 10 10 56

   * - Mode
     - Left slot
     - Right slot
     - ``i2s_ch``
     - Notes / use case
   * - ``mono_left``
     - audio
     - silence
     - 1
     - **DMASPLIT** + ``silabs,mono-tx-slot = "left"`` (via ``boards/mono_left.overlay``);
       mono buffer ``[M0, M1, ...]`` (``block=512`` @ 16-bit).
   * - ``mono_right``
     - silence
     - audio
     - 1
     - **DMASPLIT** (default right slot); mono buffer ``[M0, M1, ...]``.
   * - ``stereo``
     - audio
     - audio
     - 2
     - Interleaved ``channels=2``; ``sine1khz`` can use native stereo clips.
       Mono backends duplicate L=R in ``fill_block_stereo()``.

TX buffer memory (``WORD_SIZE=16``, ``SAMPLES_PER_BLOCK=256``,
``NUM_BLOCKS=8``):

.. list-table::
   :header-rows: 1
   :widths: 18 14 14 14 40

   * - ``CHANNEL_MODE``
     - Block size
     - ``tx_slab``
     - Total RAM*
     - Driver path
   * - ``mono_left``
     - 512 B
     - 4096 B
     - ~12.9 KB
     - ``channels=1``, DMASPLIT=1
   * - ``mono_right``
     - 512 B
     - 4096 B
     - ~12.9 KB
     - ``channels=1``, DMASPLIT=1
   * - ``stereo``
     - 1024 B
     - 8192 B
     - ~16.9 KB
     - ``channels=2``, DMASPLIT=0

\*Measured on ``xg27_rb4194a`` with ``AUDIO_SOURCE=sine1khz``,
``FRAME_CLK_HZ=16000``, ``TAS2505_BOARD=0`` (I2S-only bench build).
Flash audio data (``sine1khz_16bit_mono_pcm_16k[]``) is **3200 B** for mono
modes; stereo may link the larger interleaved clip.

Building and running
----------------------

Run these from your **west workspace** directory (the folder that contains
``zephyr-4.4.0`` and ``.west``, for example ``devs-i2s-driver-zephyr/projects``
after ``west init -l zephyr-4.4.0``). Keep build output **outside** the Zephyr
tree with ``-d`` (matches a typical Zephyr west layout).

BRD4194A (``xg27_rb4194a``), embedded PCM (``AUDIO_SOURCE=pcm``):

.. code-block:: shell

   python -m west build -p always -b xg27_rb4194a zephyr-4.4.0/samples/drivers/i2s/tas2505 -d build/tas2505_w16 -- -DBUILD_VERSION=4.4.0 -DWORD_SIZE=16 -DTAS2505_BOARD=1
   python -m west flash -d build/tas2505_w16

BRD4194A, short public-domain songs (``AUDIO_SOURCE=short_songs``, no ``song_pcm`` flash):

.. code-block:: shell

   python -m west build -p always -b xg27_rb4194a zephyr-4.4.0/samples/drivers/i2s/tas2505 -d build/tas2505_short -- -DBUILD_VERSION=4.4.0 -DAUDIO_SOURCE=short_songs -DWORD_SIZE=16 -DFRAME_CLK_HZ=16000
   python -m west flash -d build/tas2505_short

**Channel routing variants (short_songs, 16 kHz, 16-bit):**

.. code-block:: shell

   # Mono LEFT only (right channel silent)
   python -m west build -p always -b xg27_rb4194a zephyr-4.4.0/samples/drivers/i2s/tas2505 -d build/tas2505_short_16k_left -- -DBUILD_VERSION=4.4.0 -DAUDIO_SOURCE=short_songs -DWORD_SIZE=16 -DFRAME_CLK_HZ=16000 -DCHANNEL_MODE=mono_left
   python -m west flash -d build/tas2505_short_16k_left

   # Mono RIGHT only (left channel silent)
   python -m west build -p always -b xg27_rb4194a zephyr-4.4.0/samples/drivers/i2s/tas2505 -d build/tas2505_short_16k_right -- -DBUILD_VERSION=4.4.0 -DAUDIO_SOURCE=short_songs -DWORD_SIZE=16 -DFRAME_CLK_HZ=16000 -DCHANNEL_MODE=mono_right
   python -m west flash -d build/tas2505_short_16k_right

   # STEREO (duplicate mono to L+R, or native stereo with sine1khz)
   python -m west build -p always -b xg27_rb4194a zephyr-4.4.0/samples/drivers/i2s/tas2505 -d build/tas2505_short_16k_stereo -- -DBUILD_VERSION=4.4.0 -DAUDIO_SOURCE=short_songs -DWORD_SIZE=16 -DFRAME_CLK_HZ=16000 -DCHANNEL_MODE=stereo
   python -m west flash -d build/tas2505_short_16k_stereo

**Channel routing variants (short_songs, 8 kHz, 16-bit):**

.. code-block:: shell

   # Mono LEFT only
   python -m west build -p always -b xg27_rb4194a zephyr-4.4.0/samples/drivers/i2s/tas2505 -d build/tas2505_short_8k_left -- -DBUILD_VERSION=4.4.0 -DAUDIO_SOURCE=short_songs -DWORD_SIZE=16 -DFRAME_CLK_HZ=8000 -DCHANNEL_MODE=mono_left
   python -m west flash -d build/tas2505_short_8k_left

   # Mono RIGHT only
   python -m west build -p always -b xg27_rb4194a zephyr-4.4.0/samples/drivers/i2s/tas2505 -d build/tas2505_short_8k_right -- -DBUILD_VERSION=4.4.0 -DAUDIO_SOURCE=short_songs -DWORD_SIZE=16 -DFRAME_CLK_HZ=8000 -DCHANNEL_MODE=mono_right
   python -m west flash -d build/tas2505_short_8k_right

   # STEREO
   python -m west build -p always -b xg27_rb4194a zephyr-4.4.0/samples/drivers/i2s/tas2505 -d build/tas2505_short_8k_stereo -- -DBUILD_VERSION=4.4.0 -DAUDIO_SOURCE=short_songs -DWORD_SIZE=16 -DFRAME_CLK_HZ=8000 -DCHANNEL_MODE=stereo
   python -m west flash -d build/tas2505_short_8k_stereo

**Channel routing variants (short_songs, 44.1 kHz, 16-bit):**

.. code-block:: shell

   # Mono LEFT only
   python -m west build -p always -b xg27_rb4194a zephyr-4.4.0/samples/drivers/i2s/tas2505 -d build/tas2505_short_44k_left -- -DBUILD_VERSION=4.4.0 -DAUDIO_SOURCE=short_songs -DWORD_SIZE=16 -DFRAME_CLK_HZ=44100 -DCHANNEL_MODE=mono_left
   python -m west flash -d build/tas2505_short_44k_left

   # Mono RIGHT only
   python -m west build -p always -b xg27_rb4194a zephyr-4.4.0/samples/drivers/i2s/tas2505 -d build/tas2505_short_44k_right -- -DBUILD_VERSION=4.4.0 -DAUDIO_SOURCE=short_songs -DWORD_SIZE=16 -DFRAME_CLK_HZ=44100 -DCHANNEL_MODE=mono_right
   python -m west flash -d build/tas2505_short_44k_right

   # STEREO
   python -m west build -p always -b xg27_rb4194a zephyr-4.4.0/samples/drivers/i2s/tas2505 -d build/tas2505_short_44k_stereo -- -DBUILD_VERSION=4.4.0 -DAUDIO_SOURCE=short_songs -DWORD_SIZE=16 -DFRAME_CLK_HZ=44100 -DCHANNEL_MODE=stereo
   python -m west flash -d build/tas2505_short_44k_stereo

**Channel routing variants (short_songs, 48 kHz, 16-bit):**

.. code-block:: shell

   # Mono LEFT only
   python -m west build -p always -b xg27_rb4194a zephyr-4.4.0/samples/drivers/i2s/tas2505 -d build/tas2505_short_48k_left -- -DBUILD_VERSION=4.4.0 -DAUDIO_SOURCE=short_songs -DWORD_SIZE=16 -DFRAME_CLK_HZ=48000 -DCHANNEL_MODE=mono_left
   python -m west flash -d build/tas2505_short_48k_left

   # Mono RIGHT only
   python -m west build -p always -b xg27_rb4194a zephyr-4.4.0/samples/drivers/i2s/tas2505 -d build/tas2505_short_48k_right -- -DBUILD_VERSION=4.4.0 -DAUDIO_SOURCE=short_songs -DWORD_SIZE=16 -DFRAME_CLK_HZ=48000 -DCHANNEL_MODE=mono_right
   python -m west flash -d build/tas2505_short_48k_right

   # STEREO
   python -m west build -p always -b xg27_rb4194a zephyr-4.4.0/samples/drivers/i2s/tas2505 -d build/tas2505_short_48k_stereo -- -DBUILD_VERSION=4.4.0 -DAUDIO_SOURCE=short_songs -DWORD_SIZE=16 -DFRAME_CLK_HZ=48000 -DCHANNEL_MODE=stereo
   python -m west flash -d build/tas2505_short_48k_stereo

**Channel routing variants (short_songs, 16 kHz, 32-bit slots):**

.. code-block:: shell

   # Mono LEFT only
   python -m west build -p always -b xg27_rb4194a zephyr-4.4.0/samples/drivers/i2s/tas2505 -d build/tas2505_short_w32_left -- -DBUILD_VERSION=4.4.0 -DAUDIO_SOURCE=short_songs -DWORD_SIZE=32 -DFRAME_CLK_HZ=16000 -DCHANNEL_MODE=mono_left
   python -m west flash -d build/tas2505_short_w32_left

   # Mono RIGHT only
   python -m west build -p always -b xg27_rb4194a zephyr-4.4.0/samples/drivers/i2s/tas2505 -d build/tas2505_short_w32_right -- -DBUILD_VERSION=4.4.0 -DAUDIO_SOURCE=short_songs -DWORD_SIZE=32 -DFRAME_CLK_HZ=16000 -DCHANNEL_MODE=mono_right
   python -m west flash -d build/tas2505_short_w32_right

   # STEREO
   python -m west build -p always -b xg27_rb4194a zephyr-4.4.0/samples/drivers/i2s/tas2505 -d build/tas2505_short_w32_stereo -- -DBUILD_VERSION=4.4.0 -DAUDIO_SOURCE=short_songs -DWORD_SIZE=32 -DFRAME_CLK_HZ=16000 -DCHANNEL_MODE=stereo
   python -m west flash -d build/tas2505_short_w32_stereo

xG27-DK2602A (``xg27_dk2602a``), 16-bit build (default, mono):

.. code-block:: shell

   python -m west build -p always -b xg27_dk2602a zephyr-4.4.0/samples/drivers/i2s/tas2505 -d build/tas2505_w16 -- -DBUILD_VERSION=4.4.0 -DWORD_SIZE=16
   python -m west flash -d build/tas2505_w16

xG27-DK2602A, 32-bit build (optional, same mono content in 32-bit I2S slots):

.. code-block:: shell

   python -m west build -p always -b xg27_dk2602a zephyr-4.4.0/samples/drivers/i2s/tas2505 -d build/tas2505_w32 -- -DBUILD_VERSION=4.4.0 -DWORD_SIZE=32
   python -m west flash -d build/tas2505_w32

If HAL modules are not present yet, run ``west update hal_silabs cmsis cmsis_6`` (or a full ``west update``) once from the same workspace.

1 kHz sine wave acceptance test (SRS)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Use ``AUDIO_SOURCE=sine1khz`` to play the pure 1 kHz reference tone that
the SRS calls for in section 2.b ("Output 1 kHz sine wave audio data to
amplifier and get a clean audio output").

The tone is held in four pre-quantized files under ``src/audio_sine/``,
one per SRS-supported sample rate.  Each file ships **four parallel
arrays** of the same 1 kHz waveform, covering every combination of
``WORD_SIZE`` (SRS 1.f) and ``CHANNEL_MODE`` (SRS 1.g):

* ``sine1khz_16bit_mono_pcm_<rate>[]`` -- ``int16_t``, SRS 1.f.i + 1.g.i (**mandatory**)
* ``sine1khz_32bit_mono_pcm_<rate>[]`` -- ``int32_t``, SRS 1.f.ii + 1.g.i (optional)
* ``sine1khz_16bit_stereo_pcm_<rate>[]`` -- ``int16_t``, SRS 1.f.i + 1.g.ii (optional)
* ``sine1khz_32bit_stereo_pcm_<rate>[]`` -- ``int32_t``, SRS 1.f.ii + 1.g.ii (optional)

Both arrays are MONO (mandatory), stored as readable signed
integers (not raw bytes).  ``audio_sine.c`` picks which array to read
based on ``-DWORD_SIZE`` and the linker drops the other via
``--gc-sections``, so per-build flash cost is one array, not two.
CMake selects exactly **one** ``sine_<rate>.c`` based on
``-DFRAME_CLK_HZ`` so flash usage stays small:

.. list-table::
   :header-rows: 1
   :widths: 12 14 14 18 18

   * - ``FRAME_CLK_HZ``
     - Clip file
     - Frames (100 cycles)
     - Flash (16-bit, mono / stereo)
     - Flash (32-bit, mono / stereo)
   * - 8000
     - ``sine_8k.c``
     - 800
     - 1.6 / 3.2 KB
     - 3.2 / 6.4 KB
   * - 16000 (default)
     - ``sine_16k.c``
     - 1600
     - 3.2 / 6.4 KB
     - 6.4 / 12.8 KB
   * - 44100
     - ``sine_44k.c``
     - 4410
     - 8.8 / 17.6 KB
     - 17.6 / 35.3 KB
   * - 48000
     - ``sine_48k.c``
     - 4800
     - 9.6 / 19.2 KB
     - 19.2 / 38.4 KB

``WORD_SIZE=16`` reads the ``int16_t`` array directly; ``WORD_SIZE=32``
reads the ``int32_t`` array (so the 32-bit data file is
actually exercised and lands in the link map), with main.c handling
I2S slot expansion via ``SAMPLE_EXPAND``.

The mono routing modes (``mono_left``, ``mono_right``) read from the mono
array via ``fill_block_mono()``; ``stereo`` uses ``fill_block_stereo()``
(duplicate L=R for mono backends, or native interleaved clips for
``sine1khz``).

Level: each clip is generated at exactly -6 dBFS (peak = 16419 for the
``int16_t`` array, peak = 1 076 028 544 for the ``int32_t`` array).  The
generator uses ``ffmpeg lavfi sine`` plus a ``volume`` filter sized to
compensate for lavfi's -18 dBFS default, so the dBFS label on the file
matches reality (verifiable with ``python3 -c 'import struct...'`` on
the array).

``PLAYBACK_MODE=loopback`` is the recommended pairing for the bench
acceptance run: the 100-cycle clip wraps forever with no boundary glitch
so scope / FFT capture has unlimited capture time.

Regenerate the clips (optional -- only if you want a different
duration / level; the files are already in tree):

.. code-block:: shell

   # Regenerate all four rates at the default -6 dBFS, 100 cycles
   python3 src/tools/gen_sine_pcm.py

   # Just one rate
   python3 src/tools/gen_sine_pcm.py --fs 44100

   # Quieter (-12 dBFS) for small speakers
   python3 src/tools/gen_sine_pcm.py --level -12

   # Longer clip (still loop-clean -- 200 cycles ≈ 200 ms)
   python3 src/tools/gen_sine_pcm.py --cycles 200

**Build recipes (one per supported Fs, xG27-DK2602A, 16-bit, mono_left, looped, TAS2505 board):**

.. code-block:: shell

   # 16 kHz (mandatory per SRS 1.e.ii)
   python -m west build -p always -b xg27_dk2602a zephyr-4.4.0/samples/drivers/i2s/tas2505 -d build/tas2505_sine1k_16k -- -DBUILD_VERSION=4.4.0 -DAUDIO_SOURCE=sine1khz -DWORD_SIZE=16 -DFRAME_CLK_HZ=16000 -DCHANNEL_MODE=mono_left -DPLAYBACK_MODE=loopback -DTAS2505_BOARD=1
   python -m west flash -d build/tas2505_sine1k_16k

   # 8 kHz (optional per SRS 1.e.i)
   python -m west build -p always -b xg27_dk2602a zephyr-4.4.0/samples/drivers/i2s/tas2505 -d build/tas2505_sine1k_8k -- -DBUILD_VERSION=4.4.0 -DAUDIO_SOURCE=sine1khz -DWORD_SIZE=16 -DFRAME_CLK_HZ=8000 -DCHANNEL_MODE=mono_left -DPLAYBACK_MODE=loopback -DTAS2505_BOARD=1
   python -m west flash -d build/tas2505_sine1k_8k

   # 44.1 kHz (optional per SRS 1.e.iii)
   python -m west build -p always -b xg27_dk2602a zephyr-4.4.0/samples/drivers/i2s/tas2505 -d build/tas2505_sine1k_44k -- -DBUILD_VERSION=4.4.0 -DAUDIO_SOURCE=sine1khz -DWORD_SIZE=16 -DFRAME_CLK_HZ=44100 -DCHANNEL_MODE=mono_left -DPLAYBACK_MODE=loopback -DTAS2505_BOARD=1
   python -m west flash -d build/tas2505_sine1k_44k

   # 48 kHz (optional per SRS 1.e.iv)
   python -m west build -p always -b xg27_dk2602a zephyr-4.4.0/samples/drivers/i2s/tas2505 -d build/tas2505_sine1k_48k -- -DBUILD_VERSION=4.4.0 -DAUDIO_SOURCE=sine1khz -DWORD_SIZE=16 -DFRAME_CLK_HZ=48000 -DCHANNEL_MODE=mono_left -DPLAYBACK_MODE=loopback -DTAS2505_BOARD=1
   python -m west flash -d build/tas2505_sine1k_48k

**16-bit slot variant (SRS 1.f.i mandatory), mono_right, looped, TAS2505 board**

.. code-block:: shell

   python -m west build -p always -b xg27_dk2602a zephyr-4.4.0/samples/drivers/i2s/tas2505 -d build/tas2505_sine1k_16k_right -- -DBUILD_VERSION=4.4.0 -DAUDIO_SOURCE=sine1khz -DWORD_SIZE=16 -DFRAME_CLK_HZ=16000 -DCHANNEL_MODE=mono_right -DPLAYBACK_MODE=loopback -DTAS2505_BOARD=1
   python -m west flash -d build/tas2505_sine1k_16k_right

   python -m west build -p always -b xg27_dk2602a zephyr-4.4.0/samples/drivers/i2s/tas2505 -d build/tas2505_sine1k_8k_right -- -DBUILD_VERSION=4.4.0 -DAUDIO_SOURCE=sine1khz -DWORD_SIZE=16 -DFRAME_CLK_HZ=8000 -DCHANNEL_MODE=mono_right -DPLAYBACK_MODE=loopback -DTAS2505_BOARD=1
   python -m west flash -d build/tas2505_sine1k_8k_right

   python -m west build -p always -b xg27_dk2602a zephyr-4.4.0/samples/drivers/i2s/tas2505 -d build/tas2505_sine1k_44k_right -- -DBUILD_VERSION=4.4.0 -DAUDIO_SOURCE=sine1khz -DWORD_SIZE=16 -DFRAME_CLK_HZ=44100 -DCHANNEL_MODE=mono_right -DPLAYBACK_MODE=loopback -DTAS2505_BOARD=1
   python -m west flash -d build/tas2505_sine1k_44k_right

   python -m west build -p always -b xg27_dk2602a zephyr-4.4.0/samples/drivers/i2s/tas2505 -d build/tas2505_sine1k_48k_right -- -DBUILD_VERSION=4.4.0 -DAUDIO_SOURCE=sine1khz -DWORD_SIZE=16 -DFRAME_CLK_HZ=48000 -DCHANNEL_MODE=mono_right -DPLAYBACK_MODE=loopback -DTAS2505_BOARD=1
   python -m west flash -d build/tas2505_sine1k_48k_right

**16-bit slot variant (SRS 1.f.i mandatory), stereo, looped, TAS2505 board**

.. code-block:: shell

   python -m west build -p always -b xg27_dk2602a zephyr-4.4.0/samples/drivers/i2s/tas2505 -d build/tas2505_sine1k_16k_stereo -- -DBUILD_VERSION=4.4.0 -DAUDIO_SOURCE=sine1khz -DWORD_SIZE=16 -DFRAME_CLK_HZ=16000 -DCHANNEL_MODE=stereo -DPLAYBACK_MODE=loopback -DTAS2505_BOARD=1
   python -m west flash -d build/tas2505_sine1k_16k_stereo

   python -m west build -p always -b xg27_dk2602a zephyr-4.4.0/samples/drivers/i2s/tas2505 -d build/tas2505_sine1k_8k_stereo -- -DBUILD_VERSION=4.4.0 -DAUDIO_SOURCE=sine1khz -DWORD_SIZE=16 -DFRAME_CLK_HZ=8000 -DCHANNEL_MODE=stereo -DPLAYBACK_MODE=loopback -DTAS2505_BOARD=1
   python -m west flash -d build/tas2505_sine1k_8k_stereo

   python -m west build -p always -b xg27_dk2602a zephyr-4.4.0/samples/drivers/i2s/tas2505 -d build/tas2505_sine1k_44k_stereo -- -DBUILD_VERSION=4.4.0 -DAUDIO_SOURCE=sine1khz -DWORD_SIZE=16 -DFRAME_CLK_HZ=44100 -DCHANNEL_MODE=stereo -DPLAYBACK_MODE=loopback -DTAS2505_BOARD=1
   python -m west flash -d build/tas2505_sine1k_44k_stereo

   python -m west build -p always -b xg27_dk2602a zephyr-4.4.0/samples/drivers/i2s/tas2505 -d build/tas2505_sine1k_48k_stereo -- -DBUILD_VERSION=4.4.0 -DAUDIO_SOURCE=sine1khz -DWORD_SIZE=16 -DFRAME_CLK_HZ=48000 -DCHANNEL_MODE=stereo -DPLAYBACK_MODE=loopback -DTAS2505_BOARD=1
   python -m west flash -d build/tas2505_sine1k_48k_stereo

**32-bit slot variant (SRS 1.f.ii optional), mono_left, looped, TAS2505 board**

.. code-block:: shell

   python -m west build -p always -b xg27_dk2602a zephyr-4.4.0/samples/drivers/i2s/tas2505 -d build/tas2505_sine1k_16k_w32 -- -DBUILD_VERSION=4.4.0 -DAUDIO_SOURCE=sine1khz -DWORD_SIZE=32 -DFRAME_CLK_HZ=16000 -DCHANNEL_MODE=mono_left -DPLAYBACK_MODE=loopback -DTAS2505_BOARD=1
   python -m west flash -d build/tas2505_sine1k_16k_w32

   python -m west build -p always -b xg27_dk2602a zephyr-4.4.0/samples/drivers/i2s/tas2505 -d build/tas2505_sine1k_8k_w32 -- -DBUILD_VERSION=4.4.0 -DAUDIO_SOURCE=sine1khz -DWORD_SIZE=32 -DFRAME_CLK_HZ=8000 -DCHANNEL_MODE=mono_left -DPLAYBACK_MODE=loopback -DTAS2505_BOARD=1
   python -m west flash -d build/tas2505_sine1k_8k_w32

   python -m west build -p always -b xg27_dk2602a zephyr-4.4.0/samples/drivers/i2s/tas2505 -d build/tas2505_sine1k_44k_w32 -- -DBUILD_VERSION=4.4.0 -DAUDIO_SOURCE=sine1khz -DWORD_SIZE=32 -DFRAME_CLK_HZ=44100 -DCHANNEL_MODE=mono_left -DPLAYBACK_MODE=loopback -DTAS2505_BOARD=1
   python -m west flash -d build/tas2505_sine1k_44k_w32

   python -m west build -p always -b xg27_dk2602a zephyr-4.4.0/samples/drivers/i2s/tas2505 -d build/tas2505_sine1k_48k_w32 -- -DBUILD_VERSION=4.4.0 -DAUDIO_SOURCE=sine1khz -DWORD_SIZE=32 -DFRAME_CLK_HZ=48000 -DCHANNEL_MODE=mono_left -DPLAYBACK_MODE=loopback -DTAS2505_BOARD=1
   python -m west flash -d build/tas2505_sine1k_48k_w32

**32-bit slot variant (SRS 1.f.ii optional), mono_right, looped, TAS2505 board**

.. code-block:: shell

   python -m west build -p always -b xg27_dk2602a zephyr-4.4.0/samples/drivers/i2s/tas2505 -d build/tas2505_sine1k_16k_w32_right -- -DBUILD_VERSION=4.4.0 -DAUDIO_SOURCE=sine1khz -DWORD_SIZE=32 -DFRAME_CLK_HZ=16000 -DCHANNEL_MODE=mono_right -DPLAYBACK_MODE=loopback -DTAS2505_BOARD=1
   python -m west flash -d build/tas2505_sine1k_16k_w32_right

   python -m west build -p always -b xg27_dk2602a zephyr-4.4.0/samples/drivers/i2s/tas2505 -d build/tas2505_sine1k_8k_w32_right -- -DBUILD_VERSION=4.4.0 -DAUDIO_SOURCE=sine1khz -DWORD_SIZE=32 -DFRAME_CLK_HZ=8000 -DCHANNEL_MODE=mono_right -DPLAYBACK_MODE=loopback -DTAS2505_BOARD=1
   python -m west flash -d build/tas2505_sine1k_8k_w32_right

   python -m west build -p always -b xg27_dk2602a zephyr-4.4.0/samples/drivers/i2s/tas2505 -d build/tas2505_sine1k_44k_w32_right -- -DBUILD_VERSION=4.4.0 -DAUDIO_SOURCE=sine1khz -DWORD_SIZE=32 -DFRAME_CLK_HZ=44100 -DCHANNEL_MODE=mono_right -DPLAYBACK_MODE=loopback -DTAS2505_BOARD=1
   python -m west flash -d build/tas2505_sine1k_44k_w32_right

   python -m west build -p always -b xg27_dk2602a zephyr-4.4.0/samples/drivers/i2s/tas2505 -d build/tas2505_sine1k_48k_w32_right -- -DBUILD_VERSION=4.4.0 -DAUDIO_SOURCE=sine1khz -DWORD_SIZE=32 -DFRAME_CLK_HZ=48000 -DCHANNEL_MODE=mono_right -DPLAYBACK_MODE=loopback -DTAS2505_BOARD=1
   python -m west flash -d build/tas2505_sine1k_48k_w32_right

**32-bit slot variant (SRS 1.f.ii optional), stereo, looped, TAS2505 board**

.. code-block:: shell

   python -m west build -p always -b xg27_dk2602a zephyr-4.4.0/samples/drivers/i2s/tas2505 -d build/tas2505_sine1k_16k_w32_stereo -- -DBUILD_VERSION=4.4.0 -DAUDIO_SOURCE=sine1khz -DWORD_SIZE=32 -DFRAME_CLK_HZ=16000 -DCHANNEL_MODE=stereo -DPLAYBACK_MODE=loopback -DTAS2505_BOARD=1
   python -m west flash -d build/tas2505_sine1k_16k_w32_stereo

   python -m west build -p always -b xg27_dk2602a zephyr-4.4.0/samples/drivers/i2s/tas2505 -d build/tas2505_sine1k_8k_w32_stereo -- -DBUILD_VERSION=4.4.0 -DAUDIO_SOURCE=sine1khz -DWORD_SIZE=32 -DFRAME_CLK_HZ=8000 -DCHANNEL_MODE=stereo -DPLAYBACK_MODE=loopback -DTAS2505_BOARD=1
   python -m west flash -d build/tas2505_sine1k_8k_w32_stereo

   python -m west build -p always -b xg27_dk2602a zephyr-4.4.0/samples/drivers/i2s/tas2505 -d build/tas2505_sine1k_44k_w32_stereo -- -DBUILD_VERSION=4.4.0 -DAUDIO_SOURCE=sine1khz -DWORD_SIZE=32 -DFRAME_CLK_HZ=44100 -DCHANNEL_MODE=stereo -DPLAYBACK_MODE=loopback -DTAS2505_BOARD=1
   python -m west flash -d build/tas2505_sine1k_44k_w32_stereo

   python -m west build -p always -b xg27_dk2602a zephyr-4.4.0/samples/drivers/i2s/tas2505 -d build/tas2505_sine1k_48k_w32_stereo -- -DBUILD_VERSION=4.4.0 -DAUDIO_SOURCE=sine1khz -DWORD_SIZE=32 -DFRAME_CLK_HZ=48000 -DCHANNEL_MODE=stereo -DPLAYBACK_MODE=loopback -DTAS2505_BOARD=1
   python -m west flash -d build/tas2505_sine1k_48k_w32_stereo

Boot-time UART log confirms which array got linked:

.. code-block:: text

   audio=sine1khz@16k/s16/stereo     # 16-bit stereo at 16 kHz
   audio=sine1khz@48k/s32/stereo     # 32-bit stereo at 48 kHz
   audio=sine1khz@16k/s16/mono       # 16-bit mono at 16 kHz (mandatory)

**Mono routing variants (single-channel test), 16 kHz**

Bench / scope builds can omit codec init with ``-DTAS2505_BOARD=0``.

.. code-block:: shell

   # Tone on LEFT slot only, RIGHT silent (channels=1, DMASPLIT, block=512)
   python -m west build -p always -b xg27_rb4194a zephyr-4.4.0/samples/drivers/i2s/tas2505 -d build/tas2505_rb_sine1k_mono_left_nocodec -- -DBUILD_VERSION=4.4.0 -DAUDIO_SOURCE=sine1khz -DWORD_SIZE=16 -DFRAME_CLK_HZ=16000 -DCHANNEL_MODE=mono_left -DPLAYBACK_MODE=loopback -DTAS2505_BOARD=0
   python -m west flash -d build/tas2505_rb_sine1k_mono_left_nocodec

   # Tone on RIGHT slot only, LEFT silent (channels=1, DMASPLIT, block=512)
   python -m west build -p always -b xg27_rb4194a zephyr-4.4.0/samples/drivers/i2s/tas2505 -d build/tas2505_rb_sine1k_mono_right_nocodec -- -DBUILD_VERSION=4.4.0 -DAUDIO_SOURCE=sine1khz -DWORD_SIZE=16 -DFRAME_CLK_HZ=16000 -DCHANNEL_MODE=mono_right -DPLAYBACK_MODE=loopback -DTAS2505_BOARD=0
   python -m west flash -d build/tas2505_rb_sine1k_mono_right_nocodec

   # Tone on BOTH slots (channels=2, block=1024)
   python -m west build -p always -b xg27_rb4194a zephyr-4.4.0/samples/drivers/i2s/tas2505 -d build/tas2505_rb_sine1k_stereo_nocodec -- -DBUILD_VERSION=4.4.0 -DAUDIO_SOURCE=sine1khz -DWORD_SIZE=16 -DFRAME_CLK_HZ=16000 -DCHANNEL_MODE=stereo -DPLAYBACK_MODE=loopback -DTAS2505_BOARD=0
   python -m west flash -d build/tas2505_rb_sine1k_stereo_nocodec

DK2602A equivalents (with codec init, ``-DTAS2505_BOARD=1`` if wired):

.. code-block:: shell

   # Tone on LEFT slot only, RIGHT silent
   python -m west build -p always -b xg27_dk2602a zephyr-4.4.0/samples/drivers/i2s/tas2505 -d build/tas2505_sine1k_left -- -DBUILD_VERSION=4.4.0 -DAUDIO_SOURCE=sine1khz -DWORD_SIZE=16 -DFRAME_CLK_HZ=16000 -DCHANNEL_MODE=mono_left -DPLAYBACK_MODE=loopback
   python -m west flash -d build/tas2505_sine1k_left

   # Tone on RIGHT slot only, LEFT silent
   python -m west build -p always -b xg27_dk2602a zephyr-4.4.0/samples/drivers/i2s/tas2505 -d build/tas2505_sine1k_right -- -DBUILD_VERSION=4.4.0 -DAUDIO_SOURCE=sine1khz -DWORD_SIZE=16 -DFRAME_CLK_HZ=16000 -DCHANNEL_MODE=mono_right -DPLAYBACK_MODE=loopback
   python -m west flash -d build/tas2505_sine1k_right

**One-shot variant** (plays the clip once, then ``i2s_configure(off)``
gates BCLK/LRCLK -- useful for the SRS 2.c "clocks stop at end of
stream" check):

.. code-block:: shell

   python -m west build -p always -b xg27_rb4194a zephyr-4.4.0/samples/drivers/i2s/tas2505 -d build/tas2505_sine1k_once -- -DBUILD_VERSION=4.4.0 -DAUDIO_SOURCE=sine1khz -DWORD_SIZE=16 -DFRAME_CLK_HZ=16000 -DCHANNEL_MODE=stereo
   python -m west flash -d build/tas2505_sine1k_once

**What to expect on the bench (for any of the above):**

* Loudspeaker: a steady 1 kHz tone, no audible chirp / aliasing / clicks.
* BCLK ≈ ``Fs × channels × word_size``. For 16 k / 2 / 16 → **512 kHz**;
  for 48 k / 2 / 32 → **3.072 MHz** etc.
* LRCLK / WCLK ≈ ``FRAME_CLK_HZ``, 50 % duty.
* MCLK ≈ 19.2 MHz on PB0 / EXP7 (RB4194A and DK2602A) when
  ``silabs_cmu_clkout`` is enabled by the board overlay (matches SRS 1.d).
* In ``loopback`` mode the boot log keeps streaming blocks forever; in
  ``one_shot`` mode it logs ``I2S stopped; BCLK/LRCLK gated`` once the
  clip drains.

Loopback example (replay forever, clocks never stop)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Add ``-DPLAYBACK_MODE=loopback`` to any of the recipes above. Example:

.. code-block:: shell

   python -m west build -p always -b xg27_rb4194a zephyr-4.4.0/samples/drivers/i2s/tas2505 -d build/tas2505_short_16k_stereo_loop -- -DBUILD_VERSION=4.4.0 -DAUDIO_SOURCE=short_songs -DWORD_SIZE=16 -DFRAME_CLK_HZ=16000 -DCHANNEL_MODE=stereo -DPLAYBACK_MODE=loopback
   python -m west flash -d build/tas2505_short_16k_stereo_loop

   # PCM clip looping
   python -m west build -p always -b xg27_rb4194a zephyr-4.4.0/samples/drivers/i2s/tas2505 -d build/tas2505_pcm_16k_stereo_loop -- -DBUILD_VERSION=4.4.0 -DAUDIO_SOURCE=pcm -DWORD_SIZE=16 -DFRAME_CLK_HZ=16000 -DCHANNEL_MODE=stereo -DPLAYBACK_MODE=loopback
   python -m west flash -d build/tas2505_pcm_16k_stereo_loop

In ``loopback`` mode the audio source wraps to the start automatically and
``main.c`` never tears down the I2S engine: BCLK/LRCLK keep toggling and the
"draining" / "I2S stopped" log lines are not printed.

Serial console: 115200 8N1 on the board USB (USART1). On startup the sample
logs the resolved audio source, ``CHANNEL_MODE``, ``i2s_ch``,
``PLAYBACK_MODE``, ``FRAME_CLK_HZ``, ``WORD_SIZE`` and block size, e.g.::

   sample start board=xg27_rb4194a audio=sine1khz@16k/s16/mono channels=mono_right i2s_ch=1 playback=loopback FRAME_CLK_HZ=16000 WORD_SIZE=16 block=512

   sample start board=xg27_rb4194a audio=short_songs channels=stereo i2s_ch=2 playback=one_shot FRAME_CLK_HZ=16000 WORD_SIZE=16 block=1024

Runtime
-------

Default (``PLAYBACK_MODE=one_shot``) behaviour:

* The audio source (``song_pcm`` or ``short_songs``) is pulled exactly once.
* When the source signals "done", the sample queues a few silent tail blocks
  so the in-flight DMA queue can drain cleanly without a click.
* It then triggers ``I2S_TRIGGER_DRAIN`` and waits long enough for all
  queued frames to clock out at ``FRAME_CLK_HZ``.
* Finally, the sample calls ``i2s_configure(dev, I2S_DIR_TX, &(struct
  i2s_config){0})``. The EFR32 USART-I2S driver treats ``frame_clk_freq == 0``
  (or a NULL config) as a stop request: it drops any remaining DMA buffers
  and calls ``USART_Enable(usartDisable)``, which gates **BCLK** and
  **LRCLK** on the pins. Probing those lines after the "I2S stopped"
  message should show them idle.

The application then blocks in ``k_sleep(K_FOREVER)``.

With ``PLAYBACK_MODE=loopback`` none of the drain / gate steps run: the audio
source wraps to the start, ``main.c`` keeps writing blocks in a tight ``while
(1)`` loop, and BCLK/LRCLK stay active forever.

Serial log example (one_shot)::

   sample start board=xg27_rb4194a audio=short_songs channels=stereo i2s_ch=2 playback=one_shot FRAME_CLK_HZ=16000 WORD_SIZE=16 block=1024
   i2s_configure ok
   pre-roll queued: 4 silent blocks
   I2S START @ 16000 Hz
   ... (music) ...
   audio source reports done; queuing 4 silent tail blocks
   draining (~292 ms)...
   I2S stopped; BCLK/LRCLK gated. Probe pins to confirm: DIN/BCLK/LRCLK should be idle.
