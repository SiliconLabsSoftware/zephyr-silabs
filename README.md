[![Silabs upstream daily build][badge]][recipe]

[badge]:  https://github.com/SiliconLabsSoftware/zephyr-silabs/actions/workflows/upstream-build.yml/badge.svg
[recipe]: https://github.com/SiliconLabsSoftware/zephyr-silabs/actions/workflows/upstream-build.yml

# Simplicity SDK for Zephyr

This repository contains the Simplicity SDK for Zephyr, which is Silicon Labs'
primary downstream enablement for Zephyr.

Silicon Labs is a [Platinum Member][project-members] of the Zephyr Project, and
is committed to providing upstream support for [Silicon Labs hardware][boards].
In addition to upstream support, Silicon Labs provides this downstream
[manifest repository][west-manifest] to provide access to features that are not
yet available upstream, such as new hardware support, as well as features that
cannot be upstreamed, such as content that does not have an open source license
compatible with the upstream. The downstream repository also enables additional
quality assurance of releases for Silicon Labs platforms.

Silicon Labs is committed to an upstream-first development methodology. We
strive to keep the number of patches applied in Simplicity SDK for Zephyr
down by basing the downstream release on upstream stable releases.

[project-members]: https://zephyrproject.org/project-members/
[boards]: https://docs.zephyrproject.org/latest/boards/silabs/index.html
[west]: https://docs.zephyrproject.org/latest/develop/west/index.html
[west-manifest]: https://docs.zephyrproject.org/latest/develop/west/manifest.html

## Structure

This repository is the top-level [manifest repository][west-manifest] for the
Simplicity SDK for Zephyr. The SDK uses the [West][west] tool to check out
and organize the different repositories that are part of it. The
[manifest file](./west.yml) tells West which repositories to check out at
which revision. Important repos include:

* [zephyr-silabs][repo-zephyr-silabs] - The manifest repository for Silicon
  Labs SDK for Zephyr. Functions as the entry point for the SDK, and points to
  a mix of upstream repositories, downstream forks and additional downstream
  repositories. Filters out HAL repositories not related to Silicon Labs targets
  to optimize the download size and disk usage of the SDK.
* [zephyr][repo-zephyr] - Silicon Labs fork of the Zephyr repository. Kept in
  sync with the upstream for every release. May add additional patches that are
  not yet available upstream.
* [hal_silabs][repo-hal-silabs] - Silicon Labs fork of the Silicon Labs HAL for
  Zephyr. Includes the parts of Simplicity SDK and WiSeConnect used by Zephyr.

[repo-zephyr-silabs]: https://github.com/SiliconLabsSoftware/zephyr-silabs
[repo-zephyr]: https://github.com/SiliconLabsSoftware/zephyr
[repo-hal-silabs]: https://github.com/SiliconLabsSoftware/hal_silabs

The workspace directory structure looks like this, with additional modules
as specified by the manifest:

```
workspace/
├── modules/
│   ├── crypto/
│   │   └── mbedtls/    # Silicon Labs fork with hardware acceleration
│   └── hal/
│       ├── cmsis_6/    # Upstream CMSIS 6 repository
│       └── silabs/     # Silicon Labs HAL
├── zephyr/             # Silicon Labs downstream fork of Zephyr
└── zephyr-silabs/      # Simplicity SDK for Zephyr manifest repository
```

## Getting Started

To get started with Simplicity SDK for Zephyr, follow the
[Getting Started Guide from the Zephyr Project][zephyr-getting-started].
Instead of doing `west init` to initialize a workspace based on the upstream
manifest, use the following commands, where `silabs_zephyr` is an example name
for your workspace directory:

```
west init -m https://github.com/SiliconLabsSoftware/zephyr-silabs silabs_zephyr
cd silabs_zephyr
west update
west blobs fetch
```

It is also possible to clone the repository manually, and use `west init -l` to
perform initialization from local sources.

The Getting Started Guide covers setting up the build environment, as well as
building and flashing an example.

To use Zephyr with Silicon Labs devices, certain pre-built libraries are
required for the radio. The `west blobs fetch` command downloads these
libraries.

[zephyr-getting-started]: https://docs.zephyrproject.org/latest/develop/getting_started/index.html

### Linux

For Linux users, see also the more detailed
[Getting Started on Linux](./doc/getting-started-linux.md) guide.
