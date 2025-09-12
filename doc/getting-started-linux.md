# Getting Started with Silicon Labs SDK for Zephyr on Linux

The steps below applies on common Linux hosts. Please refer to the [full
documentation][main-doc] for detailed steps.

First, install packages required for Zephyr development, as described in the
[Zephyr documentation][sysdeps]:

    sudo apt install --no-install-recommends git cmake ninja-build gperf \
      ccache dfu-util device-tree-compiler wget python3-dev python3-pip  \
      python3-setuptools python3-tk python3-wheel xz-utils file make gcc \
      gcc-multilib g++-multilib libsdl2-dev libmagic1

Also [install `west` command][west]. Since no package is provided for `west`, it
can be done through `pip`:

    pip install west

Retrieve this repository using `west init`:

    mkdir workspace
    cd workspace
    west init -m git@github.com:siliconlabssoftware/zephyr-silabs

Retrieve modules:

    west update

You can now [install extra Python packages][pydeps] required by Zephyr:

     pip install -r zephyr/scripts/requirements.txt

Retrieve the blobs:

    west blobs fetch

Install [a toolchain][toolchain]. [Zephyr SDK][sdk] is recommended:

    west sdk install

Then, [Simplicity Commander][commander] is required to flash some targets (eg.
SiWG917 can only be flashed using Simplicity Commander):

    ARCH=x86_64 # Also consider "aarch32" or "aarch64"
    wget https://www.silabs.com/documents/login/software/SimplicityCommander-Linux.zip
    unzip SimplicityCommander-Linux.zip
    sudo mkdir -p /opt/commander
    sudo chown $(id -un):$(id -gn) /opt/commander
    tar -C /opt -xvf SimplicityCommander-Linux/Commander_linux_${ARCH}_*.tar.bz
    sudo ln -sfn /opt/commander/commander /usr/local/bin/

In order to debug the target, you will need [J-Link software pack][jlink]:

    ARCH=x86_64 # Also consider "arm" or "arm64"
    wget --post-data accept_license_agreement=accepted https://www.segger.com/downloads/jlink/JLink_Linux_$ARCH.deb
    sudo dpkg -i JLink_Linux_$ARCH.deb

Your environment is now installed. You can run all the Zephyr commands, ie.
build an application:

    west build -b siwx917_rb4338a zephyr/samples/hello_world

... then flash it:

    west flash

... and debug it:

    west attach

[main-doc]:  https://docs.zephyrproject.org/latest/develop/getting_started/index.html
[sysdeps]:   https://docs.zephyrproject.org/latest/develop/getting_started/index.html#install-dependencies
[west]:      https://docs.zephyrproject.org/latest/develop/west/install.html
[pydeps]:    https://docs.zephyrproject.org/latest/develop/getting_started/index.html#get-zephyr-and-install-python-dependencies
[toolchain]: https://docs.zephyrproject.org/latest/develop/toolchains/index.html
[sdk]:       https://docs.zephyrproject.org/latest/develop/toolchains/zephyr_sdk.html
[commander]: https://www.silabs.com/developers/simplicity-studio/simplicity-commander?tab=downloads
[jlink]:     https://www.segger.com/jlink-software.html

## Troubleshooting

### `pip` says "This environment is externally managed".

On recent version of Debian (>= bookworm) and derivative, you need to use `pipx`
(or use Python venv) instead of `pip`:

    pipx install west
    pipx runpip west install crc
    pipx runpip west install -r zephyr/scripts/requirements.txt


### I am not able to install JLink and Simplicity Commander on Raspberry Pi

You probably need to retrieve the binary that match with your architecture. Here
is a table to identify your system:

  | `uname -m` | `dpkg --print-architecture` | JLink    | Commander |
  |------------|-----------------------------|----------|-----------|
  | `x86_64`   | `amd64`                     | `x86_64` | `x86_64`  |
  | `aarch64`  | `arm64`                     | `arm64`  | `aarch64` |
  | `arm`      | `armhf`                     | `arm`    | `aarch32` |


### I am not able to debug my target

J-Link software package may not support the Silicon Labs parts. Commander is
generally up to date. You can try to copy Commander J-Link customisation files
to J-Link software pack:

    sudo cp -fr /opt/commander/resources/jlink/* /opt/SEGGER/JLink_V*/
