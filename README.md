Silicon Labs Zephyr repository
==============================

This repository include support for device not yet included in the Zephyr RTOS
project.

Usage
-----

[Install `west` command][1]. Usually, it is done through `pip` (or `pipx`):

    pip install west

Retrieve this repository:

    mkdir workspace
    cd workspace
    west init -m git@github.com:siliconlabssoftware/zephyr-silabs

Retrieve modules:

    west update

Install a toolchain. Toolchain installation [is described in Zephyr
documentation[2].

TL;DR:

    wget https://github.com/zephyrproject-rtos/sdk-ng/releases/download/v0.16.8/zephyr-sdk-0.16.8_linux-x86_64.tar.xz
    wget -O - https://github.com/zephyrproject-rtos/sdk-ng/releases/download/v0.16.8/sha256.sum | shasum --check --ignore-missing
    tar -xvf zephyr-sdk-0.16.8_linux-x86_64.tar.xz
    cd zephyr-sdk-0.16.8
    ./setup.sh

Build an application:

    west build -b siwx917_rb4338a zephyr/samples/hello_world


[1]: https://docs.zephyrproject.org/latest/develop/west/install.html
[2]: https://docs.zephyrproject.org/latest/develop/toolchains/index.html
