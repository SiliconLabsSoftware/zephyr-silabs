[![Silabs upstream daily build][badge]][recipe]

[badge]:  https://github.com/SiliconLabsSoftware/zephyr-silabs/actions/workflows/upstream-build.yml/badge.svg
[recipe]: https://github.com/SiliconLabsSoftware/zephyr-silabs/actions/workflows/upstream-build.yml

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

    west sdk install

[Install J-Link software pack][3]:

    curl --data-raw accept_license_agreement=accepted https://www.segger.com/downloads/jlink/JLink_Linux_$(uname -m).deb -o JLink_Linux_$(uname -m).deb
    sudo dpkg -i JLink_Linux_$(uname -m).deb

[Install Simplicity Commander][4]:

    cd /tmp
    wget https://www.silabs.com/documents/login/software/SimplicityCommander-Linux.zip
    unzip SimplicityCommander-Linux.zip
    sudo tar -C /opt -xvf /tmp/SimplicityCommander-Linux/Commander_linux_$(uname -m)_*.tar.bz
    sudo ln -sfn /opt/commander/commander /usr/local/bin/

Build an application:

    west build -b siwx917_rb4338a zephyr/samples/hello_world


[1]: https://docs.zephyrproject.org/latest/develop/west/install.html
[2]: https://docs.zephyrproject.org/latest/develop/toolchains/index.html
[3]: https://www.segger.com/jlink-software.html
[4]: https://www.silabs.com/developers/simplicity-studio/simplicity-commander?tab=downloads
