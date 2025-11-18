# PSA Crypto test

This test functions as a smoke test for PSA Crypto APIs, demonstrating that single and multipart
operations work as expected using both transparent drivers and opaque drivers on devices that
support them.

## Device Configuration

### Series 2

No special configuration is required.

### SiWx91x

In order for opaque APIs to work, the device needs to be provisioned to enable security features.
At a minimum, images must have a MIC, but can also be encrypted and signed.

#### Provisioning

See [UG574](https://www.silabs.com/documents/public/user-guides/ug574-siwx917-soc-manufacturing-utility-user-guide.pdf)
for details.

```
commander manufacturing init --mbr default -d SiWG917M111MGTBA
commander util genkeyconfig -o keys.json -d SiWG917M111MGTBA
commander manufacturing provision --keys keys.json -d SiWG917M111MGTBA
echo '{"efuse_data": {"ta_secure_boot_enable": 1, "m4_secure_boot_enable": 1}}' > mbr.json
commander manufacturing provision --mbr default --data mbr.json -d SiWG917M111MGTBA
```

#### Adding MIC to Images

The above configuration enables MIC authentication of images. A MIC is added to the image by a
post-build step in the Zephyr build system when `CONFIG_SIWX91X_MIC_KEY` is set. The Kconfig option
must be set to the key provisioned to the device in the previous section under `.KEYS.M4_OTA_KEY`.

Example using `jq` to extract the key from the json file:

```
west build -p -b siwx917_rb4338a tests/crypto/psa_crypto/ -T crypto.psa_crypto.default -DCONFIG_SIWX91X_MIC_KEY=`jq '.KEYS.M4_OTA_KEY' keys.json`
```

The key can also be given directly or set in `prj.conf`.
