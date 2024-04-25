# RocketZ Bootloader

RocketZ is a bootloader based on Zephyr framework and MCUboot. It provides features such as:

- Utilizing multiple storage mediums
- Storing multiple images
- Can be customized for different devices
- Image signing for secure boot
- Image encryption
- Rollback on multiple app start failures
- Watchdog setup upon start with configurable settings
- Optional flash security lock
- Boot logs to provide information about any errors occurring during boot

## Usage

### Creating images

When building firmware to be used with RocketZ bootloader, make sure you use the following configurations in your `prj.conf`:

```
CONFIG_FLASH=y
CONFIG_USING_ROCKETZ=y
CONFIG_FLASH_LOAD_OFFSET=0x10400 # ROCKETZ_APP_ADDR + header size
```

You can use `Kconfig` file in this repository to add RocketZ-related configurations.

#### Signing and encrypting the image

You can use the source under `rocket-z/image-generator` to build image signing or image encryption tools (you can use the provided `Makefile` in linux or `win-make` in windows to build the code), or you could use pre-built binaries under `build` directory.

Use `img-sign` tool to create a signature for the image. Signature provides authentication for the image to make sure it was created by an authorized user. Signing should be preferably done in a remote host that can verify the user. Run the tool in command-line without arguments to see how to use it.

The bootloader must have the authenticator's public key built-in. It can be found in `keys.h`.

Use `img-gen` to generate an image with a header that contains image signature and meta-data in addition to the firmware binary itself. This tool can output encrypted as well as unencrypted image. Unencrypted images are faster to load (good for debugging and testing), but are not recommended if you are uploading the image to a host.

The bootloader has its own private key which is used in encryption. `img-gen` tool requires the public key of the bootloader.

Currently, the supported keys are all EC-P256.

### Installing the bootloader in a device

To use the bootloader in a device you need to

- flash the bootloader binary, and,
- flash the bootloader private key

Private key is a 32-byte key that need to be stored in an address defined as `CONFIG_ROCKETZ_KEY_ADDR` (typically 0xD000). Before the app starts, the bootloader attempts to lock the region where the key is stored from read/write.

#### Generating bootloader's private key

The process of generating bootloader's key should typically be done once. The key `.hex` file then can be used across devices.

You can [generate EC-P256 keys using OpenSSL](https://www.scottbrady91.com/openssl/creating-elliptical-curve-keys-using-openssl) (make sure you use `-nodes` option to have an unencrypted key). Then use `openssl ec -text -noout < /private/key/path` to get the private key in hex. You'll need to [print that key in binary into a file](https://stackoverflow.com/questions/5582778/how-to-write-a-binary-file-using-bash). Then use `srec_cat binary_file.bin -Binary -offset 0xD000 -o hex_file.hex` to generate hex file with the right address offset which you can use to burn the key into the device using the debugger tools (e.g. nrfjprog).

### In-app bootloader API

The loaded firmware app can set configurations for the bootloader using the functions provided in `boot-info-ctrl.h`. Configurations are stored in a struct of type `struct BootInfo` at address `CONFIG_ROCKETZ_INFO_ADDR`. To modify the configuration you need to load the struct using `bootInfo_load` function, make the modifications required with the functions below, then save the new configurations with `bootInfo_save` function.

To use these functions, the relevant source code needs to included in the app project. See relevant sources needed in rocket-z CMakeLists file (find `# Sources needed for in-app API`). You might also need to import definition of `bootInfo_getFlashDevice` function and serial interfaces.

The configurations can be modified as follows:

#### Loading a new image

To load an image,

- store the generated image binary in any supported storage medium (e.g. external or internal flash storage),
- use `bootInfo_setStore` to provide the storage medium and address offset of the image (you need to select one of the `stores` slots in the `BootInfo` struct to save this info),
- use `bootInfo_setHasImage` to indicate that the store has a valid image,
- use `bootInfo_setLoadRequest` to request loading image from that store, then,
- save the information using `bootInfo_save` and restart.

#### App start failure

You can setup the bootloader to rollback the image if the loaded app failed to start. Rollback occurs in any of the following cases:

- The bootloader failed to verify signature or checksum of the loaded app twice
- Max fail count > 0, and the app failed to confirm more than max fail count.

Before the app starts bootloader sets a flag for app failure. When the app starts and everything works fine, it needs to confirm by clearing the fail flags using `bootInfo_failClear`.

The app needs to set the maximum fail count using `bootInfo_setFailCountMax`. If that number is 0, which is the default, this mechanism is disabled.

When rollback occurs, preference is to the previously loaded image (if it's still valid). Otherwise, the bootloader will try to load any available image in the `stores` slots.

#### Watchdog

The bootloader can setup the watchdog on startup. The watchdog configuration must be provided using `bootInfo_setWdt`. If the number of WDT channels is 0 (which is default) WDT will not be started by the bootloader.

`bootInfo_setWdt` return value indicates if the currently running watchdog uses the required configuration. If it is not, it would be better to restart the device immediately (after saving the new configurations) to restart WDT with the required options.

### Debugging the app

While developing the app, you might use a debugger to load and run the binary. This would not work with a normal bootloader configuration as the binary might not go through the signing and header-generation process. But this can be done by building the bootloader with `CONFIG_ROCKETZ_DEBUG` option enabled which skips the authentication step. This is not recommended in production.

### Reading boot logs

The bootloader prints errors, warnings and info messages that can be read by the app. Messages are stored in `CONFIG_ROCKETZ_LOG_ADDR`. They are stored as a sequence of null-terminated strings. The sequence ends end at the first byte with value `0xFF`. The log area spans one flash block at maximum (as defined in `CONFIG_ROCKETZ_FLASH_BLOCK_SIZE`).

#### Prevent flash lock

Depending on the device, the bootloader might lock the app code area from modification. This can be disabled (which poses a security risk) in case, for example, the bootloader itself or bootloader's private key needs to be updated (which is risky in itself). To disable it the bootloader must have a secret 32-byte code. The code needs to be hashed using SHA-256 and the hash stored in base-64 format in `CONFIG_ROCKETZ_NO_LOCK_HASH`. The app then needs to store the (unhashed) code in `BootInfo` struct in the designated member variable `noLockCode` and restart the device.

## Porting the bootloader

To build the bootloader for different devices, you need to:

- Modify relevant configurations for your build (see `Kconfig` file) this includes code area size
- Define main function (see `main.c` as an example)
- Modify device-specific functions such as `bootloader_wdtFeed`, `bootloader_jump` and `bootloader_restart` (see `main.c` as an example)
- Define storage interfaces in function `bootInfo_getFlashDevice` (see `main.c` as an example)
- Create new build configuration

You need to make sure the bootloader binary doesn't overlap with other flash blocks such as private key area, boot logs, and boot info.
