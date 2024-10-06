# Windows Registry Spoofer

Able to spoof programs that reads registry values using `RegEnumValueW`, by performing an IAT hook.

This is a PoC so currently any registry value that matches `HIDDEN_REG` will be removed (irrespective of the subkey). This can be changed to be subkey specific by getting the subkey value from `hKey`.

## Usage

Inject into any 64 bit program. To inject into a 32 bit program, compile DLL as 32 bit.

## Demo

https://youtu.be/EFTov_RQ0Ws
