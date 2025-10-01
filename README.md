A Rust UEFI app to play with a TPM2 chip.

## Development
Clone `https://github.com/ChocolateLoverRaj/ez_tpm` in the same folder as this repo. `ez_tpm` is also in early development.

Get OVMF with TPM enabled and set `OVMF_PATH` to the folder containing `OVMF_CODE.fd` and `OVMF_VARS.fd`. If you are using Nix, this is as easy as running `nix develop`.

Start the software TPM:
```bash
mkdir -p /tmp/mytpm1
swtpm socket --tpmstate dir=/tmp/mytpm1 \
  --ctrl type=unixio,path=/tmp/mytpm1/swtpm-sock \
  --tpm2 \
  --log level=20
```

Set up the `esp` folder:
```bash
mkdir -p esp/efi/boot/
```

Build, copy, and run the app:
```bash
cargo build --target x86_64-unknown-uefi && cp target/x86_64-unknown-uefi/debug/uefi-tpm2.efi esp/efi/boot/bootx64.efi && qemu-system-x86_64 -enable-kvm     -drive if=pflash,format=raw,readonly=on,file=$OVMF_PATH/OVMF_CODE.fd     -drive if=pflash,format=raw,readonly=on,file=$OVMF_PATH/OVMF_VARS.fd     -drive format=raw,file=fat:rw:esp -chardev socket,id=chrtpm,path=/tmp/mytpm1/swtpm-sock -tpmdev emulator,id=tpm0,chardev=chrtpm -device tpm-tis,tpmdev=tpm0 --nographic
```
Or in Ubuntu in WSL2 
```bash
cargo build --target x86_64-unknown-uefi && cp target/x86_64-unknown-uefi/debug/uefi-tpm2.efi esp/efi/boot/bootx64.efi && qemu-system-x86_64 -drive if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd     -drive if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_VARS_4M.fd     -drive format=raw,file=fat:rw:esp -chardev socket,id=chrtpm,path=/tmp/mytpm1/swtpm-sock -tpmdev emulator,id=tpm0,chardev=chrtpm -device tpm-tis,tpmdev=tpm0 --nographic
```

## Specifications to reference
- [QEMU docs on emulating TPM](https://qemu-project.gitlab.io/qemu/specs/tpm.html#the-qemu-tpm-emulator-device)
- [TCG EFI Protocol Specification](https://trustedcomputinggroup.org/resource/tcg-efi-protocol-specification/)
- [TPM 2.0 Library (all parts)](https://trustedcomputinggroup.org/resource/tpm-library-specification/)
