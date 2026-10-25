[CmdletBinding()]
param([switch]$SoftwareEmulation)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
Push-Location $root
try {
    $qemu = Join-Path $root 'tools\qemu\qemu-system-x86_64.exe'
    $arguments = @('-L','tools/qemu/share','-machine','q35','-m','4096','-smp','4',
        '-cpu','qemu64','-display','none','-monitor','none','-serial','pipe:swanbridge-build-20261025','-no-reboot',
        '-kernel','build/openwrt/firmware/kernel/boot/vmlinuz',
        '-append','root=/dev/vda2 rootwait rw init=/bin/sh console=ttyS0 panic=-1',
        '-drive','if=none,id=os,file=build/openwrt/vm/boot.qcow2,format=qcow2',
        '-device','virtio-blk-pci,drive=os,serial=SB-BOOT',
        '-drive','if=none,id=data,file=build/openwrt/vm/data.qcow2,format=qcow2',
        '-device','virtio-blk-pci,drive=data,serial=SB-BUILD-DATA',
        '-drive','if=none,id=input,file=fat:ro:build/openwrt/vm/input,format=raw,readonly=on',
        '-device','virtio-blk-pci,drive=input,serial=SB-BUILD-INPUT',
        '-netdev','user,id=net0,hostfwd=tcp:127.0.0.1:22225-10.0.2.15:22',
        '-device','virtio-net-pci,netdev=net0','-rtc','base=utc')
    if ($SoftwareEmulation) { $arguments += @('-accel','tcg,thread=multi') }
    else { $arguments += @('-accel','whpx,kernel-irqchip=off') }
    & $qemu @arguments
    exit $LASTEXITCODE
} finally { Pop-Location }
