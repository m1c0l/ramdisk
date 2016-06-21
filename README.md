# ramdisk
This is a memory block device that can be used with QEMU. The kernel code does reads and writes to the device, and also supports delayed reads and writes, spin locks with a ticket system to synchronize reads and writes, and password-based encryption using a Jenkins hash.
