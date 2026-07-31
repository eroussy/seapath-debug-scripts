# SEAPATH scripts

Ease SEAPATH debug and deployment

## QEMU threads report

Display QEMU/KVM thread ID, name, scheduler, RT priority, priority, last CPU,
and effective affinity per VM. Pass a VM name to output only that VM and its
associated `kvm-pit` task.

```sh
./qemu_threads_report.py
./qemu_threads_report.py vmname
./qemu_threads_report.py --json
```

Run as root for complete QEMU command-line and thread visibility. `LAST_CPU` is
procfs last-scheduled CPU snapshot, not proof thread executes on CPU while
report prints.

Example:

```text
=== VM: rtvm (PID 1580) ===
    TID  THREAD                   SCHEDULER       RTPRIO PRIO LAST_CPU  AFFINITY
   1580  qemu-system-x86          SCHED_OTHER          0   19        9  9
   1583  qemu-system-x86          SCHED_OTHER          0   19        9  9
   1588  vhost-1580               SCHED_RR             1   41        9  9
   1589  IO mon_iothread          SCHED_OTHER          0   19        9  9
   1590  CPU 0/KVM                SCHED_FIFO           1   41        5  5
   [...]

=== KVM PIT for VM: rtvm (QEMU PID 1580) (PID 1593) ===
    TID  THREAD                   SCHEDULER       RTPRIO PRIO LAST_CPU  AFFINITY
   1593  kvm-pit/1580             SCHED_RR             1   41        9  9
```

## CPU task report

Display every process thread last scheduled on selected CPU. Pass `--allowed`
to also display threads whose effective affinity allows selected CPU but last
scheduler snapshot is elsewhere. When multiple CPUs are selected, tasks are
grouped by last CPU.

```sh
./cpu_tasks_report.py 4
./cpu_tasks_report.py 4-12 --json --allowed
```

Example:

```text
Selected CPU(s): 5
Last CPU is procfs scheduling snapshot, not instantaneous execution.

Last scheduled on selected CPU(s): 13
    PID     TID  PROCESS                  THREAD                   LAST_CPU  AFFINITY
     67      67  cpuhp/5                  cpuhp/5                         5  5
     68      68  irq_work/5               irq_work/5                      5  5
     69      69  migration/5              migration/5                     5  5
     70      70  rcuc/5                   rcuc/5                          5  5
     [...]
```

Run as root for complete task visibility. `LAST_CPU` is procfs last-scheduled
CPU snapshot, not proof thread executes on CPU while report prints.

## Network IRQ report

Display one IRQ table per physical network interface. Tables include IRQ number,
thread ID, IRQ name, scheduler, RT priority, priority, last CPU, and effective
IRQ affinity. Thread and scheduler fields for hard IRQs or invisible IRQ
threads are `?`.

```sh
./network_irq_report.py
./network_irq_report.py eno1
./network_irq_report.py --json
```

IRQ discovery uses device `msi_irqs` and legacy `irq` sysfs entries, with
`/proc/interrupts` name matching as fallback. Run as root for complete IRQ
thread visibility. Pass an interface name to output only that network card.

Example:

```text
=== eno1 (pci0000:00/0000:00:01.1/0000:01:00.0) ===
   IRQ     TID  IRQ_NAME                                   SCHEDULER       RTPRIO PRIO LAST_CPU  AFFINITY
    53       ?  ?                                          ?                    ?    ?        ?  ?
    57     879  IR-PCI-MSIX-0000:01:00.0 0-edge eno1-tx-0  SCHED_FIFO          50   90        7  7
    58     880  IR-PCI-MSIX-0000:01:00.0 1-edge eno1-rx-1  SCHED_FIFO          50   90       14  14
    59     881  IR-PCI-MSIX-0000:01:00.0 2-edge eno1-rx-2  SCHED_FIFO          50   90        5  5
    60     882  IR-PCI-MSIX-0000:01:00.0 3-edge eno1-rx-3  SCHED_FIFO          50   90       12  12
    61     883  IR-PCI-MSIX-0000:01:00.0 4-edge eno1-rx-4  SCHED_FIFO          50   90        3  3
```

## SSH key test

Test public-key SSH access to a SEAPATH machine.
Machine can be given as IP addr or ssh Hostname.
Tries every unencrypted private key found in `~/.ssh` plus each key loaded in
running `ssh-agent`, for `admin`, `ansible`, and `root`. Encrypted private keys
are skipped to avoid passphrase prompts. Prints every working user/key pair.

```sh
./ssh_key_test.py 192.0.2.10
./ssh_key_test.py seapath-host
```

Example:

```text
$ ./ssh_key_test.py seapath-host
Target: seapath-host
Private keys: 2

User: admin
  FAILED   /home/erwann/.ssh/id_ed25519
  SUCCESS  /home/erwann/.ssh/id_rsa

User: ansible
  FAILED   /home/erwann/.ssh/id_ed25519
  FAILED   /home/erwann/.ssh/id_rsa

User: root
  FAILED   /home/erwann/.ssh/id_ed25519
  FAILED   /home/erwann/.ssh/id_rsa
```

## SSH key management

Add, remove, or replace public keys for `admin`, `ansible`, and `root` through
public-key SSH access as `admin`. Target accepts IP addr, hostname, or SSH Host
alias.

`--key` selects private key whose public key is managed. Use `--public-key` to
manage public key directly. Every operation targets `admin`, `ansible`, and `root`.
`replace` overwrites all three `authorized_keys` files.

```sh
./ssh_key_manage.py seapath-host add --key ~/.ssh/id_ed25519
./ssh_key_manage.py 192.0.2.10 add --public-key ~/.ssh/new_key.pub --login-key ~/.ssh/admin_key
./ssh_key_manage.py seapath-host remove --key ~/.ssh/id_ed25519
./ssh_key_manage.py seapath-host replace --key ~/.ssh/new_admin_key
```
