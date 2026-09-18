"""Package an Aya integration VM around a source-built Linux kernel."""

load("@linux.bzl", "initramfs")
load("//bazel:vm.bzl", "aya_qemu_vm_test")

def aya_integration_vm_test(
        name,
        qemu_system_target,
        kernel_repo,
        tags = []):
    """Boots a kernel with its matching config, symbols, and ingress module.

    Args:
      name: Name of the VM test target.
      qemu_system_target: QEMU system target for the guest architecture.
      kernel_repo: Generated linux_images image facade repository.
      tags: Bazel tags for the VM and its generated targets.
    """
    ingress = kernel_repo + "//:sch_ingress"
    aliases = name + "_modules_alias"
    initrd = name + "_initramfs"

    native.genrule(
        name = aliases,
        srcs = [ingress],
        outs = [name + ".modules.alias"],
        cmd = """set -euo pipefail
mkdir -p "$(@D)/modules/kernel/net/sched"
cp "$(location {ingress})" "$(@D)/modules/kernel/net/sched/sch_ingress.ko"
"$(execpath //test-distro:depmod)" --base-dir "$(@D)/modules"
cp "$(@D)/modules/modules.alias" "$@"
""".format(ingress = ingress),
        tags = tags,
        tools = ["//test-distro:depmod"],
    )

    initramfs(
        name = initrd,
        # The integration tests read /boot/config and find System.map-* in /boot.
        executables = {
            "/bin/integration-test-unit-test-bin": ":integration-test-unit-test",
            "/bin/integration-test-unit-test-opt": ":integration-test-unit-test-opt",
            "/init": "//test-distro:init",
            "/sbin/modprobe": "//test-distro:modprobe",
        },
        files = {
            "/boot/config": kernel_repo + "//:config",
            "/boot/System.map-aya": kernel_repo + "//:system_map",
            "/lib/modules/kernel/net/sched/sch_ingress.ko": ingress,
            "/lib/modules/modules.alias": ":" + aliases,
        },
        tags = tags,
    )

    aya_qemu_vm_test(
        name = name,
        timeout = "long",
        args = ["--test-threads=1"],
        config = kernel_repo + "//:config",
        initrd = ":" + initrd,
        kernel = kernel_repo + "//:kernel",
        qemu_system_target = qemu_system_target,
        tags = tags,
    )

    if qemu_system_target == "x86_64":
        aya_qemu_vm_test(
            name = name + "_macos",
            args = ["--test-threads=1"],
            config = kernel_repo + "//:config",
            exec_compatible_with = ["@platforms//os:macos"],
            initrd = ":" + initrd,
            kernel = kernel_repo + "//:kernel",
            qemu_system_target = qemu_system_target,
            tags = tags + ["local", "external"],
            target_compatible_with = ["@platforms//os:macos"],
            timeout = "long",
        )
