"""Expose Homebrew's QEMU installation to macOS VM tests."""

# TODO(https://github.com/hermeticbuild/qemu-prebuilt/issues/4): Remove this
# repository when rules_qemu provides pinned macOS host artifacts.

def _homebrew_qemu_repository_impl(repository_ctx):
    if not repository_ctx.os.name.startswith("mac"):
        repository_ctx.file("BUILD.bazel", "")
        return

    brew = repository_ctx.which("brew")
    if brew == None:
        fail("Homebrew is required for macOS VM tests; install QEMU with brew install qemu")

    result = repository_ctx.execute([brew, "--prefix", "--installed", "qemu"])
    if result.return_code:
        fail("Homebrew QEMU is required for macOS VM tests: {}".format(result.stderr))

    prefix = result.stdout.strip()
    for path in ["bin/qemu-img", "bin/qemu-system-x86_64", "share/qemu"]:
        source = repository_ctx.path(prefix + "/" + path)
        if not source.exists:
            fail("Homebrew QEMU is missing {}".format(source))
        repository_ctx.symlink(source, path)

    repository_ctx.file("BUILD.bazel", """\
package(default_visibility = ["//visibility:public"])

exports_files([
    "bin/qemu-img",
    "bin/qemu-system-x86_64",
    "share/qemu",
])

filegroup(
    name = "system_data",
    srcs = ["share/qemu"],
)

toolchain(
    name = "x86_64",
    exec_compatible_with = ["@platforms//os:macos"],
    tags = ["manual"],
    target_settings = ["@aya//bazel:bpf_target_arch_x86_64"],
    toolchain = "@aya//bazel/toolchains:homebrew_qemu_x86_64_impl",
    toolchain_type = "@rules_qemu//qemu:exec_toolchain_type",
)
""")

homebrew_qemu_repository = repository_rule(
    implementation = _homebrew_qemu_repository_impl,
    environ = ["PATH"],
    local = True,
    configure = True,
)
