"""Build the kernel artifacts required by Aya's integration VMs."""

def aya_kernel(name, fragments, config_rule, config_parity_test, build_rule, artifact_rule):
    """Declare a build inside its generated repository for the guest platform.

    Each generated source repository owns its rules and provider types. Pass
    those rules together so the config, build, and selectors share that owner.

    Args:
      name: Boot image target; the other targets use this name as a prefix.
      fragments: Raw config fragments exported by the generator.
      config_rule: The repository's kernel_config macro.
      config_parity_test: The repository's native configuration comparison macro.
      build_rule: The repository's kbuild_resolved_build rule.
      artifact_rule: The repository's kernel_artifact rule.
    """
    configs = {}
    parity_tests = []
    for arch in ["aarch64", "x86_64"]:
        config = name + "_requested_" + arch
        config_rule(
            name = config,
            allnoconfig = True,
            options = "//options:options",
            pahole = "//:pahole",
            requested = fragments["aya_" + arch],
            tags = ["manual"],
        )
        configs["@platforms//cpu:" + arch] = ":" + config
        parity = name + "_config_parity_" + arch
        config_parity_test(
            name = parity,
            config = ":" + config,
            platform = "@rules_rs//rs/platforms:" + arch + "-unknown-linux-musl",
        )
        parity_tests.append(":" + parity)

    native.test_suite(
        name = name + "_config_parity",
        tags = ["manual"],
        tests = parity_tests,
    )

    build = name + "_build"
    build_rule(
        name = build,
        architecture_roots = {
            "arm64": ["arch/arm64/boot/Image"],
            "x86": ["arch/x86/boot/bzImage"],
        },
        catalog = "//:catalog",
        config = select(configs),
        modules = ["net/sched/sch_ingress.ko"],
        required_options = {
            "BPF_LSM": "y",
            "DEBUG_INFO_BTF": "y",
            "EPOLL": "y",
            "MULTIUSER": "y",
            "NAMESPACES": "y",
            "NET_CLS_BPF": "y",
            "NET_NS": "y",
            "NET_SCH_INGRESS": "m",
            "SECURITY": "y",
            "SECURITY_NETWORK": "y",
            "SHMEM": "y",
            "TMPFS": "y",
            "USER_NS": "y",
            "XDP_SOCKETS": "y",
        },
        roots = ["vmlinux"],
        tags = ["manual"],
    )
    artifact_rule(
        name = name,
        build = ":" + build,
        path = select({
            "@platforms//cpu:aarch64": "arch/arm64/boot/Image",
            "@platforms//cpu:x86_64": "arch/x86/boot/bzImage",
        }),
        tags = ["manual"],
    )
    for suffix, path in {
        "config": ".config",
        "system_map": "System.map",
        "sch_ingress": "net/sched/sch_ingress.ko",
    }.items():
        artifact_rule(
            name = name + "_" + suffix,
            build = ":" + build,
            path = path,
            tags = ["manual"],
        )
