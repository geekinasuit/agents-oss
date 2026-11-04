"""The root a scripted lead's signed spec must verify against, fixed when the binary is built."""

load("@bazel_skylib//rules:common_settings.bzl", "BuildSettingInfo")

def _pinned_root_jar_impl(ctx):
    pin = ctx.actions.declare_file(ctx.label.name + ".txt")
    ctx.actions.write(pin, ctx.attr.pin[BuildSettingInfo].value)
    jar = ctx.actions.declare_file(ctx.label.name + ".jar")

    # The entry's path in the jar is spelled out, so it is the same whether this repo is the main one
    # or a module another repo depends on (where a resource's path would start with external/<repo>).
    ctx.actions.run(
        executable = ctx.executable._zipper,
        arguments = ["c", jar.path, ctx.attr.resource_path + "=" + pin.path],
        inputs = [pin],
        outputs = [jar],
        mnemonic = "PinnedRootJar",
    )
    return [DefaultInfo(files = depset([jar]))]

pinned_root_jar = rule(
    implementation = _pinned_root_jar_impl,
    doc = "A jar holding the value of the `pin` string flag at `resource_path`, for a java_import.",
    attrs = {
        "pin": attr.label(mandatory = True, providers = [BuildSettingInfo]),
        "resource_path": attr.string(mandatory = True),
        "_zipper": attr.label(default = "@bazel_tools//tools/zip:zipper", executable = True, cfg = "exec"),
    },
)
