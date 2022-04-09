# Power Saver

Manages Windows Power Plans automatically based on running process names.

The Power Saver will set the [power plan](https://docs.microsoft.com/en-us/windows/win32/power/power-policy-settings) to *Balanced* if the running processes matches a provided list, the plan is set to *Power Saver* otherwise. This can save and regulate the consumed energy of a Windows system to **reduce your electricity bill** and cooling requirements because the performance is force-throttled if you do not need it.

The benefits of an automatic power plan selection can be increased by customizing your *Power Saver* plan to limit the the resource consumption even further (e.g. max CPU usage: 60%).

The spawned process is hidden and will react to its changed configuration file automatically.

## Configuration

The configuration file path is detected as following

1. The first program argument if provided
2. The `POWER_SAVER_CONFIG_PATH` environment variable if set.
3. A `powersaver.yaml` located next to the executable.

The configuration file is simple:

```yaml
# Process pooling time in seconds
interval: 30

# Case insensitive program names that promote the current
# power scheme to "Balanced", otherwise "Power Saver" is set.
balanced:
  - Unreal
  - Blender
  - devenv
```

**File changes are detected automatically and adjust the power plan instantly!**

## Building

````bash
cargo build --release
````

