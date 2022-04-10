# Power Saver

Manages Windows Power Plans automatically based on running process names.

The Power Saver will set the [power plan](https://docs.microsoft.com/en-us/windows/win32/power/power-policy-settings) to *Balanced* if the running processes match a provided list, the plan is set to *Power Saver* otherwise. This can save and regulate the consumed energy of a Windows system to **reduce your electricity bill** and cooling requirements because the performance is force-throttled if you do not need it.

The benefits of an automatic power plan selection can be increased by customizing your *Power Saver* plan to limit the resource consumption even further (e.g. max CPU usage: 60%).

The spawned process is hidden and will react to its changed configuration file automatically. A tray icon is displayed to indicate the current power level (green = *saving* and orange = *balanced*). Additionally, the tray icon provides the ability to force a specific power level among other useful options.

<img src="https://user-images.githubusercontent.com/1146834/162625469-031f698e-e586-4335-9a55-852fe909ea6e.png" style="zoom:67%;" />

## Configuration

The configuration file path is detected as following

1. The first program argument if provided
2. The `POWER_SAVER_CONFIG_PATH` environment variable, if set.
3. A `powersaver.yaml` that is located next to the executable.

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

