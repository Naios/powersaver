/* PowerSaver - Switches windows power plans based on running programs.
 * Copyright (C) 2022 Denis Blank denis.blank (at) outlook (dot) com
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#![cfg_attr(
    all(target_os = "windows", not(debug_assertions), not(feature = "console")),
    windows_subsystem = "windows"
)]

use core::time;
use notify::{RecursiveMode, Watcher};
use regex::{Regex, RegexBuilder};
use serde::{Deserialize, Serialize};
use std::env;
use std::error::Error;
use std::fs::File;
use std::io::BufReader;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Condvar, Mutex};
use strum_macros;
use sysinfo::{ProcessExt, System, SystemExt};
use winapi::shared::guiddef::GUID;
use winapi::um::powersetting::{PowerGetActiveScheme, PowerSetActiveScheme};
use winapi::DEFINE_GUID;

#[derive(Debug, PartialEq, Serialize, Deserialize)]
struct Config {
    interval: u32,
    balanced: Vec<String>,
}

fn read_config_from_file<P: AsRef<Path>>(path: P) -> std::result::Result<Config, Box<dyn Error>> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);

    let config = serde_yaml::from_reader(reader)?;

    Ok(config)
}

// Fixed GUIDs:
// https://docs.microsoft.com/en-us/windows/win32/power/power-policy-settings

// a1841308-3541-4fab-bc81-f71556f20b4a (Power Saver)
DEFINE_GUID! {GUID_ENERGY_SCHEME_SAVING,
0xa1841308, 0x3541, 0x4fab, 0xbc, 0x81, 0xf7, 0x15, 0x56, 0xf2, 0x0b, 0x4a}
// 381b4222-f694-41f0-9685-ff5bb260df2e (Balanced)
DEFINE_GUID! {GUID_ENERGY_SCHEME_BALANCED,
0x381b4222, 0xf694, 0x41f0, 0x96, 0x85, 0xff, 0x5b, 0xb2, 0x60, 0xdf, 0x2e}
// 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c (High Power)
// Not used currently

#[derive(Debug, Eq, PartialEq, strum_macros::Display)]
#[strum(serialize_all = "snake_case")]
enum PowerLevel {
    Saving,
    Balanced,
}

fn map_power_level_to_guid(level: &PowerLevel) -> GUID {
    match level {
        PowerLevel::Saving => GUID_ENERGY_SCHEME_SAVING,
        PowerLevel::Balanced => GUID_ENERGY_SCHEME_BALANCED,
    }
}

fn get_active_power_scheme() -> Option<GUID> {
    unsafe {
        let mut guid: *mut GUID = std::ptr::null_mut();
        if PowerGetActiveScheme(std::ptr::null_mut(), &mut guid) == 0 && !guid.is_null() {
            Some(*guid)
        } else {
            None
        }
    }
}

fn set_active_power_scheme(guid: &GUID) -> bool {
    unsafe { PowerSetActiveScheme(std::ptr::null_mut(), guid) == 0 }
}

fn compute_intended_power_scheme_guid(system: &System, regex: &Regex) -> PowerLevel {
    let is_balanced = system
        .processes()
        .iter()
        .any(|(_, process)| regex.is_match(process.name()));

    if is_balanced {
        PowerLevel::Balanced
    } else {
        PowerLevel::Saving
    }
}

fn equal(left: &GUID, right: &GUID) -> bool {
    (left.Data1 == right.Data1)
        && (left.Data2 == right.Data2)
        && (left.Data3 == right.Data3)
        && (left.Data4 == right.Data4)
}

fn get_config_path() -> PathBuf {
    // Program args
    let args: Vec<String> = env::args().collect();
    if let Some(path) = args.get(1) {
        return PathBuf::from(path);
    }

    // Environment variable
    if let Ok(path) = env::var("POWER_SAVER_CONFIG_PATH") {
        return PathBuf::from(path);
    }

    // Executable path
    let default_config_name: &'static str = "powersaver.yaml";

    if let Some(parent) = std::env::current_exe().unwrap().parent() {
        let mut buffer = PathBuf::new();
        buffer.push(parent);
        buffer.push(default_config_name);
        buffer
    } else {
        PathBuf::from(default_config_name)
    }
}

struct State {
    system: System,
    changed: AtomicBool,
    stop: AtomicBool,
    condvar: Condvar,
    mutex: Mutex<()>,
}

impl State {
    fn new() -> State {
        State {
            system: System::new_all(),
            changed: AtomicBool::new(false),
            stop: AtomicBool::new(false),
            condvar: Condvar::new(),
            mutex: Mutex::new(()),
        }
    }

    fn notify(&self) {
        self.condvar.notify_one();
    }
}

struct PowerSaver {
    config: Config,
    state: Arc<State>,
    regex: Regex,
}

impl PowerSaver {
    fn compile(config: &Config) -> Regex {
        let mut itr = config.balanced.iter();

        if let Some(first) = itr.next() {
            // Create the pattern for the balanced scheme
            let pattern = itr.map(|s| regex::escape(s)).fold(
                format!("({})", regex::escape(first.as_str())),
                |left, right| -> String { format!("{left}|({right})") },
            );

            RegexBuilder::new(pattern.as_str())
                .case_insensitive(true)
                .build()
                .unwrap()
        } else {
            // Matches never
            Regex::new("(?!)").unwrap()
        }
    }

    fn new(config: Config, state: Arc<State>) -> PowerSaver {
        let regex = PowerSaver::compile(&config);

        PowerSaver {
            config,
            state,
            regex,
        }
    }

    fn update(&self) {
        let intended = compute_intended_power_scheme_guid(&self.state.system, &self.regex);
        let target = map_power_level_to_guid(&intended);

        if let Some(active) = get_active_power_scheme() {
            if !equal(&active, &target) {
                set_active_power_scheme(&target);
                println!("Setting active power scheme to '{intended}'.")
            } else {
                println!("The current power scheme '{intended}' is equal to the current one.")
            }
        }
    }

    fn wait(&self) {
        let interval = time::Duration::from_secs(self.config.interval.into());

        let locked = self.state.mutex.lock().unwrap();

        let (_, _) = self.state.condvar.wait_timeout(locked, interval).unwrap();
    }
}

fn main() -> std::result::Result<(), Box<dyn Error>> {
    let state = Arc::new(State::new());

    let path = get_config_path();
    let readable = path.as_path().display().to_string();

    println!("Reading config file '{readable}'...");

    // Read the config and create the saver and state
    let default_config = read_config_from_file(&path)?;

    let mut saver = PowerSaver::new(default_config, state.clone());

    let mut watcher = notify::recommended_watcher({
        let state_t2 = state.clone();

        move |res| match res {
            Ok(_) => {
                state_t2
                    .changed
                    .store(true, std::sync::atomic::Ordering::Relaxed);

                state_t2.notify();
            }
            Err(e) => {
                println!("watch error: {:?}", e);
                state_t2
                    .stop
                    .store(true, std::sync::atomic::Ordering::Relaxed);

                state_t2.notify();
            }
        }
    })?;

    watcher.watch(path.as_path(), RecursiveMode::Recursive)?;

    loop {
        saver.update();
        saver.wait();

        if state.stop.load(std::sync::atomic::Ordering::Acquire) {
            break;
        }

        if state.changed.load(std::sync::atomic::Ordering::Acquire) {
            state
                .changed
                .store(false, std::sync::atomic::Ordering::Release);

            println!("Detected a config file change!");

            match read_config_from_file(&path) {
                Ok(updated_config) => {
                    if updated_config == saver.config {
                        println!("Config file '{readable}' did not change!");
                    } else {
                        saver = PowerSaver::new(updated_config, state.clone());
                        println!("Updated the config file '{readable}'.");
                    }
                }
                Err(error) => {
                    println!("Failed to update the config file '{readable}' ('{error}').");
                }
            }
        }
    }

    Ok(())
}
