import sys
import os
import subprocess
import platform
import ctypes
import shlex  
import shutil
import time

try:
    import tkinter as tk
    from tkinter import filedialog
    TK_AVAILABLE = True
except Exception:
    tk = None
    filedialog = None
    TK_AVAILABLE = False

_DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
if _DATA_DIR not in sys.path:
    sys.path.insert(0, _DATA_DIR)

from data import server

def attach_console():
    if sys.platform == "win32":
        try:
            ctypes.windll.kernel32.FreeConsole()
            ctypes.windll.kernel32.AllocConsole()
            sys.stdout = open("CONOUT$", "w")
            sys.stderr = open("CONOUT$", "w")
        except Exception:
            pass

def _escape_applescript_arg(arg: str) -> str:
    # Basic escaping for AppleScript strings
    return arg.replace("\\", "\\\\").replace('"', '\\"')

def _is_termux():
    return "com.termux" in os.environ.get("PREFIX", "") or "TERMUX_VERSION" in os.environ

def _cli_folder_browser():
    home = os.path.expanduser("~")
    current = home
    for cand in (os.path.join(home, "storage", "shared"), "/storage/emulated/0", home):
        if os.path.isdir(cand):
            current = cand
            break
    while True:
        try:
            subs = sorted(
                d for d in os.listdir(current)
                if os.path.isdir(os.path.join(current, d)) and not d.startswith('.')
            )
        except OSError:
            print("Cannot read this folder, going up.")
            current = os.path.dirname(current) or "/"
            continue
        print(f"\nCurrent: {current}")
        for i, d in enumerate(subs, 1):
            print(f"  {i}. {d}/")
        print("[number]=open  ..=up  s=SELECT THIS FOLDER  p=type path  q=quit")
        try:
            cmd = input("> ").strip()
        except (EOFError, KeyboardInterrupt):
            return None
        if cmd.lower() == 'q':
            return None
        if cmd.lower() == 's':
            return current
        if cmd == '..':
            current = os.path.dirname(current) or "/"
        elif cmd.lower() == 'p':
            p = input("Path: ").strip().strip('"')
            if os.path.isdir(p):
                current = os.path.abspath(p)
            else:
                print("Not a valid directory.")
        elif cmd.isdigit() and 1 <= int(cmd) <= len(subs):
            current = os.path.join(current, subs[int(cmd) - 1])
        else:
            print("Invalid input.")

def open_folder_picker():
    system = platform.system()
    if _is_termux():
        return _cli_folder_browser()

    # Tkinter GUI dialog
    if TK_AVAILABLE:
        try:
            root = tk.Tk()
            root.withdraw()
            root.attributes('-topmost', True)
            folder_selected = filedialog.askdirectory(title="Select Folder to Serve")
            root.destroy()
            if folder_selected:
                return folder_selected
        except Exception:
            pass

    # OS-native fallbacks (no Tkinter)
    
    # macOS: use AppleScript
    if system == "Darwin":
        try:
            script = 'POSIX path of (choose folder with prompt "Select Folder to Serve")'
            result = subprocess.run(
                ["osascript", "-e", script],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                env=_clean_subprocess_env(),
            )
            folder = result.stdout.strip()
            if folder:
                return folder
        except Exception:
            pass

    # Linux: try zenity or kdialog
    if system == "Linux":
        zenity_cmd = ["zenity", "--file-selection", "--directory", "--title=Select Folder to Serve"]
        kdialog_cmd = ["kdialog", "--getexistingdirectory", os.path.expanduser("~")]

        for cmd in (zenity_cmd, kdialog_cmd):
            try:
                result = subprocess.run(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,
                    text=True,
                    env=_clean_subprocess_env(),
                )
                folder = result.stdout.strip()
                if folder:
                    return folder
            except (FileNotFoundError, Exception):
                continue

    # CLI input
    print("\n--- Folder Selection ---")
    while True:
        try:
            path_input = input("Enter folder path to serve (or 'q' to quit): ").strip('"').strip()
            if path_input.lower() == 'q':
                return None
            if not path_input:
                continue # ignore empty enter presses
                
            if os.path.isdir(path_input):
                return path_input
            else:
                print(f"Error: '{path_input}' is not a valid directory. Try again.")
        except (EOFError, KeyboardInterrupt):
            return None

def _clean_subprocess_env():
    """Return a copy of the environment with PyInstaller's onefile
    LD_LIBRARY_PATH override restored to its original value, so that
    externally spawned processes (terminal emulators, zenity, etc.)
    don't inherit incompatible bundled library paths and crash."""
    env = os.environ.copy()
    for var in ("LD_LIBRARY_PATH", "DYLD_LIBRARY_PATH"):
        orig_var = var + "_ORIG"
        if orig_var in env:
            env[var] = env[orig_var]
        elif var in env:
            # No _ORIG saved (not frozen, or nothing to restore) - leave as is
            pass
    return env


    system = platform.system()

    if getattr(sys, 'frozen', False):
        executable = sys.executable
        args = [executable, target_folder]
    else:
        executable = sys.executable
        script_path = os.path.abspath(__file__)
        args = [executable, script_path, target_folder]

    proc = None

    if system == "Windows":
        proc = subprocess.Popen(
            args,
            close_fds=True,
            creationflags=subprocess.CREATE_NEW_CONSOLE,
            env=_clean_subprocess_env(),
        )

    elif system == "Darwin":
        safe_args = " ".join(f'"{_escape_applescript_arg(a)}"' for a in args)
        osascript_cmd = f'tell application "Terminal" to do script "{safe_args}"'
        try:
            subprocess.run(['osascript', '-e', osascript_cmd], env=_clean_subprocess_env())
            # macOS Terminal launches async; we don't get a Popen object back usually
            return None
        except Exception as e:
            print(f"Failed to launch Terminal: {e}")
            print("Running server in the current process instead.")
            run_server_in_process(target_folder)
        return None

    elif system == "Linux":
        terminals = [
            "gnome-terminal", "xfce4-terminal", "konsole", "lxterminal",
            "tilix", "mate-terminal", "qterminal", "terminator",
            "alacritty", "xterm"
        ]

        for term in terminals:
            term_path = shutil.which(term)
            if not term_path:
                print(f"[launcher] '{term}' not found on PATH, skipping.")
                continue
            try:
                if term == "gnome-terminal":
                    cmd = [term, "--"] + args
                elif term in ("xfce4-terminal", "qterminal"):
                    safe_command = " ".join(shlex.quote(arg) for arg in args)
                    cmd = [term, "-e", safe_command]
                else:
                    cmd = [term, "-e"] + args
                print(f"[launcher] Trying terminal: {cmd}")
                proc = subprocess.Popen(cmd, close_fds=True)
                print(f"[launcher] Launched {term} (pid={proc.pid})")
                break
            except Exception as e:
                print(f"[launcher] Failed to launch {term}: {e}")
                proc = None
                continue

        if proc is None:
            print("Could not find a suitable terminal emulator.")
            print("Running server in the current process instead.")
            run_server_in_process(target_folder)
            return None

    return proc

def _app_base_dir():
    if getattr(sys, 'frozen', False):
        return os.path.dirname(os.path.abspath(sys.executable))
    return os.path.dirname(os.path.abspath(__file__))

_console_ctrl_handler_ref = None

def _install_console_close_handler(target_folder):
    # Handles the Windows console X button and CTRL events so the normal try/except/finally won't fire.
    global _console_ctrl_handler_ref
    HANDLER_ROUTINE = ctypes.WINFUNCTYPE(ctypes.c_int, ctypes.c_uint)

    def _handler(ctrl_type):
        # CTRL_C=0, CTRL_BREAK=1, CTRL_CLOSE=2, CTRL_LOGOFF=5, CTRL_SHUTDOWN=6
        if ctrl_type in (0, 1, 2, 5, 6):
            cleanup_extracted_subtitles(target_folder)
        return False

    try:
        _console_ctrl_handler_ref = HANDLER_ROUTINE(_handler)
        ctypes.windll.kernel32.SetConsoleCtrlHandler(_console_ctrl_handler_ref, True)
    except Exception:
        pass

def cleanup_extracted_subtitles(target_folder):
   
    dir_to_remove = getattr(server, "SUBTITLES_EXTRACT_DIR", None)
    if not dir_to_remove:
        dir_to_remove = os.path.join(_app_base_dir(), "data", "subtitles extracted")
    if os.path.isdir(dir_to_remove):
        try:
            shutil.rmtree(dir_to_remove)
            print(f"Deleted: {dir_to_remove}")
        except Exception as e:
            print(f"Failed to delete {dir_to_remove}: {e}")

def _notify_clients_server_closing():
    # Best-effort: ask the server to push a quick refresh/shutdown notice
    for hook_name in ("broadcast_shutdown", "notify_shutdown", "broadcast_server_closing"):
        hook = getattr(server, hook_name, None)
        if callable(hook):
            try:
                hook()
            except Exception:
                pass
            break

def run_server_in_process(target_folder):
    if os.path.isdir(target_folder):
        server.FOLDER_TO_SERVE = target_folder
        if sys.platform == "win32":
            _install_console_close_handler(target_folder)
        try:
            server.run_server()
        except KeyboardInterrupt:
            _notify_clients_server_closing()
            sys.exit(0)
        except Exception as e:
            print(f"Critical Error: {e}")
            input("Press Enter to exit...")
        finally:
            _notify_clients_server_closing()
            cleanup_extracted_subtitles(target_folder)
            if _is_termux():
                try:
                    input("\nServer stopped. Press Enter to exit...")
                except (EOFError, KeyboardInterrupt):
                    pass
            sys.exit(0)
    else:
        print("Error: Invalid folder path.")
        input("Press Enter to exit...")
def launch_server_process(target_folder):
    system = platform.system()

    if getattr(sys, "frozen", False):
        executable = sys.executable
        args = [executable, target_folder]
    else:
        executable = sys.executable
        script_path = os.path.abspath(__file__)
        args = [executable, script_path, target_folder]

    proc = None

    if system == "Windows":
        proc = subprocess.Popen(
            args,
            close_fds=True,
            creationflags=subprocess.CREATE_NEW_CONSOLE,
            env=_clean_subprocess_env(),
        )

    elif system == "Darwin":
        safe_args = " ".join(
            f'"{_escape_applescript_arg(a)}"' for a in args
        )
        osascript_cmd = (
            f'tell application "Terminal" to do script "{safe_args}"'
        )

        try:
            subprocess.run(
                ["osascript", "-e", osascript_cmd],
                env=_clean_subprocess_env()
            )
            return None
        except Exception as e:
            print(f"Failed to launch Terminal: {e}")
            print("Running server in the current process instead.")
            run_server_in_process(target_folder)
            return None

    elif system == "Linux":
        terminals = [
            "gnome-terminal",
            "xfce4-terminal",
            "konsole",
            "lxterminal",
            "tilix",
            "mate-terminal",
            "qterminal",
            "terminator",
            "alacritty",
            "xterm",
        ]

        for term in terminals:
            term_path = shutil.which(term)
            if not term_path:
                print(f"[launcher] '{term}' not found on PATH, skipping.")
                continue

            try:
                if term == "gnome-terminal":
                    cmd = [term, "--"] + args
                elif term in ("xfce4-terminal", "qterminal"):
                    safe_command = " ".join(
                        shlex.quote(arg) for arg in args
                    )
                    cmd = [term, "-e", safe_command]
                else:
                    cmd = [term, "-e"] + args

                print(f"[launcher] Trying terminal: {cmd}")
                proc = subprocess.Popen(cmd, close_fds=True)
                print(f"[launcher] Launched {term} (pid={proc.pid})")
                break

            except Exception as e:
                print(f"[launcher] Failed to launch {term}: {e}")
                proc = None

        if proc is None:
            print("Could not find a suitable terminal emulator.")
            print("Running server in the current process instead.")
            run_server_in_process(target_folder)
            return None

    return proc
    
def main():
    if len(sys.argv) > 1:
        target_folder = sys.argv[1]
        if getattr(sys, 'frozen', False):
            attach_console()
        if sys.platform == "win32":
            os.system(f"title WiFi Server - {target_folder}")
        run_server_in_process(target_folder)
    else:
        folder = open_folder_picker()
        if folder and _is_termux():
            run_server_in_process(folder)
        elif folder:
            proc = launch_server_process(folder)
            
            if proc:
                proc.wait()  # Linux/Windows wait
            elif platform.system() == "Darwin":
                # macOS asynchronous wait workaround
                time.sleep(2) # Give osascript time to launch the new terminal
                exe_name = os.path.basename(sys.executable)
                
                while True:
                    try:
                        # Check if the binary is still running with the target_folder argument
                        output = subprocess.check_output(["ps", "aux"], text=True)
                        if exe_name in output and folder in output:
                            time.sleep(2)
                        else:
                            break
                    except Exception:
                        break
        sys.exit()

if __name__ == "__main__":
    main()
