import tkinter as tk
from tkinter.scrolledtext import ScrolledText
import subprocess
import os
import sys
import threading
from queue import Queue, Empty
import time

# --- Configuration ---
VENV_NAME = "venv"
REQUIREMENTS_FILE = "requirements.txt"
APP_FILE = "core/app.py"


# --- End Configuration ---

class TextHandler:
    """A class to handle writing to a Tkinter Text widget."""

    def __init__(self, text_widget):
        self.text_widget = text_widget

    def write(self, s):
        self.text_widget.insert(tk.END, s)
        self.text_widget.see(tk.END)

    def flush(self):
        pass  # Required for file-like object interface


class AppLauncher(tk.Tk):
    """A Tkinter GUI for launching and monitoring a Python web application."""

    def __init__(self):
        super().__init__()
        self.title("App Launcher & Server Log")
        self.geometry("800x600")

        self.log_widget = ScrolledText(self, wrap=tk.WORD, bg="black", fg="white", font=("Courier New", 10))
        self.log_widget.pack(expand=True, fill=tk.BOTH)

        self.start_button = tk.Button(self, text="Start Application", command=self.start_app_thread,
                                      font=("Segoe UI", 10))
        self.start_button.pack(pady=10)

        # Redirect stdout and stderr to the log widget
        sys.stdout = TextHandler(self.log_widget)
        sys.stderr = TextHandler(self.log_widget)

        self.log("Launcher initialized.")
        self.log("Please ensure all custom modules (config, utils, engines) are in the same directory.")
        self.log(f"Ready to start '{APP_FILE}'.")

    def log(self, message):
        """Logs a message to the log widget."""
        print(f"[{time.strftime('%H:%M:%S')}] {message}\n")

    def detect_environment(self):
        """Detects the current Python environment."""
        self.log("Detecting environment...")
        if "PYCHARM_HOSTED" in os.environ:
            self.log("Environment: PyCharm")
            return "pycharm"
        elif "CONDA_PREFIX" in os.environ:
            self.log("Environment: Conda")
            return "conda"
        else:
            self.log("Environment: Standard CLI")
            return "cli"

    def setup_environment(self):
        """Sets up the virtual environment and installs dependencies."""
        self.log("Setting up environment...")
        env = self.detect_environment()

        if env in ["cli", "pycharm"]:
            if not os.path.exists(VENV_NAME):
                self.log(f"Creating virtual environment: {VENV_NAME}")
                subprocess.run([sys.executable, "-m", "venv", VENV_NAME], check=True, capture_output=True)

            python_executable = os.path.join(VENV_NAME, "Scripts" if sys.platform == "win32" else "bin", "python")
            pip_executable = os.path.join(VENV_NAME, "Scripts" if sys.platform == "win32" else "bin", "pip")

            if not os.path.exists(REQUIREMENTS_FILE):
                self.log(f"ERROR: '{REQUIREMENTS_FILE}' not found. Cannot install dependencies.")
                return None

            self.log("Installing/updating dependencies from requirements.txt...")
            subprocess.run([pip_executable, "install", "-r", REQUIREMENTS_FILE], check=True, capture_output=True)
            self.log("Dependencies are up to date.")
            return python_executable

        elif env == "conda":
            self.log("Conda environment detected. Assuming dependencies are managed by Conda.")
            self.log("Please ensure required packages from requirements.txt are installed in your Conda environment.")
            return sys.executable

        return None

    def start_app_thread(self):
        """Starts the Flask application in a separate thread."""
        self.start_button.config(state=tk.DISABLED, text="Application Running...")
        self.log("Starting application thread...")
        threading.Thread(target=self.run_app, daemon=True).start()

    def run_app(self):
        """Runs the Flask application."""
        try:
            python_executable = self.setup_environment()
            if not python_executable:
                self.log("Environment setup failed. Aborting application start.")
                self.start_button.config(state=tk.NORMAL, text="Start Application")
                return

            self.log(f"Starting {APP_FILE} with {python_executable}...")

            # --- FIX: Added encoding='utf-8' and errors='replace' to handle Unicode ---
            process = subprocess.Popen(
                [python_executable, APP_FILE],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
                universal_newlines=True,
                encoding='utf-8',
                errors='replace'
            )

            # Non-blocking read from stdout and stderr
            def reader_thread(pipe, queue):
                try:
                    with pipe:
                        for line in iter(pipe.readline, ''):
                            queue.put(line)
                finally:
                    queue.put(None)

            q_stdout = Queue()
            q_stderr = Queue()

            threading.Thread(target=reader_thread, args=[process.stdout, q_stdout], daemon=True).start()
            threading.Thread(target=reader_thread, args=[process.stderr, q_stderr], daemon=True).start()

            def poll_queues():
                # Check if the process is still running
                if process.poll() is not None:
                    # Process has terminated, read any remaining output
                    while not q_stdout.empty():
                        line = q_stdout.get_nowait()
                        if line: self.log(f"[APP-STDOUT] {line.strip()}")
                    while not q_stderr.empty():
                        line = q_stderr.get_nowait()
                        if line: self.log(f"[APP-STDERR] {line.strip()}")

                    self.log("Application process has terminated.")
                    self.start_button.config(state=tk.NORMAL, text="Start Application")
                    return  # Stop polling

                # Process is running, read available output
                try:
                    while True:  # Read all available lines
                        line = q_stdout.get_nowait()
                        if line is None: break
                        self.log(f"[APP-STDOUT] {line.strip()}")
                except Empty:
                    pass

                try:
                    while True:  # Read all available lines
                        line = q_stderr.get_nowait()
                        if line is None: break
                        self.log(f"[APP-STDERR] {line.strip()}")
                except Empty:
                    pass

                # Schedule the next poll
                self.after(100, poll_queues)

            # Start the first poll
            self.after(100, poll_queues)

        except subprocess.CalledProcessError as e:
            self.log(f"An error occurred during environment setup: {e}")
            self.log(f"STDOUT: {e.stdout}")
            self.log(f"STDERR: {e.stderr}")
            self.start_button.config(state=tk.NORMAL, text="Start Application")
        except Exception as e:
            self.log(f"An unexpected error occurred while trying to run the application: {e}")
            self.start_button.config(state=tk.NORMAL, text="Start Application")


if __name__ == "__main__":
    app_launcher = AppLauncher()
    app_launcher.mainloop()
