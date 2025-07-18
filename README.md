# CyberClause

CyberClause is my initial project for a cybersecurity intelligence platform designed to aggregate, analyze, and present critical cybersecurity information. It aims to provide users with up-to-date insights into vulnerabilities, policies, news, and frameworks.

## Project Structure

This repository contains the following key directories:

-   `api_clients`: Contains modules for interacting with various cybersecurity APIs (e.g., NVD, RSS feeds).
-   `engines`: Houses the core logic for processing and analyzing data, including engines for documentation, frameworks, news, policies, and vulnerabilities.
-   `gui`: Contains components related to the graphical user interface, such as an enhanced CVE viewer.
-   `scripts`: Utility scripts for data export, database maintenance, and performance monitoring.
-   `tests`: Unit and integration tests for various modules.
-   `utils`: Helper utilities, including API management, data storage, and scheduling.

## Getting Started

To get started with CyberClause, you will need the latest version of Python (>=3.7) installed on your system.

> 💡 **No manual setup is required. The launcher will automatically create a virtual environment and install all dependencies.**

### 🔧 Installation

1.  **Clone the repository**:
    ```bash
    git clone https://github.com/mrtimber425/CyberClause.git
    cd CyberClause
    ```

2.  **Run the application** using the appropriate script below.

### 🚀 Running the Application

The primary entry point is `launcher.py`, which provides a GUI and automatically:

- Detects the environment
- Creates a virtual environment (`venv/`) if it doesn’t exist
- Installs all required dependencies from `requirements.txt`
- Starts the application with full log output in the GUI

You can launch the app in two ways:

#### 🪟 On Windows:
Double-click or run:
```bash
launch_app.bat
````

#### 🐧 On macOS/Linux:

Make the script executable and run:

```bash
chmod +x launch_app.sh
./launch_app.sh
```

> Alternatively, to launch manually:
>
> ```bash
> python launcher.py
> ```

No need to run `pip install` or manually set up the virtual environment — it's all automated 🎉

---

### 📜 License

This project is licensed under the MIT License – see the `LICENSE` file for details.
