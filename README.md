```
    .___      _____.__
  __| _/_____/ ____\__| ____  ______
 / __ |/ __ \   __\|  |/  _ \/  ___/
/ /_/ \  ___/|  |  |  (  <_> )___ \
\____ |\___  >__|  |__|\____/____  >_____
     \/    \/                    \/_____/
::wazuh-deploy v0.0.1

Usage: ./deploy.sh [-h | -d] {install|start|stop|changePasswords|setBranding|deploy|remove}
  -h  Show this help message
  -d  Enable debug mode
irradiatedcircle@defios:~/defios-security$
```
This script automates the deployment of Wazuh, a popular open-source security monitoring and logging platform, making it easy to set up and configure Wazuh on your Linux system.

## Features

- **Automated Installation:** Downloads and installs the latest Wazuh version inside a docker container.
- **Password Management:** Generates strong passwords for Wazuh components and automatically updates configuration files.
- **Branding Configuration:** Allows you to customize the Wazuh dashboard with your own branding using a `config.json` file.
- **Dependency Management:** Installs required dependencies silently.
- **Error Handling and Logging:** Includes robust error handling and logging for troubleshooting.
- **Command-Line Interface:** Provides a user-friendly command-line interface for easy deployment.

## Usage

1. **Prerequisites:**
   - A Linux system (e.g., Ubuntu, Debian).
   - Root privileges (run the script as root).
   - Docker installed and running.

2. **Download the script:**
   - Download the `deploy.sh` script from this repository.

3. **Customise Wazuh using the `config.json` file:**
   - Edit a file named `config.json` in the branding directory to include your own custom branding.

4. **Run the script:**
   - Make the script executable: `chmod +x deploy.sh`
   - Run the script with the desired command:

     ```bash
     sudo ./deploy.sh install     # Install Wazuh
     sudo ./deploy.sh setBranding  # Configure branding
     sudo ./deploy.sh deploy      # Install and configure
     sudo ./deploy.sh start      # Start Wazuh
     sudo ./deploy.sh stop       # Stop Wazuh
     sudo ./deploy.sh remove      # Remove Wazuh
     ```

5. **View the logs:**
   - The script logs messages to `/var/log/defios-wazuh-deployer.log` for debugging and troubleshooting.

## Contributing

Contributions are welcome! If you find any issues or have suggestions for improvements, please open an issue or submit a pull request.

## License

This script is licensed under GPL-2.0.

## Acknowledgements

- Wazuh: [https://wazuh.com/](https://wazuh.com/)
- `jq`: [https://stedolan.github.io/jq/](https://stedolan.github.io/jq/)

## Disclaimer

This script is provided as-is without warranty of any kind. Use at your own risk.