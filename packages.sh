#!/bin/bash

QUIET=0
LINUX_PACKAGE_MANAGER="apt-get"
install_linux_packages() {
    # Install required packages
    PACKAGES="python3 python3-pip wget curl sqlite3 libsqlite3-dev cmake gcc libmariadb-dev mariadb-client jq"
    which ${LINUX_PACKAGE_MANAGER} &> /dev/null
    if [ $? != 0 ]; then
        printf "${RED}Could not find ${LINUX_PACKAGE_MANAGER} command.\\nPlease specify your package manager at the start of the script.\\n${SANE}"
        exit 1
    fi

    if [ $QUIET != 1 ]; then
        sudo ${LINUX_PACKAGE_MANAGER} update
    else
        sudo ${LINUX_PACKAGE_MANAGER} update >/dev/null
    fi
    if [ $? != 0 ]; then
        printf "${RED}Installation of ${LINUX_PACKAGE_MANAGER} packages was not successful.\\n${SANE}"
        exit 1
    fi

    if [ ${QUIET} != 1 ]; then
        sudo ${LINUX_PACKAGE_MANAGER} -y install ${PACKAGES}
    else
        sudo ${LINUX_PACKAGE_MANAGER} -y install ${PACKAGES} >/dev/null
    fi
    if [ $? != 0 ]; then
        printf "${RED}Installation of ${LINUX_PACKAGE_MANAGER} packages was not successful.\\n${SANE}"
        exit 1
    fi

    pip3 install -r requirements.txt
    if [ $? != 0 ]; then
        pip3 install -r requirements.txt --break-system-packages
    fi

    pip3 install mariadb
    if [ $? != 0 ]; then
        pip3 install mariadb --break-system-packages
    fi
}



printf "${GREEN}[+] Installing ${LINUX_PACKAGE_MANAGER} packages\\n${SANE}"
install_linux_packages
sudo ln -sf "$(pwd -P)/search_vulns.py" /usr/local/bin/search_vulns
