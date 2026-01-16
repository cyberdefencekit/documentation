# **Velociraptor**

Velociraptor is an advanced digital forensic and incident response tool that enhances your visibility into your endpoints.

<iframe width="560" height="315" src="https://www.youtube.com/embed/T75Fo0NoqVE?si=KptUGLEzR25iua1b" title="YouTube video player" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share" referrerpolicy="strict-origin-when-cross-origin" allowfullscreen></iframe>

## **Lab Setup for Proof of Concept**

In this proof of concept, the Velociraptor server was configured on an Ubuntu virtual machine (VM), and the Velociraptor client was configured on a Windows VM. An attack simulation was conducted on the Windows hosts using a Kali machine in a safe and controlled setting.

**Note: Do not attempt to replicate the attack emulation demonstrated here unless you are properly trained and it is safe to do so. Unauthorised attack emulation can lead to legal consequences and unintended damage to systems. Always ensure that such activities are conducted by qualified professionals in a secure, isolated environment.**

| **Host** | **OS** | **Role** | **IP Address** |
| --- | --- | --- | --- |
| Fortigate | Fortios 7.6.0 | Firewall/Router | 192.168.1.111 (WAN) / 10.0.0.1 (LAN) |
| WazuhServer | Ubuntu 22.04 LTS | Velociraptor Server | 10.0.0.20 |
| WS2019 | Windows Server 2019 | Velociraptor Client | 10.0.0.40 |
| Kali | Kali Linux 2024.2 | Attacker machine | 10.0.0.22 |

![Velociraptor.drawio.png](Velociraptor.drawio.png)

## **Deploy Velociraptor Server (Linux)**

The Velociraptor server will be set up to use self-signed SSL certificates and Basic authentication, which is a fairly straightforward configuration option.

In `self-signed SSL` mode, Velociraptor issues its own server certificate using its internal CA. This means the Admin GUI and front end also use a self-signed server certificate.

### **Download the Velociraptor binaries**

Download the latest Velociraptor binary that is compatible for your host architecture from [https://github.com/Velocidex/velociraptor/releases](https://github.com/Velocidex/velociraptor/releases).

Before starting the setup, it’s a good idea to create a fresh working directory to use for the pre-installation tasks.

```bash
mkdir ~/velociraptor_setup && cd ~/velociraptor_setup
```

Copy the download link for the latest release that matches your server’s platform and architecture, then use it in the `wget` command below. This will download the binary and save it as **velociraptor**.

```bash
wget -O velociraptor https://github.com/Velocidex/velociraptor/releases/download/v0.75/velociraptor-v0.75.6-linux-amd64
```

Next, make the downloaded file executable:

```bash
chmod +x velociraptor
```

### **Create the server configuration file**

To create a new configuration file, we use the `config generate` command. The `-i` flag runs the process in interactive mode, launching a question-and-answer style wizard that collects the key details needed to build your configuration.

```bash
./velociraptor config generate -i
```

In the configuration wizard, select the options outlined below. For any other prompts, just accept the default settings.

**Deployment Type:** Self-signed SSL

**Public DNS name of the Master Frontend:** Enter the server’s IP address (or a DNS name, if you’ve set one up) that clients will use to connect to the server.

On the fourth screen of the configuration wizard, you’ll be asked to create an admin user. Enter a username and password for the initial admin account, which will be used to access the web interface. You only need one admin at this stage, as additional users can be added later. After creating the first admin user, leave the next username and password blank to continue.

In the last step of the configuration wizard, you’ll be asked to save the config file to your working directory. You can stick with the default filename and the wizard will then close.
**Name of file to write:** server.config.yaml

By default, the configuration binds the GUI and Frontend services to the loopback address (127.0.0.1), meaning they’re only accessible from the local machine. To allow access from other hosts on the network, you’ll need to update the configuration file.

Open the config file in a text editor and change:

```bash
Frontend:
  bind_address: 127.0.0.1
```

to:

```bash
Frontend:
  bind_address: 0.0.0.0
```

If you need to access the GUI from a different network host then also change:

```bash
GUI:
  bind_address: 127.0.0.1
```

to:

```bash
GUI:
  bind_address: 0.0.0.0
```

When using self-signed SSL, which only supports Basic authentication, you should avoid exposing the GUI to untrusted networks such as the public internet. If the server must be reachable from the internet, keep `GUI.bind_address` set to the loopback interface and access the GUI via SSH local port forwarding, which can be protected with stronger authentication.

### **Create the server installation package**

To create the server installation package, run the appropriate command below in your working directory.

**Debian-based server:**

```bash
./velociraptor debian server --config ./server.config.yaml
```

```bash
#Example Output
velouser@Velociraptor:~/velociraptor_setup$ ./velociraptor debian server --config ./server.config.yaml
[
 {
  "OSPath": "/home/velouser/velociraptor_setup/velociraptor-server-0.75.6.amd64.deb"
 }
```

**RPM-based server:**

```bash
./velociraptor rpm server --config ./server.config.yaml
```

The output file is automatically named to include the version and architecture, but you can use any filename you like by specifying it with the `--output <your_file_name>` option.

### **Install the server component**

Install the server package using the command below according to your server’s packaging system.

**Debian-based server installation:**

```bash
sudo dpkg -i velociraptor-server-0.75.6.amd64.deb
```

```bash
#Example Output
velouser@Velociraptor:~/velociraptor_setup$ sudo dpkg -i velociraptor-server-0.75.6.amd64.deb
Selecting previously unselected package velociraptor-server.
(Reading database ... 150772 files and directories currently installed.)
Preparing to unpack velociraptor-server-0.75.6.amd64.deb ...
Unpacking velociraptor-server (0.75.6) ...
Setting up velociraptor-server (0.75.6) ...
info: Selecting GID from range 100 to 999 ...
info: Adding group `velociraptor' (GID 124) ...
info: Selecting UID from range 100 to 999 ...

info: Adding system user `velociraptor' (UID 122) ...
info: Adding new user `velociraptor' (UID 122) with group `velociraptor' ...
info: Not creating home directory `/etc/velociraptor'.
Created symlink /etc/systemd/system/multi-user.target.wants/velociraptor_server.service → /etc/systemd/system/velociraptor_server.service.
```

**RPM-based server installation:**

```bash
sudo rpm -Uvh velociraptor-server-0.75.6.x86_64.rpm
```

Now that the service is installed, there are a few ways you can check its status.

**Check the service status:**

```bash
systemctl status velociraptor_server.service
```

```bash
#Example Output
● velociraptor_server.service - Velociraptor server
     Loaded: loaded (/etc/systemd/system/velociraptor_server.service; enabled; preset: enabled)
     Active: active (running) since Fri 2026-01-16 22:42:21 NZDT; 58s ago
   Main PID: 4399 (velociraptor)
      Tasks: 15 (limit: 4545)
     Memory: 86.6M (peak: 88.0M)
        CPU: 3.036s
     CGroup: /system.slice/velociraptor_server.service
             ├─4399 /usr/local/bin/velociraptor --config /etc/velociraptor/server.config.yaml frontend
             └─4407 /usr/local/bin/velociraptor --config /etc/velociraptor/server.config.yaml frontend

Jan 16 22:42:21 Velociraptor systemd[1]: Started velociraptor_server.service - Velociraptor server.
```

**Check that the GUI is listening:**

```bash
nc -vz 127.0.0.1 8889
```

```bash
#Example Output
velouser@Velociraptor:~/velociraptor_setup$ nc -vz 127.0.0.1 8889
Connection to 127.0.0.1 8889 port [tcp/*] succeeded!
```

**Check that the Frontend is listening:**

```bash
nc -vz 127.0.0.1 8000
```

```bash
#Example Output
velouser@Velociraptor:~/velociraptor_setup$ nc -vz 127.0.0.1 8000
Connection to 127.0.0.1 8000 port [tcp/*] succeeded!
```

### **Log in to the Admin GUI**

The Admin GUI should now be reachable in a web browser at `https://127.0.0.1:8889`, or via the server’s IP address if you updated the `GUI.bind_address` setting earlier. Log in using the admin account you created during the configuration wizard, and you’ll be taken to the Welcome screen.

![image.png](image.png)

![image.png](image%201.png)

### **Import artifacts from external projects**

This step only applies if you are using version 0.75 or above. For older versions you can skip to the next step .
Over time, Velociraptor has grown a number of separate sub-projects to handle larger and more complex artifacts. As these artifacts became more advanced, they were split out from the main project so they could be developed and maintained independently, allowing faster updates and innovation.

While Velociraptor includes hundreds of built-in artifacts, it’s recommended that you also use these external projects. Built-in artifacts usually focus on very specific tasks, whereas the larger projects are designed for broader investigations, such as wide-scale registry or indicator hunting.

| **Project** | **Description** |
| --- | --- |
| [Velociraptor Sigma Project](https://sigma.velocidex.com/) | Artifacts that implement Sigma-based triage and monitoring rules. Includes curated Sigma Rules (Hayabusa/Hayabusa Live/ChopChopGo) |
| [Velociraptor Triage Project](https://triage.velocidex.com/) | This project intends to develop a set of rules that are used for specifying the collection of files from the endpoint. |
| [Rapid7Labs](https://github.com/rapid7/Rapid7-Labs/tree/main/Vql) | Artifacts developed and shared by [Rapid7 Labs](https://www.rapid7.com/blog/tag/research/) . |
| [Velociraptor Registry Hunter Project](https://registry-hunter.velocidex.com/) | Velociraptor project to develop sophisticated registry analysis modules. |
| [Velociraptor SQLite Hunter Project](https://sqlitehunter.velocidex.com/) | This project aims to be a one-stop shop for `SQLite`, `ESE` and many other database-oriented forensic artifacts. |
| [The Velociraptor Artifact Exchange](https://docs.velociraptor.app/exchange/) | Velociraptor repository of community-contributed artifacts. |

From the Welcome screen, click **Import Extra Artifacts**. This will launch the artifact collection wizard for the server artifact `Server.Import.Extras`. Click **Configure Parameters** to move to that section of the wizard.

![image.png](image%202.png)

By default, `Server.Import.Extras` will import artifacts from all sub-projects. You don’t have to import everything straight away though, as you can run this process again later to add or update specific artifacts. To remove an item, click the bin icon next to it. Once you’re happy with your selection, click **Launch** to start the import.

![image.png](image%203.png)

Once the collection finishes, you can view the outcome in the **Results** tab. If the import fails for any reason, check the **Log** tab for more details.

![image.png](image%204.png)

## **Deploying Velociraptor Clients (Windows)**

### **Option 1: Create an installation package for Windows clients**

In the Velociraptor web GUI select **Server Artifacts** from the sidebar on the left side of the page.

![image.png](image%205.png)

Add a new collection (”+” icon). Search for `Server.Utils.CreateMSI`, select it, and then click “Launch”.

![image.png](image%206.png)

It may take a short while to download the latest MSI releases from GitHub (64-bit and, if selected, 32-bit) and repackage them with your client configuration. Once complete, the rebuilt MSI files will be available in the **Uploaded Files** tab of the collection.

![image.png](image%207.png)

Download the MSI files, then double-click the installer to install the client.

![image.png](image%208.png)

If prompted by Windows SmartScreen, click **More info**, then select **Run anyway**.

![image.png](image%209.png)

Navigate to `C:\Program Files\Velociraptor`. After a successful installation, you should see `velociraptor.writeback.yaml` in that directory.

![image.png](image%2010.png)

### **Option 2: Download official release MSI**

Download the latest Velociraptor MSI from the [Velociraptor GitHub releases page](https://github.com/Velocidex/velociraptor/releases/tag/v0.75). On your Windows host, double-click the MSI to install it.

Once installed, navigate to `C:\Program Files\Velociraptor` and delete the existing default `client.config.yaml` file.

The easiest way to obtain the correct client config file is to download it directly from the GUI. From the Home screen, go to **Current Orgs** and click the filename to download the YAML file.

![image.png](image%2011.png)

Copy the downloaded `client.config.yaml` into `C:\Program Files\Velociraptor`.

After this, you should see `velociraptor.writeback.yaml` appear in the same directory. If it doesn’t appear, restart the computer.

![image.png](image%2010.png)

## **Verify client connection**

On the Velociraptor Server web GUI, click on the magnifying glass icon and verify that your client is connected.

Any client that has successfully enrolled will show a green light.

![image.png](image%2012.png)

## **Introduction to Velociraptor**

### **Creating a Process Hunt**

A Windows reverse shell named `1.exe` was generated and executed on the Windows Server 2019 host, connecting to the Kali machine. The session was then switched from Command Prompt to PowerShell.

```bash
[*] Started reverse TCP handler on 10.0.0.22:4444 
[*] Command shell session 1 opened (10.0.0.22:4444 -> 10.0.0.40:49886) at 2024-09-18 19:56:51 -0400

Shell Banner:
Microsoft Windows [Version 10.0.17763.3650]
-----       

C:\Users\Administrator\Downloads>whoami
whoami
ws2019\administrator

C:\Users\Administrator\Downloads>powershell
powershell
Windows PowerShell 
Copyright (C) Microsoft Corporation. All rights reserved.

```

Create New Hunt by clicking Hunt icon and + icon

In the Configure Hunt tab, add the description Process Hunt

![image.png](image%2013.png)

In the Select Artifacts tab, search for pstree. Select `Generic.System.Pstree`

This artifact displays the call chain for every process on the system by traversing the process’s parent ID.

![image.png](image%2014.png)

In the same tab, search for pslist and select `Windows.System.Pslist`

This artifact list processes and their running binaries

![image.png](image%2015.png)

In the Configure Parameters tab, Edit `Generic.system.Pstree`

Select IncludePstree

![image.png](image%2016.png)

Select Review then Launch. Select the Hunt and click Play button to launch it.

![image.png](image%2017.png)

Once the Hunt is complete (indicated by Total schedules and Finished clients), click the stop button to stop the Hunt.

Check the results on the Notebook tab on web GUI.

As shown in the screenshot below, the suspicious activity is detected. 

![image.png](image%2018.png)

Alternatively, if you prefer to Download Results as a CSV file and view it in an Excel, this can be done in the Results Section > Download Results

### **Adding Client Labels**

To create a label, click the magnifying glass icon, select the target host, then click the label icon. Name the new label (e.g., `windows`).

![image.png](image%2019.png)

Verify that the label has been created.

![image.png](image%2020.png)

### **Creating a Filename Search Hunt**

A malicious PowerShell script called `justascript.ps1` was created then removed on Windows client. 

Create a new hunt with the description `Filename search`

For Include Condition, select `Match by label`

For Include Labels, select `windows`

![image.png](image%2021.png)

On the Select Artifacts tab, type `filename` and select `Windows.Forensics.FilenameSearch`

![image.png](image%2022.png)

On the Configure Parameters tab, click spanner icon to configure.

In the yaraRule, replace `my secret fie.txt` with `justascript.ps1` 

![image.png](image%2023.png)

Select Review then Launch. Run hunt by clicking the play icon. Once the hunt is finished, stop the hunt by clicking the stop icon. View results in the Notebook tab. Velociraptor detects that the script is in the Recycle bin. 

![image.png](image%2024.png)

### **Creating a Hash Hunt**

Mimikatz is a tool used to find and steal passwords from Windows computers. The `mimikatz.exe` was copied over to Windows client and have been renamed as `justanexe.exe`.

Create a new hunt with the description `Hash Hunt`

For Include Condition, select `Match by label`

For Include Labels, select `windows`

![image.png](image%2025.png)

On the Select Artifacts tab, type `hash` and select `Generic.Detection.HashHunter`

![image.png](image%2026.png)

On the Configure Parameters tab, click spanner icon to configure.

On SHA256List, copy and paste sha256 hash of mimikatz.exe `61c0810a23580cf492a6ba4f7654566108331e7a4134c968c2d6a05261b2d8a1`

![image.png](image%2027.png)

Select Launch. Run hunt by clicking the play icon. Once the hunt is finished, stop the hunt by clicking the stop icon. View results in the Notebook tab. Velociraptor matches the SHA256 hash with `justanexe.exe`

![image.png](image%2028.png)

## **References**

- https://docs.velociraptor.app/
- https://www.youtube.com/watch?v=p9pQ2g-18o4&t=590s
- https://youtu.be/-bj0c158Wlo?si=Gms_VnVyWe-LufOZ
- https://www.youtube.com/watch?v=S8POUZv7pT8
- https://www.youtube.com/watch?v=M7bMfdmWR7A
- https://github.com/Velocidex/velociraptor/releases/tag/v0.72