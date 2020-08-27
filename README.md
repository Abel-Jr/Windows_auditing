# Windows_auditing

The main objective of this project is to write PowerShell script for checks on various
security controls and policies applied on the host machine.
The result can be showed on the standard output or saved on a HTML file that can
be sent to the administrator mailbox.

1. Checking if your PowerShell script execution policy is set to Unrestricted and
change it if necessary. This change will be reverted to its original state after script
execution is complete.

2. Showing operating system, service pack and architecture information.

3. Showing local accounts information, local password policy, security privileges by
user and last login for each user. Write in the log file the expired ones and those
whose password must be changed in less than one week.
Checking for User Account Contol (UAC) settings.

4. Checking directories in PATH environment variable.

5. Enumerating registry autoruns. Retrieving ACLs for winlogon, LSA, secure pipe
servers, knownDLLs, AllowedPATHS, and RPC.

6. Checking for installed security products: product name, virus definition state, size
of threat database, ...

7. Information about the firewall: firewall profile, number of rules, third party
firewalls, ...

Activate firewall logging, check the ACLs on the logging file and show the total
number of packet drops.

8. Checking AppLocker status and policies and checking device guard status.

9. Enumerating exposed local filesystem shares. Start a quick scan on these shares.
Show the file extensions present in each share.

10. Checking BitLocker status on all volumes and permissions on NTFS drives.

11. Enumerating installed certificated and expiring date of each one.

12. Showing the overall execution time of the script.
