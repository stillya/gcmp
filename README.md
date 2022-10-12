# gcmp - custom ICMP protocol for CTF-task

It contains two commands:
- ***server*** - start up icmp-server with custom ```NuclearProtocol``` handling.
``` bash
  sudo ./gcmp server [server-OPTIONS]
```
- ***client*** - send ICMP-request with encaplsulated ```NuclearProtocol``` frame.
``` bash
  sudo ./gcmp client [client-OPTIONS]
```

```
Help Options:
  -h, --help      Show this help message

[server command options]
          --addr= address of interface
          --code= code for authentication purposes
      -f, --flag= flag for CTF (default: flag{I_am_the_nuclear_bomb})
      
[client command options]
          --addr= address of server
          --code= code for authentication purposes
          --cmd=  server command
```
