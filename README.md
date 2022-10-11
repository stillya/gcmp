# gcmp - custom ICMP protocol for CTF-task

It contains two commands:
- ***server*** - start up icmp-server with custom ```NuclearProtocol``` handling.
``` bash
  sudo ./gcmp server --addr 127.0.0.1 --code 0000 -f FLAG{TEST}
```
- ***client*** - send ICMP-request with encaplsulated ```NuclearProtocol``` frame.
``` bash
  sudo ./gcmp client --addr 127.0.0.1 --code 0000 -cmd 3
```
