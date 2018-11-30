# sysu-h3c
A H3C 802.1X authentication client for Sun Yat-sen University east campus 
on linux platform (Ubuntu, Debian, OpenWrt, etc on x86 , ARM, MIPS, etc). 
Replacement of the official iNode client provided by SYSU Network and 
information technology center as the iNode client is bloated, bringing 
lots dependency libraries and cannot be uninstalled completely with the 
dependency libraries it brings by the uninstall script.

## Inspiration
Project [renbaoke/h3c](https://github.com/renbaoke/h3c), which provide 
basic function to get network access authorization in SYSU east campus.

## Motivation
Implement a program which not only provides basic function like 
[renbaoke/h3c](https://github.com/renbaoke/h3c), but also runs with less 
manual intervention. 
For example, [renbaoke/h3c](https://github.com/renbaoke/h3c) can get 
authorization form server and keep it alive, but cannot request IP address 
form the DHCP server when the authentication is success, so that the host 
might still cannot surf the Internet until some mechanisms cause a DHCP 
request to DHCP server. 
Besides, [renbaoke/h3c](https://github.com/renbaoke/h3c) has no 
reconnection mechanism, so that manual intervention is needed when it 
gets offline.
In my opinion ,the [renbaoke/h3c](https://github.com/renbaoke/h3c) doesn't 
divide different kinds of function into different module. Once a big 
change happens in the authentication process of H3C authorization service, 
the code will need significant modifications. If someone add features to 
it, the codes will become more difficult to read.
[sysu-h3c](https://github.com/KryptonLee/sysu-h3c) refactors the code of 
[renbaoke/h3c](https://github.com/renbaoke/h3c), and add features like 
re-authentication after recovery from network outage, and requesting IP 
from DHCP server after authentication success.

## Install
Use git to clone the source code from github and checkout a specified
version from tag (for example, v0.1.0).
```
git clone https://github.com/KryptonLee/sysu-h3c.git
git checkout v0.1.0
```
Go to the root diretory of the source code.
```
cd sysu-h3c
```
**For Debian & Ubuntu**
```
make clean && make
sudo make install
```
**For DietPi 6.16 (Debian 9.0) for ARM devices**
```
make clean && make && make install
```
**For macOS**
```
make clean && make && make install
```
**For CentOS**
```
make clean && make && make install
```
**For other OS**
<br>Not test...

## License
This software is licensed under the GNU General Public License v3.0.
To learn more information, see 
[./LICENSE](https://github.com/KryptonLee/sysu-h3c/blob/master/LICENSE).
