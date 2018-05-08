This analyzer extends the open-source Cuckoo Sandbox (legacy) with functionality for analyzing macOS malware in macOS guest VM(s).


See [Mac-A-Mal](https://github.com/phdphuc/mac-a-mal) for kernel monitor module on guest machine.


## Installation
### Host setup

1. Clone the [cuckoo-legacy branch](https://github.com/cuckoosandbox/cuckoo.git)

2. Run the following command to install the requirements packages:

sudo pip install -r requirements.txt

3. Clone [Mac-a-mal-cuckoo](https://github.com/phdphuc/mac-a-mal-cuckoo.git)

5. Replace subfolders in cuckoo-legacy with mac-a-mal-cuckoo's subfolders.

6. Setting up VMWare/VirtualBox configuration in `conf/` folder.

6. Start cuckoo
`python ./cuckoo.py`

7. Skip to guest setup and return to this step after you've done with Guest virtual machine installation. Submit samples with sample's path and optional options: **runas** _username_ instead of _root_, **gctimeout** timeout for kernel-mode macamal monitor, and **timeout** for total analysis time.
`python submit.py --platform darwin sample -o runas=admin,gctimeout=60 --timeout=600`
## Guest setup

macOS versions supported 10.6, 10.7, 10.8, 10.9, 10.10, 10.11, 10.12, and 10.13 (untested)

 1. Guest machine can be setup manually using VMWare or VirtualBox. ([OSX 10.8](https://drive.google.com/file/d/0BxBVjisqLRIrSTRySWJJUUlRZm8/view) - password: summer)
 [Documentation]( https://github.com/rodionovd/cuckoo-osx-analyzer/wiki/Setting-up-the-environment ) for setting up the environment.
 2. Download the Mac-a-mal for [guest machine monitor](https://github.com/phdphuc/mac-a-mal), compile 2 binaries using Xcode: mac-a-mal.kext and grey-cuckoo. The agent in user-mode requires libevent for multithreading.
 3. Install dependencies:
 ```
 sudo pip install pymongo
 brew install libtiff libjpeg webp little-cms2
 pip install Pillow
 ```
 4. Start the monitor and agent in super-user privilege is recommended. 
 
``` homebrew libevent &&
 sudo chown -R root:wheel mac-a-mal.kext &&
 sudo kextload mac-a-mal.kext &&
 cp grey-cuckoo /tmp/&&
 sudo chown root:wheel /tmp/grey-cuckoo &&
 sudo python ./agent.py
 ```
 
5. Take the snapshot of the guest machine

## Credits

[Sfylabs](http://sfylabs.com)
