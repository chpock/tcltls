	Windows DLL Build instructions using nmake build system
	2020-10-15 Harald.Oehlmann@elmicron.de
	2023-08-22 Kevin Walzer (kw@codebykevin.com)

Properties:
- 64 bit DLL
- VisualStudio 2019
- WSL 
- OpenSSL dynamically linked to TCLTLS DLL. We used a freely redistributable build of OpenSSL from https://www.firedaemon.com/firedaemon-openssl. Unzip and install OpenSSL in an accessible place (we used the lib subdirectory of our Tcl installation).

1. Visual Studio x86 native prompt. Update environmental variables for building Tcltls. Customize the below entries for your setup. 

set PATH=%PATH%;C:\tcl-trunk\lib\openssl-3\x64\bin
set INCLUDE=%INCLUDE%;C:\tcl-trunk\tcl\lib\openssl-3\x64\include\openssl
set LIB=%LIB%;C:\tcl-trunk\tcl\lib\openssl-3\x64\bin


2) Build TCLTLS

-> Unzip distribution on your system. 
-> Start WSL.
-> cd /mnt/c/path/to/tcltls

./gen_dh_params > dh_params.h

od -A n -v -t xC < 'tls.tcl' > tls.tcl.h.new.1
sed 's@[^0-9A-Fa-f]@@g;s@..@0x&, @g' < tls.tcl.h.new.1 > tls.tcl.h
rm -f tls.tcl.h.new.1

-> Visual Studio x86 native prompt.

cd C:path\to\tcltls\win

Run the following commands (modify the flags to your specific installations).

nmake -f makefile.vc TCLDIR=c:\users\wordt\tcl INSTALLDIR=c:\tcl-trunk\tcl\lib SSL_INSTALL_FOLDER=C:\tcl-trunk\tcl\lib\openssl-3\x64

nmake -f makefile.vc TCLDIR=c:\users\wordt\tcl INSTALLDIR=c:\tcl-trunk\tcl\lib SSL_INSTALL_FOLDER=C:\tcl-trunk\tcl\lib\openssl-3\x64 install

The resulting installation will include both the tcltls package and also have libcrypto.dll and libssl.dll copied into the same directory. 

3) Test

Start tclsh

package require tls
package require http
http::register https 443 [list ::tls::socket -autoservername true]
set tok [http::data [http::geturl https://www.tcl-lang.org]]