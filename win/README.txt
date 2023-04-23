	Windows DLL Build instructions using nmake build system
	2020-10-15 Harald.Oehlmann@elmicron.de
	2023-04-23 Brian O'Hagan

Properties:
- 64 bit DLL
- VisualStudio 2015
Note: Visual C++ 6 does not build OpenSSL (long long syntax error)
- Cygwin32 (temporary helper, please help to replace by tclsh)
- OpenSSL statically linked to TCLTLS DLL.
Note: Dynamic linking also works but results in a DLL dependency on OPENSSL DLL's

1) Build OpenSSL static libraries:

(1a) Get OpenSSL
  https://github.com/openssl/openssl/releases/download/OpenSSL_1_1_1t/openssl-1.1.1t.tar.gz

  OpenSSL source distribution unpacked in:
  C:\Users\Brian\Documents\Source\Build\openssl-1.1.1t

(1b) Install Perl from https://strawberryperl.com/
  https://strawberryperl.com/download/5.32.1.1/strawberry-perl-5.32.1.1-64bit.msi
  to C:\Strawberry\perl
  (ActivePerl failed due to missing 32 bit console module)

(1c) Install NASM Assembler from https://www.nasm.us/
  https://www.nasm.us/pub/nasm/releasebuilds/2.16.01/win64/nasm-2.16.01-installer-x64.exe
  to C:\Program Files\NASM

(1d)
- Configure
  At Visual Studio x86 native prompt:

set Path=%PATH%;C:\Program Files\NASM;C:\Strawberry\perl\bin

perl Configure VC-WIN32 --prefix=c:\test\tcltls\openssl --openssldir=c:\test\tcltls\openssldir no-shared no-filenames threads
perl ..\Configure VC-WIN64A no-asm no-ssl3 no-zlib no-comp no-ui-console no-autoload-config --api=1.1.0 --prefix="%installdir%" --openssldir="%commoninstalldir%" -DOPENSSL_NO_DEPRECATED


nmake
nmake test
nmake install

2) Build TCLTLS

2a) Unzip distribution in:
C:\Users\Brian\Documents\Source\Build\tcltls-b5c41cdeb6

2b) Start BASH shell (MinGW62 Git shell)

cd /c/Users/Brian/Documents/Source/Build/tcltls-b5c41cdeb6
./gen_dh_params > dh_params.h

od -A n -v -t xC < 'tls.tcl' > tls.tcl.h.new.1
sed 's@[^0-9A-Fa-f]@@g;s@..@0x&, @g' < tls.tcl.h.new.1 > tls.tcl.h
rm -f tls.tcl.h.new.1

2c) Start Visual Studio shell

cd C:\Users\Brian\Documents\Source\Build\tcltls-b5c41cdeb6\win

nmake -f makefile.vc TCLDIR=c:\test\tcl8610 SSL_INSTALL_FOLDER=C:\test\tcltls\openssl

nmake -f makefile.vc install TCLDIR=c:\test\tcl8610 INSTALLDIR=c:\test\tcltls SSL_INSTALL_FOLDER=C:\test\tcltls\openssl

3) Test

Start tclsh or wish

package require tls
package require http
http::register https 443 [list ::tls::socket -autoservername true]
set tok [http::data [http::geturl https://www.tcl-lang.org]]
::http::cleanup $tok
