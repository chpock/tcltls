#!/bin/sh
# The next line is executed by /bin/sh, but not tcl \
exec tclsh "$0" ${1+"$@"}

set auto_path [linsert $auto_path 0 [file normalize [file join [file dirname [info script]] ..]]]
package require tls

set s [tls::socket 127.0.0.1 12300]
puts $s "A line"
flush $s
puts [join [tls::status $s] \n]
exit
