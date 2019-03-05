trace
=====

This is a WIP and research SAPI for tracing PHP 7 processes. 

 * It is inspired by phpspy
 * It is currently heavily coupled to libelf/libdw, so only works on linux
 * It is extremely unfinished and not useful to deploy
 
Building
--------

Building this SAPI must be done in source tree of php:

    cd /path/to/php-src
    git clone https://github.com/krakjoe/php-trace sapi/trace
    ./buildconf --force
    ./configure --enable-trace
    ...
    
Executing
---------

Executing php-trace requires root privileges:

    php-trace -p PID
    
Your terminal will be filled with backtraces from the target process, or the process will fail, or crash.

SAPI Support
------------

All PHP SAPIs are supported, however, ZTS is not (yet, this should be quite trivial to support).

Untested
--------

I've tested this on one machine, with a couple of builds of PHP ... if you find crashes please open an issue.

TODO
----

  * Make translation table for classes
  * Make translation of instruction make sense
  * Don't rely on executor globals
  * Make default handler implement callgrind
  * Make usable API for implementors of tracing tools
  * Research Windows (no ideas, pull in a windows person probably)
  * Research Mac (no ideas)
  * Improve command line options (depth, frequency - both fixed currently)
