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
    
Options:

| Option (S/L)  | Purpose               | Default |
|:-------------:|:----------------------|:-------:|
|`p`/`process`  | Set target process    |         |
|`m`/`max`      | Maximum samples       |         |
|`f`/`frequency`| Frequency (sleep)     | 1000    |
|`d`/`depth`    | Maximum stack depth   | 64      |

Your terminal will be filled with backtraces from the target process, or the process will fail, or crash.

SAPI Support
------------

All PHP SAPIs are supported, however, ZTS is not (yet, this should be quite trivial to support).

Untested
--------

I've tested this on one machine, with a couple of builds of PHP ... if you find crashes please open an issue.

Stripped Binaries
-----------------

`php-trace` will work on any *unstripped* build of PHP (debug/no-debug); It's common (apparently) for distros to strip all symbols ...

Should this be merged into PHP, package maintainers will have to amend their build to keep some symbols, still allowing them to strip out the vast majority.

Currently symbols required are:

  * executor_globals

ZTS support may require more symbols to be kept.

*It's possible that installing the dbgsym package may be enough, I haven't done much testing here ...*

TODO
----

  * Don't rely on executor globals
  * Make default handler implement callgrind
  * Make usable API for implementors of tracing tools (started)
  * Research Windows (no ideas, pull in a windows person probably)
  * Research Mac (no ideas)
