trace
=====

This is a tracing SAPI for PHP 7 processes, inspired by phpspy, but not as feature full. 

It has one default mode (but is extensible) that prints stack traces from the target process, the target process may be any SAPI on any system that meets requirements.

Requirements
------------

 * libelf
 * libdw
 * NTS 🕇

*🕇 : ZTS is supported if executor_globals address is known and set with -e*

Automatic Build
------------------
    
There exists a `build` script in this repository which helps to produce a working build:

    usage: build [options]
    Options:
        --php-config <path>      path to php-config              (default auto)
        --prefix     <path>      prefix for install              (default auto)
        --build      <path>      build directory                 (default /tmp/php-src-trace)
        --version    <version>   version of PHP to build against (default auto)
        --jobs       <int>       number of jobs to run make with (default 16)

    Notes
    Version may be:
	    a tag in the form of "php-7.3.1"
	    a branch in the form of "PHP-7.3"
    Build directory must be writable by current uid
    Jobs should be set to number of cores available on current machine
    
*Executing `build` with no options should in most cases work.*

Manual Build
------------

Building this SAPI must be done in source tree of php:

    cd /path/to/php-src
    git clone https://github.com/krakjoe/php-trace sapi/trace
    ./buildconf --force
    ./configure --enable-trace [options]
    ...

*Note: the target version of PHP and the version php-trace is built against must match, but the target process may not be from the same build as php-trace*

Executing
---------

Executing php-trace requires root privileges:

    php-trace -p PID
    
Options:

| Option (S/L)  | Purpose               | Default |
|:--------------|:----------------------|:-------:|
|`p`/`process`  | Set target process    |         |
|`e`/`executor` | Set executor address  | auto    |
|`m`/`max`      | Maximum samples       |         |
|`f`/`frequency`| Frequency (sleep)     | 1000    |
|`d`/`depth`    | Maximum stack depth   | 64      |


Flags:

| Flag (S/L)                  | Purpose                                 |
|:----------------------------|:----------------------------------------|
|`s`/`stack`                  | Collect args/vars from stack on frame   |
|`with-array-elements`        | Copy array elements from stack          |
|`with-string-contents`       | Copy string contents from stack         |

Your terminal will be filled with backtraces from the target process.

SAPI Support
------------

All PHP SAPIs are supported.

TODO
----

  * Make usable API for implementors of tracing tools (started)
  * Research Windows (no ideas, pull in a windows person probably)
  * Research Mac (no ideas)
