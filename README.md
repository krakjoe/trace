trace
=====

This is a WIP and research SAPI for tracing PHP 7 processes

 * It is inspired by phpspy
 * It is extremely unfinished and not useful to deploy

Requirements
------------

 * libelf
 * libdw
 * binary with executor_globals not stripped
 * NTS

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
|:--------------|:----------------------|:-------:|
|`p`/`process`  | Set target process    |         |
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
