trace
=====

This is a tracing API for PHP 7 processes, inspired by phpspy.

It has one default mode that prints stack traces from the target process, the target process may be any SAPI on any system that meets requirements.

It installs an API for implementors of tools or interfaces.

Requirements
------------

 * libphp7 (+dev)
 * libelf
 * libdw
 * NTS 🕇 

*🕇 : ZTS is supported if executor_globals address is known and set with -e*

On ubuntu and friends, prerequisites may be installed with

    sudo apt install libelf-dev libdw-dev libphp-embed php-dev
    
*Note: If you are building PHP yourself, use `--enable-embed` configure option.*

Building
--------

`php-trace` uses the CMake build system:

    git clone https://github.com/krakjoe/trace php-trace
    cd php-trace
    mkdir build
    cd build
    cmake ..
    make
    sudo make install
   
CMake will attempt to find all prerequisites and configure the build automatically, you may override the defaults:

| Option                | Purpose                      | Default |
|:----------------------|:-----------------------------|:-------:|
| `CMAKE_BUILD_TYPE`    | Set Debug/Release build type | auto    |
| `CMAKE_INSTALL_PREFIX`| Set installation prefix      | auto    |
| `PHP_CONFIG`          | Set path to php-config       | auto    |
| `PHP_TRACE_LIBPHP`    | Set path to libphp7.a        | auto    |
| `PHP_TRACE_LIBELF`    | Set path to libelf.so        | auto    |
| `PHP_TRACE_LIBDW`     | Set path to libdw.so         | auto    |

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

  * Research Windows (no ideas, pull in a windows person probably)
  * Research Mac (no ideas)
