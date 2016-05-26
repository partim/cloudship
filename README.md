# cloudship

[![Travis Build Status](https://travis-ci.org/cloudshipping/cloudship.svg?branch=master)](https://travis-ci.org/cloudshipping/cloudship)

## Building on OS X

If the `openssl` crate fails to build on OS X, you may have to specify
the path to the header files of the OpenSSL C library.  If you have
installed via homebrew the following should work:

```
export OPENSSL_INCLUDE_DIR=`brew --prefix openssl`/include
export DEP_OPENSSL_INCLUDE=${OPENSSL_INCLUDE_DIR}
```