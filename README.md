This repository is here temporarily to show the performance and practically of our submitted paper "Practical Constant-Size Delegatable Anonymous Credentials."


# Warning:
This implementation has not been audited and is not ready for a production application. The library is provided for research-purpose only and is still not meant to be used in production.


## It is still under progress, A production-level code (clean version) is planned to be published soon. The next steps are:


#  Pre-requisites
Library is built on top of petlib https://github.com/gdanezis/petlib and bplib https://github.com/gdanezis/bplib, make sure to follow these instructions to install all the pre-requisites.

## Getting started
To install the development dependencies run

    pip install -r requirements.tx


# Test
Tests can be run as follows:

    pytest tests/ -s -v
