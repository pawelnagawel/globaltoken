# Copyright (c) 2019 Crypto and Coffee | https://cryptoandcoffee.com/ however
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
# Maintained by Crypto and Coffee | https://cryptoandcoffee.com

FROM ubuntu:16.04
COPY ./build-docker.sh ./build-docker.sh
RUN ./build-docker.sh ; rm build-docker.sh
CMD globaltokend -printtoconsole