# shelter

Shelter is designed as a remote attestation tool for customer to verify if their workloads are loaded in a specified intel authorized sgx enclaved.
The verifying process is as below:
1. shelter setup a security channel based on mTLS with runE enclaved
2. runE enclaved will generate/retrieve the quote info of workload running enclave
3. runE enclaved will get IAS report by quote info from Intel authorized web server
4. runE enclaved will generate attestation verification report
5. shelter will verify the attestation verification report and mrenclave value by mTLS security channel
6. shelter will report the verifying result


**Build**

Please follow the command to build Inclavare Containers from the latested source code on your system.
1. Download the latest source code of Inclavare Containers

   mkdir -p "$WORKSPACE"

   cd "$WORKSPACE"

   git clone https://github.com/alibaba/inclavare-containers

2. Prepare the dependence libs required by shelter

   cd $WORKSPACE/inclavare-containers/ra-tls

   make

   cp $WORKSPACE/build/bin/libra-challenger.a /usr/lib/

   cp $WORKSPACE/build/lib/libwolfssl.a /usr/lib/

   cd $WORKSPACE/inclavare-containers/shelter

   make


**Run**

Before running shelter, make sure enclaved being luanched successfully in the same machine.
1. check shelter support feature as below

   ./shelter help

   NAME:
      shelter - shelter as a remote attestation tool for workload runing in runE cloud encalved containers.

   USAGE:
      shelter [global options] command [command options] [arguments...]

   VERSION:
      0.1

   COMMANDS:
      sgxra     setup TLS security channel with remote server and fetch specified enclave mrencalve from QE and compare with local caculated mrenclave value based on software algorithm
      mrverify  download target source code to rebuild and caculate mrenclave based on software algorithm and then compare with mrenclave in sigsturct file
      help, h   Shows a list of commands or help for one command

   GLOBAL OPTIONS:
      --verbose      enable verbose output
      --help, -h     show help
      --version, -v  print the version

2. verify SGX remote attestation feature

   ./shelter sgxra

3. verify mrencalve software algorithm by [skeleton](https://github.com/alibaba/inclavare-containers/tree/master/rune/libenclave/internal/runtime/pal/skeleton) project

   ./shelter mrverify

**Touble shooting**

   NA


