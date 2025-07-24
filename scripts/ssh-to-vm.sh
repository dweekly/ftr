#!/bin/bash
# Helper to SSH into test VMs

VM=$1
case $VM in
    ubuntu)
        ssh -i ~/.ssh/ftr-test-key -p 22022 ftr@localhost
        ;;
    freebsd)
        ssh -i ~/.ssh/ftr-test-key -p 22023 ftr@localhost
        ;;
    *)
        echo "Usage: $0 [ubuntu|freebsd]"
        exit 1
        ;;
esac
