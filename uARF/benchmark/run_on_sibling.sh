#!/bin/bash

# Set affinity of $@ to two SMT sibling threads

threads=

case $(hostname) in

    ee-tik-cn117) # Zen1
        threads="6,7"
        ;;
    ee-tik-cn102) # Zen2
        threads="3,11"
        ;;
    ee-tik-cn105) # Zen3
        threads="31,7"
        ;;
    ee-tik-cn128) # Zen4
        threads="11,3"
        ;;
    ee-tik-cn145) # Zen5
        threads="9,3"
        ;;
    ee-tik-cn016) # Coffee
        threads="9,3"
        ;;
    ee-tik-cn120) # Raptor
        # There is not SMT for efficiency core
        threads="10,11"
        ;;
    *)
        echo "Invalid host name!"
        exit 1
esac

echo "Run on '$threads'"

taskset -c "$threads" $@
