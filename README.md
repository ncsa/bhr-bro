Bro Integration for BHR
=======================

Usage
-----

In local.bro:

    @load ./bhr-bro

    redef BHR::block_types += {
        Scan::Port_Scan,
        Scan::Address_Scan,
    };

and if your default block time is less than 15 minutes:

    redef Notice::type_suppression_intervals += {
        [Scan::Port_Scan]    = 800sec,
        [Scan::Address_Scan] = 800sec,
    };

There are two modes of operation:

* Queue based: Bro -> dirq + dirq -> BHR API
* Direct Bro -> BHR API communication

Queue
-----

The default is to use dirq.  To process the queue you need to run

    $ export BHR_TOKEN=abc91639287637189236193671983619783619c4
    $ export BHR_HOST=http://localhost:8000
    $ while true; do bhr.py run_queue ; sleep 2; done


`run_queue` will stop after 10 minutes and fail fast on any errors, so it needs
to be ran in a loop using upstart/systemd/etc.

Direct
------

If you don't want to setup queueing add to local.bro:

    redef BHR::mode = "block";

and to broctl.cfg:

    env_vars=BHR_TOKEN=abc91639287637189236193671983619783619c4,BHR_HOST=http://localhost:8000
