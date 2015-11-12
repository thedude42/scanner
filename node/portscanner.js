"use strict";

var child_process = require("child_process"),
    path = require("path"),
    dns = require("dns");

if (process.argv.length < 3) {
    console.log("Please supply an address to scani\n\nusage:\n\t", path.basename(process.argv[1]), "<address>");
}

// Constants
var SCANNER_MODULE = "childscanner.js",
    CORES = require("os").cpus().length,
    JOBS = CORES*100,
    NUM_PORTS = 65535,
    ADDR = process.argv[2];

var children = [],
    results = {
        open:[],
        closed:[],
        filtered:[]
    },
    next_port = 1,
    guard = jobGate(JOBS);

console.log("Starting",JOBS,"child processes for scanning address",ADDR);

dns.lookup(ADDR, function onDnsLookup(err, address, fam) {
    if (err) {
        console.log("Unable to resolve", ADDR);
        process.exit(1);
    }
    else {
        console.log("need to regex this address for IP addr format");
        beginScan();
    }
});


function beginScan() {
    for (var i = 0; i < JOBS; ++i) {
        children[i] = initChild(i);
    }
}

function initChild(num) {
    var child = child_process.fork(path.resolve(SCANNER_MODULE));
    child.num = num;
    child.on("error", function parentErrorHandler(e) {
        console.log("Child", num, "died:", e);
        if (next_port <= NUM_PORTS) {
            console.log("restarting child",child.num);
            initChild(child.num);
        }
    });
    child.on("exit", function parentExitHandler(e) {
        console.log("Child", num, "exited:", e);
        guard();
    });
    child.on("message", function parentMsgHandler(msg) {
        if (msg.state === "open") {
            results.open.push(msg.port);
        }
        else if (msg.state === "closed") {
            results.closed.push(msg.port);
        }
        else if (msg.state === "filtered") {
            results.filtered.push(msg.port);
        }
        if (next_port <= NUM_PORTS) {
            child.send({port:next_port++,addr:ADDR});
        }
        else {
            child.kill("SIGTERM");
        }
    });
    child.send({port:next_port++,addr:ADDR});
}

function jobGate(numjobs) {
    var count = 0;
    return function() {
        count++;
        if (count == numjobs) {
            console.log("-=- results -=-\n");
            if (results.open.length) {
                console.log("open ports:\n",JSON.stringify(results.open,null,2));
            }
            else  {
                console.log("No open ports");
            }
            console.log(results.filtered.length, "ports are filtered");
            console.log(results.closed.length, "ports are closed");
        }
    };
}
