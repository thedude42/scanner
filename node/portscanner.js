"use strict";

var child_process = require("child_process"),
    path = require("path"),
    dns = require("dns"),
    EventEmitter = require("events");

if (process.argv.length < 3) {
    console.log("Please supply an address to scani\n\nusage:\n\t", path.basename(process.argv[1]), "<address>");
}

// Constants
var SCANNER_MODULE = "childscanner.js",
    CORES = require("os").cpus().length,
    JOBS = CORES,
    NUM_PORTS = 65535,
    ADDR = process.argv[2];

var children = [],
    results = {
        open:[],
        closed:[],
        filtered:[],
        scanned:[]
    },
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

function countResults() {
    return results.open.length+
           results.closed.length+
           results.filtered.length;
}

function beginScan() {
    for (var i = 0; i < JOBS; ++i) {
        children[i] = initChild(i);
    }
}

function initChild(num) {
    var child = child_process.fork(path.resolve(SCANNER_MODULE));
    child.num = num;
    child.assigned = {};
    child.on("error", function parentErrorHandler(e) {
        console.log("Child", num, "errored:", e);
    });
    child.on("exit", function parentExitHandler(e) {
        console.log("Child", num, "exited:", e);
        var waiting = [];
        for (var i = 0; i < child.assigned.length; ++i) {
            if (Object.keys(child.assigned)[i] === "waiting") {
                waiting.push(i);
            }
        }
        if (waiting.length > 0) {
            console.log("restarting child",child.num);
            initChild(child.num, waiting);
        }
        else {
            guard();
        }
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
        results.scanned[msg.port] = true;
        child.assigned[msg.port] = "scanned";
        if (countResults() == NUM_PORTS) {
            console.log("DISCONNECTING",children.length,"CHILDREN");
            children.forEach(function(c) {
                c.disconnect();
            });
        }
    });
    if (arguments.length < 2) {
        console.log("Sending port messages to child",child.num);
        for (var port = child.num+1; port <= NUM_PORTS; port += JOBS) {
            child.send({port:port,addr:ADDR});
            child.assigned[port] = "waiting";
        }
    }
    else {
        console.log("re-initializing child",child.num); 
        arguments[1].forEach(function(port) {
            child.send({port:port,addr:ADDR});
            child.assigned[port] = "waiting";
        });
    }
    return child;
}

function jobGate(numjobs) {
    var count = 0;
    return function() {
        count++;
        if (count == numjobs) {
            console.log("\n-=- results -=-\n");
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
