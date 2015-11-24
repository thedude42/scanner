"use strict";

/*
 * portscanner.js
 * Performs "connect scan" against all 2^16-1 TCP ports using concurrent
 * worker processes, the number of which equals the number of processes
 * reported by the system.
 *
 * Upon completion the open ports are listed with their resolved service
 * names, and the number of closed (received a TCP RST packet) and filtered
 * (connection timed out) ports are reported in no detial.
 *
 * Usage:
 *
 * portscanner.js <address>
 *
 * address can be ipv4, ipv6 or name which local resolver can handle
 */

var child_process = require("child_process"),
    path = require("path"),
    dns = require("dns"),
    readline = require("readline"),
    fs = require("fs");

if (process.argv.length < 3) {
    console.log("Please supply an address to scan\n\nusage:\n\t", path.basename(process.argv[1]), "<address>");
    process.exit(1);
}

// Constants
var SCANNER_MODULE = "childscanner.js",
    CORES = require("os").cpus().length,
    JOBS = CORES,
    ADDR = process.argv[2];

// Module vars
var children = [],
    results = {
        open:[],
        closed:[],
        filtered:[],
        scanned:[]
    },
    FISHY_ADDRESS = false,
    ServicesDBTcp = {},
    START_PORT = 1,
    END_PORT = 65535,
    NUM_PORTS = END_PORT - START_PORT + 1,
    guard = jobGate(JOBS);

console.log("Starting",JOBS,"child processes for scanning address",ADDR,"for ports",START_PORT,"thru",END_PORT,":",NUM_PORTS,"ports");

// Perform lookup on addr input arg, then init the services DB and start scan
dns.lookup(ADDR, function onDnsLookup(err, address, fam) {
    if (err) {
        console.log("Unable to resolve", ADDR);
        process.exit(1);
    }
    else {
        if ( /^[0-9]+$/.test(address)) {
            console.log("fishy address:",address);
        }
        FISHY_ADDRESS = true;
        initServicesObject(ServicesDBTcp, module.exports.beginScan);
    }
});

module.exports.setNumPorts = function setNumPorts(start, end) {
    if (isNaN(start) || isNaN(end) || start <= 0 || end > 65535) {
        return NUM_PORTS;
    }
    else if ((end - start) < 0) {
        return NUM_PORTS;
    }
    else {
        START_PORT = start;
        END_PORT = end;
        NUM_PORTS = END_PORT - START_PORT + 1;
        return NUM_PORTS;
    }
}

// simple creation of an object to map ports to service names
function initServicesObject(obj, cb) {
    var record_regex = /(\S+)\s+(\d+)\/tcp.+/,
        filestream = fs.createReadStream("/etc/services"),
        rl = readline.createInterface({input:filestream}),
        services = {};
    rl.on("line", function(line) {
        var m = record_regex.exec(line);
        if (m) {
            obj[m[2]] = m[1];
        }
    });
    filestream.on("close", cb);
    filestream.on("error", function(e) {
        console.log("could not open /etc/services : ",e);
    });
}

module.exports.countResults = function countResults() {
    return results.open.length+
           results.closed.length+
           results.filtered.length;
}

// initializes one child per JOBS
module.exports.beginScan = function beginScan() {
    for (var i = 0; i < JOBS; ++i) {
        var child = child_process.fork(path.resolve(SCANNER_MODULE));
        child.num = i;
        children[i] = exports.initChild(child);
    }
    return children;
}

module.exports.initChild = function initChild(child) {
    child.assigned = {};
    child.on("error", function parentErrorHandler(e) {
        console.log("Child", child.num, "errored:", e);
    });
    child.on("exit", function parentExitHandler(e) {
        console.log("Child", child.num, "exited:", e);
        var waiting = [];
        for (var i = 0; i < child.assigned.length; ++i) {
            if (Object.keys(child.assigned)[i] === "waiting") {
                waiting.push(i);
            }
        }
        if (waiting.length > 0) {
            console.log("restarting child",child.num);
            var new_child = child_process.fork(path.resolve(SCANNER_MODULE));
            new_child.num = child.num;
            children[new_child.num] = new_child;
            initChild(new_child, waiting);
        }
        else {
            guard();
        }
    });
    child.on("message", function parentMsgHandler(msg) {
        if (msg.state === "open") {
            results.open.push(msg.port+": "+ServicesDBTcp[msg.port]);
        }
        else if (msg.state === "closed") {
            results.closed.push(msg.port);
        }
        else if (msg.state === "filtered") {
            results.filtered.push(msg.port);
        }
        results.scanned[msg.port] = true;
        child.assigned[msg.port] = "scanned";
        // All work complete case
        if (exports.countResults() === NUM_PORTS) {
            console.log("DISCONNECTING",children.length,"CHILDREN");
            children.forEach(function(c) {
                c.disconnect();
            });
        }
    });
    // default case
    if (arguments.length < 2) {
        console.log("Sending port messages to child",child.num);
        for (var port = START_PORT+child.num; port <= END_PORT; port += JOBS) {
            child.send({port:port,addr:ADDR});
            child.assigned[port] = "waiting";
        }
    } // restarting failed child case with "waiting" ports array argument
    else {
        console.log("re-initializing child",child.num); 
        arguments[1].forEach(function(port) {
            child.send({port:port,addr:ADDR});
            child.assigned[port] = "waiting";
        });
    }
    return child;
}

/*
 * function maker, returns a counter function meant to be called upon each
 * child worker process port connect attempt, initialized with the number of 
 * expected tasks to complete.  Prints the results report when counter
 * matches numtasks.
 */

function jobGate(numtasks) {
    var count = 0;
    return function() {
        count++;
        if (count == numtasks) {
            console.log("\n-=- results -=-\n");
            if (FISHY_ADDRESS) {
                console.log("** WARNING: Unreliable scan, fishy address:",ADDR,"**\n");
            }
            if (results.open.length) {
                console.log("open TCP ports:\n",JSON.stringify(results.open,null,2));
            }
            else  {
                console.log("No open ports");
            }
            console.log(results.filtered.length, "ports timed out (filtered|closed|lost)");
            console.log(results.closed.length, "ports are closed");
        }
        return count;
    };
}
