"use strict";

var child_process = require("child_process"),
    path = require("path"),
    dns = require("dns"),
    readline = require("readline"),
    fs = require("fs");

if (process.argv.length < 3) {
    console.log("Please supply an address to scani\n\nusage:\n\t", path.basename(process.argv[1]), "<address>");
}

// Constants
var SCANNER_MODULE = "childscanner.js",
    CORES = require("os").cpus().length,
    JOBS = CORES,
    NUM_PORTS = 65535,
    ADDR = process.argv[2];

// Module vars
var children = [],
    results = {
        open:[],
        closed:[],
        filtered:[],
        scanned:[]
    },
    ServicesDBTcp = {},
    guard = jobGate(JOBS);

console.log("Starting",JOBS,"child processes for scanning address",ADDR);

// Perform lookup on addr input arg, then init the services DB and start scan
dns.lookup(ADDR, function onDnsLookup(err, address, fam) {
    if (err) {
        console.log("Unable to resolve", ADDR);
        process.exit(1);
    }
    else {
        console.log("need to regex this address for IP addr format");
        initServicesObject(ServicesDBTcp, beginScan);
    }
});

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
        if (countResults() == NUM_PORTS) {
            console.log("DISCONNECTING",children.length,"CHILDREN");
            children.forEach(function(c) {
                c.disconnect();
            });
        }
    });
    // default case
    if (arguments.length < 2) {
        console.log("Sending port messages to child",child.num);
        for (var port = child.num+1; port <= NUM_PORTS; port += JOBS) {
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
