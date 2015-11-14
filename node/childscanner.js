"use strict";

var net = require("net"),
    msgqueue = [],
    running = 0;

process.on("message", function childMsgHandler(msg) {
    //console.log("got message:\n",JSON.stringify(msg,null,2));
    msgqueue.push(msg);
    go();
});

process.on("disconnect", function childOnParentDiconnect() {
    process.exit(0);
});

function go() {
    while (running < 100 && msgqueue.length > 0) {
        checkPort(msgqueue.shift());
    }
    setTimeout(go, 2000);
}

/**
 * checkPort( {host:"host to connect to",port:"dst port for connection"} ) 
 * Each call attempts to open a connection to obj.host on port obj.port,
 * and sets up callbacks for socket events and sets a timeout timer.
 *
 * Too agressive concurrent connecting to a single host will produce false
 * "filtered" results, as will loss on the network path.
 */
function checkPort(obj) {
    console.log("scanning port", obj.port);
    var conn = net.connect({host:obj.addr,port:obj.port});
    running++;
    setTimeout(function filteredSockTimeout() {
        process.nextTick(function filteredSocketTimeoutNextTick() {
            if (! obj.determined) {
                console.log("destroying connection on port",obj.port);
                conn.destroy();
            }
        });
    }, 30000);
    conn.on("error", function childConnErr(e) {
        if (e.code === "ECONNREFUSED") {
            console.log("PORT",obj.port,":CLOSED");
            obj.determined = true;
            process.send({port:obj.port,state:"closed"});
        }
        else if (e.code === "ETIMEDOUT") {
            process.send({port:obj.port,state:"filtered"});
            console.log("PORT",obj.port,":FILTERED");
        }
        conn.destroy();
        running--;
    });
    conn.on("connect", function childGoodConn() {
        console.log("PORT",obj.port,":OPEN");
        process.send({port:obj.port,state:"open"});
        obj.determined = true;
        conn.destroy();
        running--;
    });
    conn.on("close", function onClose() {
        if (!obj.determined) {
            process.send({port:obj.port,state:"filtered"});
            console.log("PORT",obj.port,":PROBABLY FILTERED");
            running--;
        }
    });

}
