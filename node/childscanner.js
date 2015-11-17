"use strict";

var net = require("net"),
    msgqueue = [],
    running = 0,
    CONCURRENT_CONNECTS = 1000,
    CONNECT_TIMEOUT = 5000;

process.on("message", function childMsgHandler(msg) {
    //console.log("got message:\n",JSON.stringify(msg,null,2));
    msgqueue.push(msg);
    go();
});

process.on("disconnect", function childOnParentDiconnect() {
    process.exit(0);
});

/* go()
 * Work message handler. Pulls up to CONCURRENT_CONNECTS off the
 * array object "msgqueue", then sets itself on a timeout callback
 * for 2 seconds. This process repeats until the process is killed
 * or the parent dies.
 */
function go() {
    while (running < CONCURRENT_CONNECTS && msgqueue.length > 0) {
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
    }, CONNECT_TIMEOUT);
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
