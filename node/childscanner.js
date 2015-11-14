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
    while (running < 1000 && msgqueue.length > 0) {
        checkPort(msgqueue.shift());
    }
    setTimeout(go, 2000);
}


function checkPort(obj) {
    console.log("scanning port", obj.port);
    var conn = net.connect({host:obj.addr,port:obj.port});
    running++;
    setTimeout(function filteredSockTimeout() {
        console.log("destroying connection on port",obj.port);
        conn.destroy();
    }, 3000);
    conn.on("error", function childConnErr(e) {
        if (e.code === "ECONNREFUSED") {
            console.log("PORT",obj.port,":CLOSED");
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
        obj.connected = true;
        conn.destroy();
        running--;
    });
    conn.on("close", function onClose() {
        if (!obj.connected) {
            process.send({port:obj.port,state:"filtered"});
            console.log("PORT",obj.port,":PROBABLY FILTERED");
            running--;
        }
    });

}
