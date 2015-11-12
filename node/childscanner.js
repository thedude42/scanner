"use strict";

var net = require("net");

process.on("message", function childMsgHandler(msg) {
    console.log("got message:\n",JSON.stringify(msg,null,2));
    checkPort(msg);
});

function checkPort(obj) {
    console.log("scanning port", obj.port);
    var conn = net.connect({host:obj.addr,port:obj.port});
    conn.on("error", function childConnErr(e) {
        console.log("socket error:",e);
        if (e.code === "ECONNREFUSED") {
            process.send({port:obj.port,state:"closed"});
        }
        else if (e.code === "ETIMEDOUT") {
            process.send({port:obj.port,state:"filtered"});
        }
        conn.destroy();
    });
    conn.on("connect", function childGoodConn() {
        console.log("good connection on",obj.port);
        process.send({port:obj.port,state:"open"});
        conn.destroy();
    });

}
