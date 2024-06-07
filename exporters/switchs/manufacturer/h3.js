

/*
    return shell config ,first is more command ,second is clear line command 
*/
function getShellConfig() {
    return ["---- More ----", ""];
}

function getArpInfo(data){
    var line="Aging Type \r\r\n";
    data=getTableData(data,line,"")
    var tableData=parseTableData(data,"\r\r\n","(.{16})(.{15})(.{11})(.{25})(.{6})(.*)")
    return ["arp_addresss",["ip", "mac", "vlan", "interface", "expire", "type", "instance"],tableData];
}

function getTableData(content,startLine,endLine){
    if (startLine.length > 0) {
        let index = content.indexOf(startLine);
        if (index !== -1) {
            content = content.slice(index + startLine.length);
        }
    }
    if (endLine.length > 0) {
        let index = content.indexOf(endLine);
        if (index !== -1) {
            content = content.slice(0, index);
        }
    }
    return content;
}

function parseTableData(content, lineSeparator, rowPattern) {
    let table = [];
    let rows = content.split(lineSeparator);
    let regex = new RegExp(rowPattern);
    let lastIndex = -1;
    for (let i = 0; i < rows.length; i++) {
        let row = rows[i].trim();
        if (row.length === 0) {
            continue;
        }
        let matches = regex.exec(row);
        if (matches && matches.length > 0) {
            table.push(matches.slice(1).map(record=>record.trim()));
            lastIndex++;
        } else {
            if (lastIndex >= 0) {
                table[lastIndex].push(row.trim());
            }
        }
    }
    return table;
}


function getMacInfo(data){
    var line="Aging\r\r\n";
    data=getTableData(data,line,"")
    var tableData=parseTableData(data,"\r\n","(.{17})(.{11})(.{17})(.{24})(.*)")
    return ["mac_addresss",["mac", "vlan", "type",  "interface","aging"],tableData];
}

function getOspfInfo(data){
    const regex = /[\s\S]*?OSPF Process (\d+).*Router ID ([\s\S]*?)\r\r\n([\s\S]*?)Area: ([\s\S]*?)\r\r\n([\s\S]*?)Interface\r\r\n(\s+\d+\.\d+\.\d+\.\d+.*\r\r\n)+/g;
    const results = [];
    let match;
    var startIndex=0
    while ((match = regex.exec(data)) !== null) {
        var partData=data.slice(startIndex,regex.lastIndex);
        startIndex=regex.lastIndex;
        const processId=match[1];
        const routeId = match[2].trim();
        const areaId = match[4].trim();
        const peerDetails = getTableData(partData,"Interface\r\r\n","");
        var tableData=parseTableData(peerDetails,"\r\r\n","(.{16})(.{16})(.{4})(.{11})(.{18})(.*)")
        for (let i = 0; i < tableData.length; i++) {
            var addRouteArray=[]
            addRouteArray.push(...tableData[i]);
            addRouteArray.push(routeId);
            addRouteArray.push(areaId);
            addRouteArray.push(processId);
            results.push(addRouteArray);
        }
    }
    return ["ospf_neighbor",[ "neighbor","forward","priority" ,"deadtime", "state","interface","route","area","process"],results];
}

function getVrrpInfo(data){
    var line="---------------------------------------------------------------------\r\r\n";
    data=getTableData(data,line,"")
    var tableData=parseTableData(data,"\r\r\n","(.{19})(.{6})(.{13})(.{8})(.{8})(.{9})(.*)")
    return ["vrrp_brief",["interface","vrid", "state","runningpriority","advertimer","authtype","ip","configtype"],tableData];
}

function getPowerInfo(data){
    var line="FanDirection\r\r\n";
    data=getTableData(data,line,"")
    var tableData=parseTableData(data,"\r\r\n","(.{8})(.{14})(.{10})(.{11})(.{13})(.{7})(.*)")
    return ["power",["powerid", "state",  "mode", "current","voltage","realpwr","FanDirection","online"],tableData];
}

exports.getArpInfo=getArpInfo;
exports.getOspfInfo=getOspfInfo;
exports.getMacInfo=getMacInfo;
exports.getVrrpInfo=getVrrpInfo;
exports.getPowerInfo=getPowerInfo;