

/*
    return shell config ,first is more command ,second is clear line command 
*/
function getShellConfig() {
    return ["---- More ----", "\x1B[42D"];
}

function getArpInfo(data){
    var line="------------------------------------------------------------------------------\r\n";
    data=getTableData(data,line,line)
    var tableData=parseTableData(data,"\r\n","(.{16})(.{16})(.{10})(.{12})(.{15})(.*)")
    return ["arp_addresss",["ip", "mac", "expire", "type", "interface", "instance", "vlan"],tableData];
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

function getOspfInfo(data){
    const regex = /[\s\S]*?Router ID ([\s\S]*?)\r\n([\s\S]*?)Total Peer.*?\r\n/g;
    const results = [];
    let match;
    var line=" ----------------------------------------------------------------------------\r\n";
    while ((match = regex.exec(data)) !== null) {
        const ipAddress = match[1];
        const peerDetails = getTableData(match[2],"State    \r\n",line);
        var tableData=parseTableData(peerDetails,"\r\n","(.{17})(.{33})(.{17})(.*)")
        for (let i = 0; i < tableData.length; i++) {
            var addRouteArray=[]
            addRouteArray.push(...tableData[i]);
            addRouteArray.push(ipAddress);
            results.push(addRouteArray);
        }
    }
    return ["ospf_neighbor",["area", "interface", "neighbor", "state","route"],results];
}

function getMacInfo(data){
    let index = data.indexOf("Learned-From");
    if (index !== -1) {
        data = data.slice(index);
    }
    var line="------------------------------------------------------------------------------\r\n";
    data=getTableData(data,line,line)
    var tableData=parseTableData(data,"\r\n","(.{15})(.{34})(.{20})(.*)")
    return ["mac_addresss",["mac", "vlan",  "interface", "type"],tableData];
}

function getVrrpInfo(data){
    var line="----------------------------------------------------------------\r\n";
    data=getTableData(data,line,"")
    var tableData=parseTableData(data,"\r\n","(.{6})(.{13})(.{25})(.{9})(.*)")
    return ["vrrp_brief",["vrid", "state",  "interface", "type","ip"],tableData];
}


function getPowerInfo(data){
    let index = data.indexOf("RealPwr");
    if (index !== -1) {
        data = data.slice(index);
    }
    var line="--------------------------------------------------------------------------\r\n";
    data=getTableData(data,line,"")
    var tableData=parseTableData(data,"\r\n","(.{9})(.{8})(.{7})(.{11})(.{13})(.{13})(.*)")
    return ["power",["powerid", "online",  "mode", "state","current","voltage","realpwr"],tableData];
}

exports.getArpInfo=getArpInfo;
exports.getOspfInfo=getOspfInfo;
exports.getMacInfo=getMacInfo;
exports.getVrrpInfo=getVrrpInfo;
exports.getPowerInfo=getPowerInfo;