
/*
    return shell config ,first is more command ,second is clear line command 
*/
function getShellConfig() {
    return ["---- More ----", "\x1B[42D"];
}

function getConfInfo(data){
    var parts=data.split("#\r\n");
    var addressSet=[];
    var serviceSet=[];
    var zoneSet=[];
    var rules;
    for(var i=0;i<parts.length;i++){
        var part=parts[i];
        if (part.startsWith("ip address-set")){
            addressSet.push(parseIpAddressSet(part));
        } else if (part.startsWith("ip service-set")){
            serviceSet.push(parseIpServiceSet(part));
        } else if (part.startsWith("firewall zone")){
            zoneSet.push(parseZoneSet(part));
        } else if (part.startsWith("security-policy")){
            rules=parseRules(part);
        } 
    }
    return {addressSet:addressSet,serviceSet:serviceSet,zoneSet:zoneSet,rules:rules};
}

function parseRules(data){
    const regex = / rule name ([\s\S]*?)\r\n([\s\S]*?)\r\n  action ([\s\S]*?)\r\n/g;
    var rules=[];
    while ((match = regex.exec(data)) !== null) {
        const ruleName=match[1];
        const action=match[3];
        const ruleContent=match[2];
        const ruleItems=parseRule(ruleContent);
        rules.push({
            ruleName:ruleName,
            action:action,
            ruleItems:ruleItems
        });
    }
    return rules;
}

function parseRule(data){
    var parts=data.split("\r\n");
    var sourceZone=[],destZone=[],sourceAddr=[],destAddr=[], service=[],description,state;
    for(var i=0;i<parts.length;i++){
        var items=parts[i].trim().split(" ");
        switch(items[0]){
            case "source-zone":
                sourceZone.push(items[1]);
                break;
            case "destination-zone":
                destZone.push(items[1]);
                break;
            case "source-address":
            case "destination-address":
                let targetAddr=items[1]=="source-address"?sourceAddr:destAddr;
                targetAddr.push(parseAddressInfo(items.slice(1)));
                break;
            case "service":
                service.push(items[1]);
                break;
            case "description":
                description=items[1];
                break;
            case "disable":
                state=items[0];
                break;
            case "long-link":
            case "profile":
                break;
            default:
                console.info("unknow data: "+data);
        }
    }
    return {sourceZone:sourceZone,destZone:destZone,sourceAddr:sourceAddr, service:service,state:state ,
        destAddr:destAddr,description:description};
}

function parseAddressInfo(items){
    if (items[0]=="range"){
        return {type:1,start:items[1],end:items[2]};
    } else if (items[0]=="address-set"){
        return {type:2,name:items[1]};
    } else if (items[1]=="mask"){
        return {type:0,address:items[0],mask:items[2]};
    } else {
        console.info("error parse address " + items);
    }

}
function parseIpAddressSet(data){
    var parts=data.split("\r\n");
    var name,description,address=[];
    for(var i=0;i<parts.length;i++){
        var items=parts[i].trim().split(" ");
        switch(items[0]){
            case "ip":
                name=items[2];
                break;
            case "description":
                description=items[1];           
                break;
            case "address":
                address.push(items.slice(2))
                break;
                
        }
    }
    return {name:name,description:description,address:address}
}

function parseIpServiceSet(data){
    var parts=data.split("\r\n");
    var addressSet={};
    for(var i=0;i<parts.length;i++){
        var part=parts[i];
        
    }
}

function parseZoneSet(data){
    var parts=data.split("\r\n");
    var addressSet={};
    for(var i=0;i<parts.length;i++){
        var part=parts[i];
        
    }
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

exports.getConfInfo=getConfInfo;