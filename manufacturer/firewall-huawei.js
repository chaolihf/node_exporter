/*
    return shell config ,first is more command ,second is clear line command 
*/
function getShellConfig() {
    return ["---- More ----", "\x1B[42D"];
}

function getConfInfo(data){
    var parts=data.split("#\r\n");
    var addressSet=[],serviceSet=[],zoneSet=[],rules,domainSet;
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
        } else if (part.startsWith(" domain-set")){
            domainSet=parseDomainSet(part);
        }
    }
    return JSON.stringify({addressSet:addressSet,serviceSet:serviceSet,
        zoneSet:zoneSet,rules:rules,domainSet:domainSet});
}

function parseDomainSet(data){
    var domainSet=[];
    var domainPart=data.split("domain-set");
    for (var j=0;j<domainPart.length;j++){
        var parts=domainPart[j].trim().split("\r\n");
        var domainInfo={};
        var domains=[];
        for(var i=0;i<parts.length;i++){
            var items=parts[i].trim().split(" ");
            switch(items[0]){
                case "name":
                    domainInfo.name=items[1];
                    break;
                case "description":
                    domainInfo.description=items[1];
                    break;
                case "add":
                    if (items[1]=="domain") {
                        domains.push(items[2]);
                        break;
                    }
                case "":
                    break;
                default:
                    console.info("error prase domain " + data);
            }
        }
        domainInfo.domains=domains;
        domainSet.push(domainInfo);
    }
    return domainSet;
}

function parseRules(data){
    let match;
    const regex = / rule name ([\s\S]*?)\r\n([\s\S]*?)\r\n  action ([\s\S]*?)\r\n/g;
    var rules=[];
    while ((match = regex.exec(data)) !== null) {
        const ruleName=match[1];
        const action=match[3];
        const ruleContent=match[2];
        const ruleItems=parseRule(ruleContent);
        rules.push(Object.assign({}, { name:ruleName,
            action:action}, ruleItems));
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
                service.push({type:0,name:items[1]});
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
        return {type:3,name:items[1]};
    } else if (items[0]=="domain-set"){
        return {type:4,name:items[1]};
    } else if (items[1]=="mask"){
        return {type:2,address:items[0],mask:items[2],v4:1};
    } else if (items[1]=="0"){
        return {type:2,address:items[0],mask:32,v4:1};
    } else if (items[0].indexOf(":")!=-1){
        return {type:0,address:items[0],mask:items[2],v4:0};
    } else{
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
                address.push(parseAddressInfo(items.slice(2)))
                break;
            case "":
                break;
            default:
                console.info("error parse ip address set " + data );
        }
    }
    return {name:name,description:description,address:address}
}

function parseIpServiceSet(data){
    var parts=data.split("\r\n");
    var name,description,service=[];
    for(var i=0;i<parts.length;i++){
        var items=parts[i].trim().split(" ");
        switch (items[0]){
            case "ip":
                name=items[2];
                break;
            case "description":
                description=items[1];           
                break;
            case "service":
                service.push( parseServiceItem(items.slice(2)));
                break;
            case "":
                break;
            default:
                console.info("error parse " + data );
        }
    }
    return {name:name,description:description,service:service};
}

function parseServiceItem(items){
    var index=0;
    var serviceItem={};
    while(index<items.length){
        var item=items[index];
        switch(item){
            case "protocol":{
                serviceItem.protocol=items[index+1];
                index+=2;
                break;
            }
            case "source-port":
            case "destination-port":{
                var portInfos=parsePorts(items.slice(index+1));
                index+=portInfos.length+1;
                serviceItem[item+"-from"]=portInfos.from;
                serviceItem[item+"-to"]=portInfos.to;
                break;
            }
            case "service-set":{
                serviceItem.service=items[index+1];
                index+=2;
                break;
            }
            default:
                console.info("error parse "+ items);

        }
    }
    return serviceItem;
}

function parsePorts(items){
    var index=0;
    var from,to;
    while(index<items.length){
        const port=parseInt(items[index]);
        if (isNaN(port)) break;
        if (index+1<items.length && items[index+1]=="to" ){
            from=items[index];
            to=items[index+2];
            index+=3;
        } else{
            from=items[index];
            to=items[index];
            index+=1;
        }
    }
    return {length:index,from:from,to:to};
}

function parseZoneSet(data){
    var parts=data.split("\r\n");
    var zoneInfo={};
    var interfaces=[];
    for(var i=0;i<parts.length;i++){
        var items=parts[i].trim().split(" ");
        switch(items[0]){
            case "firewall":
                if (items[2]=="name" ){
                    zoneInfo.name=items[3];
                } else{
                    zoneInfo.name=items[2];
                }
                break;
            case "description":
                zoneInfo.description=items[1];
                break;
            case "set":
                    if (items[1]=="priority") {
                        zoneInfo.priority=items[2];
                        break;
                    }
            case "add":
                if (items[1]=="interface") {
                    interfaces.push(items[2]);
                    break;
                }
            case "":
                break;
            default:
                console.info("error prase zone " + data);
        }
    }
    zoneInfo.interfaces=interfaces;
    return zoneInfo;
}

exports.getConfInfo=getConfInfo;