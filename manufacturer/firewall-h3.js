const { match } = require("assert");

/*
    return shell config ,first is more command ,second is clear line command 
*/
function getShellConfig() {
    return ["---- More ----", ""];
}

function getConfInfo(data){
    var parts=data.split(/#\s*\r\n/);
    var addressSet=[],serviceSet=[],zoneSet=[],rules,blacklist;
    for(var i=0;i<parts.length;i++){
        var part=parts[i];
        if (part.startsWith("object-group ip")){
            addressSet.push(parseIpAddressSet(part));
        } else if (part.startsWith("object-group service")){
            serviceSet.push(parseIpServiceSet(part));
        } else if (part.startsWith("security-zone")){
            zoneSet.push(parseZoneSet(part));
        } else if (part.startsWith("security-policy")){
            rules=parseRules(part);
        } else if (part.startsWith(" blacklist")){
            blacklist=parseBlacklist(part);
        } 
    }
    return {addressSet:addressSet,serviceSet:serviceSet,zoneSet:zoneSet,rules:rules,blacklist:blacklist};
}

function parseBlacklist(data) {
    var blacklist=[];
    var parts=data.split("\r\n");
    for(var i=0;i<parts.length;i++){
        var items=parts[i].trim().split(" ");
        if(items[0]=="blacklist"){
            if (items[1]=="ip" || items[1]=="ipv6"){
                blacklist.push(items[2]);
            } else if (items[1]=="global" || items[1]=="logging" ) {
            } else {
                console.info("error parse blacklist " + data);
            }
            
        }
    }
    return blacklist
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
    var rules=[];
    var rulePart=data.split(" rule ");
    for (var i=1;i<rulePart.length;i++){
        var ruleInfo={},sourceZone=[],destZone=[],sourceAddr=[],destAddr=[], service=[],description,state;
        var lineParts=rulePart[i].trim().split("\r\n");
        for(var j=0;j<lineParts.length;j++){
            var fieldPart=lineParts[j].trim().split(" ");
            switch(fieldPart[0]){
                case "disable":{
                    ruleInfo.state="disable";
                    break;
                }
                case "description":{
                    ruleInfo.description=fieldPart[1];
                    break;
                }
                case "action":{
                    ruleInfo.action=fieldPart[1];
                    break;
                }
                case "source-zone":{
                    sourceZone.push(fieldPart[1]);
                    break;
                }
                case "destination-zone":{
                    destZone.push(fieldPart[1]);
                    break;
                }
                case "source-ip":{
                    sourceAddr.push({type:3,address:fieldPart[1],v4:1});
                    break;
                }
                case "destination-ip":{
                    destAddr.push({type:3,address:fieldPart[1],v4:1});
                    break;
                }
                case "source-ip-subnet":{
                    sourceAddr.push({type:2,address:fieldPart[1],mask:fieldPart[2]});
                    break;
                }
                case "destination-ip-subnet":{
                    destAddr.push({type:2,address:fieldPart[1],mask:fieldPart[2]});
                    break;
                }
                case "source-ip-range":{
                    sourceAddr.push({type:1,start:fieldPart[1],end:fieldPart[2]});
                    break;
                }
                case "destination-ip-range":{
                    sourceAddr.push({type:1,start:fieldPart[1],end:fieldPart[2]});
                    break;
                }
                case "source-ip-host":{
                    sourceAddr.push({type:0,address:fieldPart[1],v4:1});
                    break;
                }
                case "destination-ip-host":{
                    destAddr.push({type:0,address:fieldPart[1],v4:1});
                    break;
                }
                case "service":{
                    service.push({type:0,name:fieldPart[1]});
                    break;
                }
                case "service-port":{
                    var serviceItem=parseServiceItem(fieldPart.slice(1))
                    serviceItem.type=1;
                    service.push(serviceItem);
                    break;
                }
                case "counting":
                case "logging":
                case "profile":{
                    break;
                }
                default:{
                    if (fieldPart[1]== "name" ){
                        ruleInfo.name=fieldPart[2];
                        break;
                    } else {
                        console.info("error parse rule " + data);
                    }
                    
                    
                }
            }
        }
        rules.push(ruleInfo);
    }
    return rules;
}

function parseAddressInfo(items){
    if (items[0]=="range"){
        return {type:1,start:items[1],end:items[2]};
    } else if (items[0]=="host"){
        return {type:0,address:items[1],v4: items[2].indexOf(":")==-1?1:0};
    } else if (items[0]=="subnet"){
        return {type:2,address:items[1],mask:items[2],v4:1};
    } else if (items[0]=="group-object"){
        return {type:3,name:items[1]};
    } else{
        console.info("error parse address " + items);
    }
}

function parseIpAddressSet(data){
    var parts=data.split("\r\n");
    var name,zone,description,address=[];
    for(var i=0;i<parts.length;i++){
        var items=parts[i].trim().split(" ");
        switch(items[0]){
            case "object-group":
                name=items[3];
                break;
            case "description":
                description=items[1];
                break;
            case "security-zone":
                zone=items[1];
                break;
            case "":
                break;
            default:
                if(items[1]=="network"){
                    address.push(parseAddressInfo(items.slice(2)));
                } else {
                    console.info("error parse ip address set " + data );
                }
        }
    }
    return {name:name,zone:zone,address:address,description:description}
}


function parseIpServiceSet(data){
    var parts=data.split("\r\n");
    var name,description,service=[];
    for(var i=0;i<parts.length;i++){
        var items=parts[i].trim().split(" ");
        switch (items[0]){
            case "object-group":
                name=items[2];
                break;
            case "description":
                description=items[1];
                break;
            case "":
                break;
            default:
                if (items[1]=="service"){
                    service.push(parseServiceItem(items.slice(2)));
                    break;
                } else {
                    console.info("error parse service " + data );
                }
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
            case "tcp":
            case "udp":
            case "icmpv6": {
                serviceItem.protocol=items[index++];
                break;
            }
            case "source":
            case "destination":{
                var portInfos=parsePorts(items.slice(index+1));
                index+=portInfos.length+1;
                serviceItem[item]=portInfos.ports;
                break;
            }
            default:
                console.info("error parse service item "+ items);

        }
    }
    return serviceItem;
}

function parsePorts(items){
    var index=0;
    var ports=[];
    switch(items[0]){
        case "eq":{
            ports.push({from:items[1],to:items[1]});
            index=2;
            break;
        }
        case "lt":{
            ports.push({from:1,to:items[1]-1});
            index=2;
            break;
        }
        case "gt":{
            ports.push({from:items[1]+1,to:65535});
            index=2;
            break;
        }
        case "range":{
            ports.push({from:items[1],to:items[2]});
            index=3;
            break;
        }
        default:{
            console.info("error parse ports " + items);
        }
    }
    
    return {length:index,ports:ports};
}

function parseZoneSet(data){
    var parts=data.split("\r\n");
    var zoneInfo={};
    var interfaces=[];
    for(var i=0;i<parts.length;i++){
        var items=parts[i].trim().split(" ");
        switch(items[0]){
            case "security-zone":
                zoneInfo.name=items[2];
                break;
            case "import":
                if (items[1]=="interface") {
                    interfaces.push(items[2]);
                    break;
                }
            case "attack-defense":
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