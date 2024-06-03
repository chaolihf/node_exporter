

function getArpInfo(data){
    var line="------------------------------------------------------------------------------\r\n";
    data=getTableData(data,line,line)
    var tableData=parseTableData(data,"\r\n","(.{16})(.{16})(.{10})(.{12})(.{15})(.*)")
    return tableData;
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

exports.getArpInfo=getArpInfo;