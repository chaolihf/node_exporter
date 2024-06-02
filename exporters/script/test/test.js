const fs = require('fs');
async function readFileContents() {
    try {
      const data = await fs.promises.readFile('node_exporter/exporters/script/test/huawei-arp.txt', 'utf8');
      parseTableData(data,"\r\n","(.{16})(.{16})(.{10})(.{12})(.{15})(.*)")
    } catch (err) {
      console.error('Error reading file:', err);
    }
  }
  
  readFileContents();



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
        table.push(matches.slice(1));
        lastIndex++;
      } else {
        if (lastIndex >= 0) {
          table[lastIndex].push(row);
        }
      }
    }
  
    return table;
  }