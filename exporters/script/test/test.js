const fs = require('fs');
const parser = require('./arpParse.js');

async function readFileContents() {
    try {
      var data = await fs.promises.readFile('node_exporter/exporters/script/test/huawei-arp.txt', 'utf8');
      var tableData=parser.getArpInfo(data);
      console.log(tableData)
    } catch (err) {
      console.error('Error reading file:', err);
    }
  }
  
readFileContents();

