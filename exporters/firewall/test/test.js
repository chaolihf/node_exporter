const fs = require('fs');
const huaweiParser = require('../manufacturer/huawei.js');
const h3Parser = require('../manufacturer/h3.js');

async function readHuaweiConf() {
    try {
      var data = await fs.promises.readFile('node_exporter/exporters/firewall/test/huawei-configuration.txt', 'utf8');
      var tableData=huaweiParser.getConfInfo(data);
      console.log(tableData)
    } catch (err) {
      console.error('Error reading file:', err);
    }
  }

readHuaweiConf();

