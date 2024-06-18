const fs = require('fs');
const huaweiParser = require('../manufacturer/firewall-huawei.js');
const h3Parser = require('../manufacturer/firewall-h3.js');

async function readHuaweiConf() {
    try {
      var data = await fs.promises.readFile('node_exporter/exporters/firewall/test/firewall-huawei-configuration.txt', 'utf8');
      var tableData=huaweiParser.getConfInfo(data);
      console.log(tableData)
    } catch (err) {
      console.error('Error reading file:', err);
    }
  }

  async function readH3Conf() {
    try {
      var data = await fs.promises.readFile('node_exporter/exporters/firewall/test/firewall-h3-configuration.txt', 'utf8');
      var tableData=h3Parser.getConfInfo(data);
      console.log(tableData)
    } catch (err) {
      console.error('Error reading file:', err);
    }
  }

  readH3Conf();

