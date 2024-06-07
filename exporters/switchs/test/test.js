const fs = require('fs');
const huaweiParser = require('../manufacturer/huawei.js');
const h3Parser = require('../manufacturer/h3.js');

async function readHuaweiArp() {
    try {
      var data = await fs.promises.readFile('node_exporter/exporters/switchs/test/huawei-arp.txt', 'utf8');
      var tableData=huaweiParser.getArpInfo(data);
      console.log(tableData)
    } catch (err) {
      console.error('Error reading file:', err);
    }
  }

async function readHuaweiOspf() {
    try {
      var data = await fs.promises.readFile('node_exporter/exporters/switchs/test/huawei-ospf.txt', 'utf8');
      var tableData=huaweiParser.getOspfInfo(data);
      console.log(tableData)
    } catch (err) {
      console.error('Error reading file:', err);
    }
}

async function readHuaweiMac() {
  try {
    var data = await fs.promises.readFile('node_exporter/exporters/switchs/test/huawei-mac.txt', 'utf8');
    var tableData=huaweiParser.getMacInfo(data);
    console.log(tableData)
  } catch (err) {
    console.error('Error reading file:', err);
  }
}


async function readHuaweiVrrp() {
  try {
    var data = await fs.promises.readFile('node_exporter/exporters/switchs/test/huawei-vrrp.txt', 'utf8');
    var tableData=huaweiParser.getVrrpInfo(data);
    console.log(tableData)
  } catch (err) {
    console.error('Error reading file:', err);
  }
}

async function readHuaweiPower() {
  try {
    var data = await fs.promises.readFile('node_exporter/exporters/switchs/test/huawei-power.txt', 'utf8');
    var tableData=huaweiParser.getPowerInfo(data);
    console.log(tableData)
  } catch (err) {
    console.error('Error reading file:', err);
  }
}


async function readH3Ospf() {
  try {
    var data = await fs.promises.readFile('node_exporter/exporters/switchs/test/h3-ospf.txt', 'utf8');
    var tableData=h3Parser.getOspfInfo(data);
    console.log(tableData)
  } catch (err) {
    console.error('Error reading file:', err);
  }
}


readH3Ospf();

