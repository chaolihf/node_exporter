const fs = require('fs');
const parser = require('../manufacturer/huawei.js');

async function readHuaweiArp() {
    try {
      var data = await fs.promises.readFile('node_exporter/exporters/switchs/test/huawei-arp.txt', 'utf8');
      var tableData=parser.getArpInfo(data);
      console.log(tableData)
    } catch (err) {
      console.error('Error reading file:', err);
    }
  }

async function readHuaweiOspf() {
    try {
      var data = await fs.promises.readFile('node_exporter/exporters/switchs/test/huawei-ospf.txt', 'utf8');
      var tableData=parser.getOspfInfo(data);
      console.log(tableData)
    } catch (err) {
      console.error('Error reading file:', err);
    }
}

async function readHuaweiMac() {
  try {
    var data = await fs.promises.readFile('node_exporter/exporters/switchs/test/huawei-mac.txt', 'utf8');
    var tableData=parser.getMacInfo(data);
    console.log(tableData)
  } catch (err) {
    console.error('Error reading file:', err);
  }
}


async function readHuaweiVrrp() {
  try {
    var data = await fs.promises.readFile('node_exporter/exporters/switchs/test/huawei-vrrp.txt', 'utf8');
    var tableData=parser.getVrrpInfo(data);
    console.log(tableData)
  } catch (err) {
    console.error('Error reading file:', err);
  }
}

async function readHuaweiPower() {
  try {
    var data = await fs.promises.readFile('node_exporter/exporters/switchs/test/huawei-power.txt', 'utf8');
    var tableData=parser.getPowerInfo(data);
    console.log(tableData)
  } catch (err) {
    console.error('Error reading file:', err);
  }
}

readHuaweiVrrp();

