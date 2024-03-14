# 集成进程、网络、脚本等融合采集器
1、访问方式  http://localhost:9999/OneAgentMetrics
# 集成方式
1、增加OneAgent项目中pkg下除NodeExportPlugins.go下文件到colletor中  
2、修改模块名称为module github.com/chaolihf/node_exporter  
3、修改node_exporter.go的包名为node_exporter_main,main方法为Main方法
4、修改node_exporter_test.go的包名为node_exporter_main
5、修改node_exporter.go中部分代码，见2024.1.10号升级版本

# 特别说明
## 1、修改模块名的原因
为了将此作为模块来发布，从而可以在其他模块中集成

## 2、原始版本
对应Node_Exporter的1.6.1版本master

## 3、升级说明
2023.12.3 升级gopsutils，修复主机进程过多时获取进程信息造成CPU异常高问题
2024.1.10 修改默认参数，增加超时设置，去掉默认页面，防范缓慢的HTTP拒绝服务（DoS）攻击，修改默认路径为OneAgentMetrics