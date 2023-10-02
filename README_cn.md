# 集成进程、网络、脚本等融合采集器
# 集成方式
1、增加OneAgent项目中pkg下除NodeExportPlugins.go下文件到colletor中  
2、修改模块名称为module github.com/chaolihf/node_exporter  
3、修改node_exporter.go的包名为node_expoter_main,mai方法为Main方法
4、修改node_exporter_test.go的包名为node_expoter_main

# 特别说明
## 1、修改模块名的原因
为了将此作为模块来发布，从而可以在其他模块中集成
