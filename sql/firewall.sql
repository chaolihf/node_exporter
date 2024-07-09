create table firewall_config (
    receiveTime timestamp not null,
    collector_id varchar(50),
    object_id varchar(50),
    batch_id varchar(50),
    is_change int 
);

create index firewall_config_idx on firewall_config(object_id, is_change,receiveTime);

create table firewall_addressset(
    batch_id varchar(50),
    addressset_id varchar(50),
    name varchar(200),
    description varchar(200),
    zone varchar(200)
);

create index firewall_addressset_idx on firewall_addressset(batch_id);

--id_type为0时，address_id为firewall_addressset的addressset_id
--id_type为1时，address_id为firewall_ruleset的ruleset_id，并且为源地址
--id_type为2时，address_id为firewall_ruleset的ruleset_id，并且为目标地址
create table firewall_address_detail(
    address_id varchar(50),
    id_type int ,
    address_detail_id varchar(50),
    address_type int,
    address inet,
    v4 int,
    end_address inet,
    mask int,
    name varchar(200)
);

create index firewall_address_detail_idx on firewall_address_detail(address_id);

create table firewall_blacklist(
    batch_id varchar(50),
    name varchar(50)
);

create index firewall_blacklist_idx on firewall_blacklist(batch_id);

create table firewall_domainset(
    batch_id varchar(50),
    domainset_id varchar(50),
    name varchar(200),
    description varchar(200)
);

create index firewall_domainset_idx on firewall_domainset(batch_id);
create table firewall_domainset_detail(
    domainset_id varchar(50),
    domain_detail_id varchar(50),
    name varchar(200)
);

create index firewall_domainset_detail_idx on firewall_domainset_detail(domainset_id);


create table firewall_serviceset(
    batch_id varchar(50),
    serviceset_id varchar(50),
    name varchar(200),
    description varchar(200)
);

create index firewall_serviceset_idx on firewall_serviceset(batch_id);

--id_type为0时，service_id为firewall_serviceset的serviceset_id
--id_type为1时，service_id为firewall_ruleset_service_detail的rule_service_detail_id
create table firewall_service_detail(
    service_id varchar(50),
    id_type int ,
    service_detail_id varchar(50),
    protocol varchar(20),
    source_port_from int ,
    source_port_to int ,
    destination_port_from int ,
    destination_port_to int 
);

create index firewall_service_detail_idx on firewall_service_detail(service_id);

create table firewall_zoneset(
    batch_id varchar(50),
    zoneset_id varchar(50),
    name varchar(200),
    description varchar(200),
    priority int
);

create index firewall_zoneset_idx on firewall_zoneset(batch_id);
create table firewall_zoneset_detail(
    zoneset_id varchar(50),
    zone_detail_id varchar(50),
    interface_name varchar(50)
);

create index firewall_zoneset_detail_idx on firewall_zoneset_detail(zoneset_id);



create table firewall_ruleset(
    batch_id varchar(50),
    ruleset_id varchar(50),
    name varchar(200),
    description varchar(200),
    state varchar(50),
    action varchar(20),
    rule_order int
);

create index firewall_ruleset_idx on firewall_ruleset(batch_id);
--rule_service_type为1时，name为随机生成的ID
create table firewall_ruleset_service_detail(
    ruleset_id varchar(50),
    rule_service_detail_id varchar(50),
    rule_service_type int,
    name varchar(50)
);

create index firewall_ruleset_service_detail_idx on firewall_ruleset_service_detail(ruleset_id);

--rule_zone_type为1时,为目标地址域，为0时为源地址域
create table firewall_ruleset_zone_detail(
    ruleset_id varchar(50),
    rule_zone_id varchar(50),
    rule_zone_type int,
    name varchar(50)
);

create index firewall_ruleset_zone_detail_idx on firewall_ruleset_zone_detail(ruleset_id);
