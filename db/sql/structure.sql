begin transaction;

create table params (
    id          integer not null primary key,
    model       integer,
    param_type  integer,
    description varchar(200),
    param1      integer not null,
    param2      integer not null,
    param3      integer not null,
    param4      integer not null,
    param5      integer not null,
    param6      integer not null,
    group_id    integer,
    guid        char(32),
    options     integer default 0,
    unique (guid)
);

create table certificates (
    id          integer not null primary key,
    cert_type   integer not null,
    param_type  integer,
    thumbprint  varchar(64) not null,
    issuedto    varchar(100) not null,
    issuedby    varchar(100) not null,
    expiration  date not null,
    params_id   integer not null,
    guid        char(32),
    options     integer default 0,
    foreign key (params_id) references params (id),
    unique (guid)
);

create table contents (
    id          integer not null primary key,
    cont_type   integer not null,
    param_type  integer,
    content     varchar(255) not null,
    file_name   varchar(255),
    params_id   integer not null,
    guid        char(32),
    options     integer default 0,
    foreign key (params_id) references params (id),
    unique (guid)
);

create table digests (
    id          integer not null primary key,
    digest_type integer not null,
    param_type  integer,
    file_name   varchar(255),
    digest      varchar(64) not null,
    params_id   integer not null,
    guid        char(32),
    options     integer,
    foreign key (params_id) references params (id),
    unique (guid)
);

create table owners (
    id          integer not null primary key,
    res_type    integer not null,
    param_type  integer,
    sid         varchar(160) not null,
    params_id   integer not null,
    guid        char(32),
    options     integer default 0,
    foreign key (params_id) references params (id),
    unique (guid)
);

create table pathes (
    id          integer not null primary key,
    res_type    integer not null,
    param_type  integer,
    path        varchar(512) not null,
    params_id   integer not null,
    guid        char(32),
    options     integer default 0,
    foreign key (params_id) references params (id),
    unique (guid)
);

create table appinfo (
    id                  integer not null primary key,
    app_id              integer not null,
    file_name           varchar(255),
    product_name        varchar(100),
    file_description    varchar(100),
    company_name        varchar(50),
    internal_name       varchar(50),
    original_file_name  varchar(50),
    product_version     varchar(20),
    file_version        varchar(20),
    legal_copyright     varchar(100),
    comments            varchar(100),
    product_url         varchar(100),
    lang                integer,    
    icon                varchar(6000),
    md5                 char(32),
    sha1                char(40),
    sha256              char(64),
    cert_thumbprint     varchar(64),
    app_options         integer default 0,
    guid                char(32),
    options             integer default 0,
    unique (guid)
);

create index idx_appinfo_app_id on appinfo (app_id);
create index idx_certificates_params_id on certificates (params_id);
create index idx_certificates_semunique on certificates (cert_type, thumbprint, issuedto, issuedby, expiration);
create index idx_contents_params_id on contents (params_id);
create index idx_contents_semunique on contents (cont_type, content);
create index idx_digests_params_id on digests (params_id);
create index idx_digests_semunique on digests (digest, digest_type);
create index idx_owners_params_id on owners (params_id);
create index idx_owners_semunique on owners (sid, res_type);
create index idx_params_param1 on params (param1);
create index idx_params_param2 on params (param2);
create index idx_params_param_type on params (param_type);
create index idx_params_params_id on params (group_id);
create index idx_pathes_params_id on pathes (params_id);
create index idx_pathes_semunique on pathes (res_type, path);

create table gswinfo (
	db_ver			integer,
	update_ver		integer
);

insert into gswinfo(db_ver, update_ver) values(1, 0);

create table idspatterns (
	id					integer not null primary key,
	res_type		    integer not null,
	pattern_type		integer not null,
	flags				integer default 0,
	pattern				varchar(512) not null,
	message				varchar(512),
    guid                char(32),
    options             integer default 0,
    unique (guid)
);


commit;
